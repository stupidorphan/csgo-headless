#include "hc/session.hpp"
#include "hc/netchannel.hpp"
#include "hc/hash.hpp"
#include "hc/usercmd.hpp"
#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>

using namespace hc;
namespace {
void check(bool value, const char* reason) { if (!value) throw std::runtime_error(reason); }
template<class F> void rejects(F&& operation, const char* reason) {
    bool rejected = false;
    try { operation(); } catch (const std::exception&) { rejected = true; }
    check(rejected, reason);
}
const Bytes whitelist{0x73, 0x61, 0x66, 0x65};
constexpr uint32_t schema_checksum = 0x1234abcd;
constexpr uint32_t map_checksum = 0x55667788;
Json fixture_profile() {
    return {{"host_version", 13881u}, {"send_table_crc", schema_checksum},
        {"bootstrap", {{"stock_signon_verified", true}, {"send_table_crc_verified", true}}},
        {"integrity", {{"requirements_verified", true}, {"whitelist_sha256", sha256(whitelist)},
            {"coverage", {{"server", "151.243.93.16:27015"}, {"map", "fixture_map"}, {"map_crc", map_checksum}}}}},
        {"entity_schema", {
            {"send_tables", Json::array({{{"name", "DT_CSPlayer"}, {"props", Json::array({
                {{"type", 0}, {"name", "m_iHealth"}, {"flags", 1}, {"bits", 10}},
                {{"type", 2}, {"name", "m_vecOrigin"}, {"flags", 4}, {"bits", 32}},
                {{"type", 0}, {"name", "m_iAccount"}, {"flags", 1u << 19}, {"bits", 32}},
                {{"type", 0}, {"name", "m_ArmorValue"}, {"flags", 1}, {"bits", 8}}
            })}}})},
            {"classes", Json::array({{{"id", 0}, {"name", "CCSPlayer"}, {"table", "DT_CSPlayer"}}})}
        }}};
}
struct TemporaryProfile {
    std::filesystem::path path;
    TemporaryProfile() {
        path = std::filesystem::temp_directory_path() /
            ("hc-session-fixture-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + ".json");
        std::ofstream file(path);
        if (!file) throw std::runtime_error("cannot create temporary session metadata fixture");
        file << fixture_profile().dump();
    }
    ~TemporaryProfile() { std::error_code error; std::filesystem::remove(path, error); }
};
void field_start(BitWriter& writer, unsigned count) {
    writer.bit(true);
    for (unsigned i = 0; i < count; ++i) writer.bit(true);
    writer.bit(false); writer.bit(false); writer.bits(127, 7); writer.bits(127, 7);
}
Bytes properties(unsigned health, float x) {
    BitWriter fields;
    field_start(fields, 4);
    fields.bits(health, 10); fields.float32(x); fields.float32(20); fields.float32(30);
    fields.varuint32(1600); fields.bits(75, 8);
    return fields.take();
}
Proto string_table(const char* name, const char* key, const Bytes& userdata) {
    BitWriter data;
    data.bit(false); data.bit(true); data.bit(true); data.bit(false); data.string(key);
    data.bit(true); data.bits(uint32_t(userdata.size()), 14); data.bytes(userdata);
    ProtoWriter table;
    table.string(1, name).u32(2, 64).u32(3, 1).bytes(8, data.data());
    return Proto(table.data());
}
Proto full_snapshot(unsigned health = 100, float x = 10) {
    BitWriter data;
    data.ubitvar(1); data.bit(false); data.bit(true); data.bits(0, 1); data.bits(9, 10);
    data.bit_bytes(properties(health, x), 151);
    ProtoWriter snapshot;
    snapshot.u32(1, 2048).u32(2, 1).u32(4, 1).u32(5, 0).bytes(7, data.data());
    return Proto(snapshot.data());
}
Proto health_delta(int32_t from, unsigned health) {
    BitWriter data;
    data.ubitvar(1); data.bit(false); data.bit(false);
    field_start(data, 1); data.bits(health, 10); data.ubitvar(0);
    ProtoWriter snapshot;
    snapshot.u32(1, 2048).u32(2, 1).u32(3, 1).i32(6, from).bytes(7, data.data());
    return Proto(snapshot.data());
}
void signon(Session& session, int stage, int spawn = 41) {
    ProtoWriter body;
    body.i32(1, stage).i32(2, spawn);
    session.replay_message(7, Proto(body.data()));
}
void server_tick(Session& session, int tick) {
    ProtoWriter body;
    body.i32(1, tick);
    session.replay_message(4, Proto(body.data()));
}
void signon_to_spawn(Session& session) {
    signon(session, 2, -1);
    ProtoWriter info;
    info.u32(2, 41).fixed32(8, map_checksum).u32(11, 16).u32(13, 0)
        .float32(14, 1.0f / 64).string(16, "fixture_map");
    session.replay_message(8, Proto(info.data()));
    signon(session, 3);
    session.replay_message(12, string_table("server_query_info", "PureServerWhitelist", whitelist));
    session.replay_message(12, string_table("instancebaseline", "0", properties(0, 0)));
    signon(session, 4);
    signon(session, 5);
    check(session.status()["connection"]["signon"] == 5, "fixture reached SPAWN");
}
void complete_signon(Session& session, int tick = 100) {
    signon_to_spawn(session);
    server_tick(session, tick);
    session.replay_message(26, full_snapshot());
    check(session.status()["connection"]["signon"] == 6,
          "first complete non-delta snapshot advances SPAWN to FULL despite updated_entries=1");
}
ChannelConfig passive_config() { ChannelConfig result; result.passive = true; return result; }
std::vector<Message> decode_step(Session& session, Netchannel& peer, int tick) {
    std::vector<Message> messages;
    for (const auto& datagram : session.replay_step(tick)) {
        auto packet = peer.receive(datagram);
        if (packet.pending) continue;
        check(packet.valid, "replay output is a valid encrypted netchannel packet");
        messages.insert(messages.end(), packet.messages.begin(), packet.messages.end());
    }
    return messages;
}
const Message& find_message(const std::vector<Message>& messages, unsigned type) {
    const auto found = std::find_if(messages.rbegin(), messages.rend(), [type](const auto& message) { return message.type == type; });
    if (found == messages.rend()) throw std::runtime_error("expected replay output message type " + std::to_string(type));
    return *found;
}
UserCmd last_usercmd(const std::vector<Message>& messages) {
    const Proto move(find_message(messages, 9).bytes);
    const auto bytes = move.get_bytes(3);
    BitReader input(bytes);
    UserCmd command;
    for (unsigned i = 0; i < move.get_u32(1) + move.get_u32(2); ++i) command = read_usercmd_delta(input, command);
    check(input.remaining() <= 7, "replayed command packet has only byte padding");
    return command;
}
void framing_tests() {
    check(sha256({}) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "empty SHA-256 fixture");
    auto request = parse_interactive("team CT");
    check(request["op"] == "team" && request["args"]["team"] == "CT", "team command parser");
    request = parse_interactive("say hello world");
    check(request["args"]["text"] == "hello world", "chat command parser");
    request = parse_interactive("move 1 -0.5 64");
    check(request["args"]["duration_ticks"] == 64, "duration command parser");
    const auto info = make_userinfo("test");
    check(info.get_messages(1).at(0).get_messages(1).at(0).get_string(1) == "name", "nested userinfo framing");
    const Bytes ticket{1, 2, 3, 4};
    const auto packet = build_connect_packet(13881, 0xabcdef, 0x1122334455667788, ticket, info);
    BitReader reader(packet);
    check(reader.bits(32) == 0xffffffff && reader.bits(8) == 'k' && reader.bits(32) == 13881 &&
          reader.bits(32) == 3 && reader.bits(32) == 0xabcdef, "connection header");
    check(reader.string().empty() && reader.string().empty() && reader.bits(8) == 1, "connection names and split-screen count");
    check(reader.varuint32() == 16, "connection userinfo message type");
    const auto size = reader.varuint32();
    check(Proto(reader.bytes(size)).get_messages(1).size() == 1, "connection userinfo payload");
    check(!reader.bit() && reader.bits(32) == 0 && reader.bits(32) == 0 && reader.bits(8) == 1 && reader.bits(32) == 0,
          "connection optional requirements");
    check(reader.bits(16) == 12 && reader.bits(32) == 0x55667788 && reader.bits(32) == 0x11223344 &&
          reader.bytes(4) == ticket, "connection test-ticket framing");
}
void lifecycle_tests(const std::filesystem::path& path) {
    ClientConfig config;
    config.profile = path;
    config.replay_only = true;
    config.auth_helper = path.parent_path() / "must-never-be-launched.exe";
    std::vector<Json> events;
    Session session(config, [&](const Json& event) { events.push_back(event); });
    rejects([&] { session.command("connect"); }, "offline replay must reject live connect before acquiring a ticket or socket");
    rejects([&] { session.command("input", {{"forward", 1}}); }, "gameplay rejected before FULL");
    signon_to_spawn(session);
    server_tick(session, 99);
    session.replay_message(26, health_delta(1, 0));
    check(session.status()["connection"]["signon"] == 5 && session.status()["entity_tick"] == -1,
          "missing first snapshot history must not incorrectly finish signon");
    server_tick(session, 100);
    session.replay_message(26, full_snapshot());
    auto status = session.status();
    check(status["connection"]["signon"] == 6 && status["local"]["health"] == 100 &&
          status["local"]["position"] == Json::array({10.0, 20.0, 30.0}), "FULL exposes authoritative player state");
    check(std::any_of(events.begin(), events.end(), [](const Json& event) { return event.value("type", "") == "signon" && event.value("state", 0) == 6; }),
          "FULL transition is emitted to the frontend");
    Netchannel peer(passive_config());
    auto outgoing = decode_step(session, peer, 100);
    const Proto client_info(find_message(outgoing, 8).bytes);
    check(client_info.get_u32(1) == schema_checksum && client_info.get_u32(2) == 41,
          "signon sends verified fixed32 schema checksum and spawn count");
    check(Proto(find_message(outgoing, 7).bytes).get_i32(1) == 6 &&
          Proto(find_message(outgoing, 5).bytes).get_string(1) == "joingame", "FULL confirmation and normal player admission command queued");
    check(Proto(find_message(outgoing, 4).bytes).get_i32(1) == 100, "first full snapshot is acknowledged");
    check(last_usercmd(outgoing).command_number == 1, "first independent user command starts at one");
    session.command("input", {{"forward", 1}, {"yaw", 33}, {"buttons", Json::array({"jump"})}, {"duration_ticks", 10}});
    check(last_usercmd(decode_step(session, peer, 101)).forwardmove == 450, "FULL gameplay reaches command encoder");
    server_tick(session, 102);
    session.replay_message(26, health_delta(100, 87));
    check(session.status()["local"]["health"] == 87, "server delta updates health");
    server_tick(session, 103);
    session.replay_message(26, health_delta(7, 0));
    outgoing = decode_step(session, peer, 103);
    check(session.status()["local"]["health"] == 87 && Proto(find_message(outgoing, 4).bytes).get_i32(1) == -1,
          "missing history preserves player state and requests full update on the wire");
    server_tick(session, 110);
    session.replay_message(26, full_snapshot(75, 55));
    outgoing = decode_step(session, peer, 110);
    check(Proto(find_message(outgoing, 4).bytes).get_i32(1) == 110 && session.status()["local"]["health"] == 75,
          "full recovery resumes authoritative snapshot acknowledgement");
    signon(session, 5);
    check(session.status()["connection"]["signon"] == 6, "late duplicate signon does not regress FULL");
    session.command("input", {{"forward", 1}, {"yaw", 66}, {"buttons", Json::array({"attack"})}, {"duration_ticks", 500}});
    signon(session, 7);
    status = session.status();
    check(status["connection"]["signon"] == 7 && status["local"].is_null() && status["entity_count"] == 0 &&
          status["entity_tick"] == -1 && status["string_table_count"] == 0, "changelevel clears map snapshots and tables");
    check(std::any_of(events.begin(), events.end(), [](const Json& event) { return event.value("type", "") == "map_transition"; }), "changelevel emits an event");
    rejects([&] { session.command("weapon", {{"entity", 2}}); }, "gameplay suspended during map transition");
    complete_signon(session, 5);
    peer.reset();
    outgoing = decode_step(session, peer, 5);
    auto command = last_usercmd(outgoing);
    const Proto after_map_move(find_message(outgoing, 9).bytes);
    check(command.command_number == 1 && command.forwardmove == 0 && command.buttons == 0 && command.viewangles[1] == 0 &&
          after_map_move.get_u32(1) == 0, "map transition clears held input, view angles, command sequence and backup history");
    session.command("input", {{"forward", 1}, {"yaw", 99}, {"duration_ticks", 500}});
    session.disconnect("offline test disconnect");
    status = session.status();
    check(status["connection"]["signon"] == 0 && status["connection"]["tick"] == 0 && status["local"].is_null() && status["entity_count"] == 0,
          "explicit disconnect clears session state");
    check(session.replay_step(6).empty(), "disconnected replay emits no datagrams");
    complete_signon(session, 20);
    peer.reset();
    command = last_usercmd(decode_step(session, peer, 20));
    check(command.command_number == 1 && command.forwardmove == 0 && command.viewangles[1] == 0, "disconnect cannot leak input into a later session");
    ProtoWriter rejection;
    rejection.string(1, "synthetic server rejection");
    session.replay_message(1, Proto(rejection.data()));
    status = session.status();
    check(status["connection"]["signon"] == 0 && status["local"].is_null() &&
          status["connection"]["last_error"].get<std::string>().find("synthetic server rejection") != std::string::npos,
          "server disconnect uses production error path and clears authoritative state");
}
void compatibility_rejection_tests(const std::filesystem::path& path) {
    ClientConfig config;
    config.profile = path;
    config.replay_only = true;
    Session changed_map(config);
    signon(changed_map, 2, -1);
    ProtoWriter wrong_map;
    wrong_map.u32(2, 41).fixed32(8, map_checksum + 1).float32(14, 1.0f / 64).string(16, "unverified_map");
    changed_map.replay_message(8, Proto(wrong_map.data()));
    check(changed_map.status()["connection"]["signon"] == 0 &&
          changed_map.status()["connection"]["last_error"].get<std::string>().find("Incompatible metadata") != std::string::npos,
          "unverified map profile fails explicitly during transition");
    Session wrong_whitelist(config);
    signon(wrong_whitelist, 2, -1);
    signon(wrong_whitelist, 3);
    wrong_whitelist.replay_message(12, string_table("server_query_info", "PureServerWhitelist", Bytes{1, 2, 3}));
    signon(wrong_whitelist, 4);
    check(wrong_whitelist.status()["connection"]["signon"] == 0 &&
          wrong_whitelist.status()["connection"]["last_error"].get<std::string>().find("whitelist differs") != std::string::npos,
          "changed integrity requirements fail before SPAWN");
    Session wrong_spawn(config);
    signon(wrong_spawn, 2, -1);
    signon(wrong_spawn, 3, 41);
    signon(wrong_spawn, 4, 42);
    check(wrong_spawn.status()["connection"]["signon"] == 0 &&
          wrong_spawn.status()["connection"]["last_error"].get<std::string>().find("spawn count mismatch") != std::string::npos,
          "inconsistent signon spawn count is rejected");
    Session invalid_stage(config);
    signon(invalid_stage, 9);
    check(invalid_stage.status()["connection"]["signon"] == 0 &&
          invalid_stage.status()["connection"]["last_error"].get<std::string>().find("Invalid signon state") != std::string::npos,
          "invalid signon stage is rejected");
}
} // namespace
int main() {
    try {
        framing_tests();
        TemporaryProfile metadata;
        lifecycle_tests(metadata.path);
        compatibility_rejection_tests(metadata.path);
        std::cout << "session framing, signon, snapshot recovery, disconnect and map-transition tests passed (offline)\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
