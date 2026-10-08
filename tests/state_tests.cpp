#include "hc/state.hpp"
#include "hc/usercmd.hpp"
#include "hc/netchannel.hpp"
#include <cmath>
#include <fstream>
#include <iostream>
#include <limits>
#include <stdexcept>

using namespace hc;
using Json = nlohmann::json;
namespace {
void check(bool value, const char* reason) { if (!value) throw std::runtime_error(reason); }
template<class F> void rejects(F&& fn, const char* reason) {
    bool rejected = false;
    try { fn(); } catch (const std::exception&) { rejected = true; }
    check(rejected, reason);
}
Json property(int type, const char* name, std::uint32_t flags, unsigned bits) {
    return {{"type", type}, {"name", name}, {"flags", flags}, {"bits", bits}};
}
Json profile() {
    return {{"entity_schema", {
        {"send_tables", Json::array({{{"name", "DT_CSPlayer"}, {"props", Json::array({
            property(0, "m_iHealth", 1, 10), property(2, "m_vecOrigin", 4, 32),
            property(0, "m_iAccount", 1u << 19, 32), property(0, "m_ArmorValue", 1, 8)
        })}}})},
        {"classes", Json::array({{{"id", 0}, {"name", "CCSPlayer"}, {"table", "DT_CSPlayer"}}})}
    }}};
}
void field_start(BitWriter& out, unsigned count) {
    out.bit(true);
    for (unsigned i = 0; i < count; ++i) out.bit(true);
    out.bit(false); out.bit(false); out.bits(127, 7); out.bits(127, 7);
}
Bytes values(unsigned health, float x, float y, float z, int money, unsigned armor) {
    BitWriter out;
    field_start(out, 4);
    out.bits(health, 10); out.float32(x); out.float32(y); out.float32(z);
    out.varuint32((static_cast<std::uint32_t>(money) << 1) ^ (0u - static_cast<std::uint32_t>(money < 0)));
    out.bits(armor, 8);
    return out.take();
}
Proto strings(const char* name, const char* key, const Bytes& user_data) {
    BitWriter data;
    data.bit(false); data.bit(true); data.bit(true); data.bit(false);
    data.string(key); data.bit(true); data.bits(static_cast<std::uint32_t>(user_data.size()), 14); data.bytes(user_data);
    ProtoWriter out;
    out.string(1, name).u32(2, 64).u32(3, 1).bytes(8, data.data());
    return Proto(out.data());
}
Proto full_packet(unsigned health, bool update = false) {
    BitWriter data;
    data.ubitvar(1); data.bit(false); data.bit(true); data.bits(0, 1); data.bits(9, 10);
    const auto fields = values(health, 123.5f, -44.25f, 6, 800, 75);
    // All four field-path bits plus the terminator consume 21 bits.
    data.bit_bytes(fields, 21 + 10 + 96 + 16 + 8);
    ProtoWriter out;
    out.u32(1, 2048).u32(2, 1).u32(4, update).u32(5, 0).bytes(7, data.data());
    return Proto(out.data());
}
Proto health_delta(int from, unsigned health) {
    BitWriter data;
    data.ubitvar(1); data.bit(false); data.bit(false);
    field_start(data, 1); data.bits(health, 10); data.ubitvar(0);
    ProtoWriter out;
    out.u32(1, 2048).u32(2, 1).u32(3, 1).i32(6, from).bytes(7, data.data());
    return Proto(out.data());
}
void state_tests() {
    State bootstrap;
    BitWriter bootstrap_baseline;
    field_start(bootstrap_baseline, 0);
    check(bootstrap.consume(12, strings("instancebaseline", "0", bootstrap_baseline.data()), 0),
          "bootstrap string table decoding does not require entity schema");
    check(bootstrap.string_table_userdata("instancebaseline", "0") == std::optional<Bytes>(bootstrap_baseline.data()),
          "bootstrap keeps bounded baseline userdata before class metadata is available");
    State state;
    state.load_profile(profile());
    state.set_server_info("de_dust2", 0, 16, 1.0f / 64);
    const auto baseline = values(0, 0, 0, 0, 0, 0);
    check(state.consume(12, strings("instancebaseline", "0", baseline), 50), "baseline strings");
    check(state.string_table_userdata("instancebaseline", "0") == std::optional<Bytes>(baseline), "userdata accessor preserves exact bytes");
    check(!state.string_table_userdata("instancebaseline", "missing") && !state.string_table_userdata("missing", "0"),
          "userdata accessor distinguishes absent table and absent entry");
    check(state.consume(26, full_packet(100, true), 100), "full snapshot");
    auto status = state.status();
    check(status["local"]["health"] == 100 && status["local"]["money"] == 800, "decoded integer properties");
    check(status["local"]["position"] == Json::array({123.5, -44.25, 6.0}), "decoded vector");
    auto outgoing = state.take_outgoing();
    check(outgoing.size() == 1 && outgoing[0].first == 11 && outgoing[0].second.get_i32(1) == 100,
          "baseline acknowledgment");
    check(state.consume(26, health_delta(100, 87), 101), "health delta");
    check(state.status()["local"]["health"] == 87, "server delta is visible");
    BitWriter unchanged;
    unchanged.ubitvar(0);
    ProtoWriter unchanged_message;
    unchanged_message.u32(1, 2048).u32(2, 0).u32(3, 1).i32(6, 100).bytes(7, unchanged.data());
    check(state.consume(26, Proto(unchanged_message.data()), 101), "delta against earlier acknowledged frame");
    check(state.status()["local"]["health"] == 100, "preserved entity reverts to referenced frame state");
    check(state.consume(26, health_delta(100, 87), 101), "restore health delta");
    check(!state.consume(26, health_delta(1, 0), 102), "missing history requests full update");
    check(state.needs_full_update() && state.entity_tick() == 101, "missing history preserves previous snapshot");
    state.clear_full_update_request();
    check(!state.needs_full_update(), "full update request clears");
    auto malformed = full_packet(100).get_bytes(7);
    malformed.resize(3);
    ProtoWriter bad;
    bad.u32(1, 2048).u32(2, 1).bytes(7, malformed);
    rejects([&] { state.consume(26, Proto(bad.data()), 103); }, "truncated snapshot must fail");
    check(state.entity_tick() == 101 && state.status()["local"]["health"] == 87, "malformed snapshot commits no state");

    BitWriter leave;
    leave.ubitvar(1); leave.bit(true); leave.bit(false); leave.ubitvar(0);
    ProtoWriter leave_message;
    leave_message.u32(1, 2048).u32(2, 1).u32(3, 1).i32(6, 101).bytes(7, leave.data());
    check(state.consume(26, Proto(leave_message.data()), 104), "leave PVS");
    check(state.status()["local"]["in_pvs"] == false, "leave retains dormant state");
    BitWriter deletion;
    deletion.ubitvar(1); deletion.ubitvar(2);
    ProtoWriter deletion_message;
    deletion_message.u32(1, 2048).u32(2, 0).u32(3, 1).i32(6, 104).bytes(7, deletion.data());
    check(state.consume(26, Proto(deletion_message.data()), 105), "explicit delete");
    check(state.status()["local"].is_null(), "deleted local entity disappears");
    state.set_server_info("de_inferno", 0, 16, 1.0f / 64);
    check(state.entity_tick() == -1 && state.class_count() == 1 && state.status()["string_table_count"] == 0,
          "map change clears session and preserves schema");
    state.reset();
    check(state.class_count() == 1, "reset preserves schema");

    Bytes user_data(344);
    std::fill(user_data.begin(), user_data.begin() + 6, std::uint8_t{255});
    user_data[6] = 240; user_data[7] = 2;
    user_data[15] = 42; user_data[16] = 'A'; user_data[147] = 7; user_data[316] = 1;
    state.set_server_info("de_dust2", 0, 16, 1.0f / 64);
    check(state.consume(12, strings("userinfo", "1", user_data), 1), "versioned player info");
    check(state.consume(12, strings("instancebaseline", "0", baseline), 2), "reload baseline");
    check(state.consume(26, full_packet(100), 3), "userinfo snapshot");
    check(state.status()["local"]["name"] == "A" && state.status()["local"]["steam_id"] == "42" &&
          state.status()["local"]["user_id"] == 7 && state.status()["local"]["bot"] == true,
          "player info uses network endianness and exact field offsets");

    // History substring references are packet-local and bounded to 32 strings.
    BitWriter data;
    data.bit(false);
    data.bit(true); data.bit(true); data.bit(false); data.string("hello_one"); data.bit(false);
    data.bit(true); data.bit(true); data.bit(true); data.bits(0, 5); data.bits(6, 5); data.string("two"); data.bit(false);
    ProtoWriter table;
    table.string(1, "modelprecache").u32(2, 64).u32(3, 2).bytes(8, data.data());
    check(state.consume(12, Proto(table.data()), 0), "substring table entries");
    check(state.string_table_userdata("modelprecache", "hello_two") == std::optional<Bytes>(Bytes{}),
          "userdata accessor distinguishes present empty data");
    ProtoWriter descriptor_key, descriptor, event_list;
    descriptor_key.u32(1, 3).string(2, "winner");
    descriptor.u32(1, 7).string(2, "round_end").message(3, descriptor_key);
    event_list.message(1, descriptor);
    check(state.consume(30, Proto(event_list.data()), 106), "game event list");
    check(state.take_outgoing().at(0).first == 12, "event subscription emitted");
    ProtoWriter key, event;
    key.u32(1, 3).i32(4, 3);
    event.u32(2, 7).message(3, key);
    check(state.consume(25, Proto(event.data()), 107), "game event decode");
    check(state.status()["round"]["result"]["winner"] == 3, "round state reflects descriptor values");
    check(state.take_events().back()["tick"] == 107, "events carry server tick");
    auto invalid_profile = profile();
    invalid_profile["entity_schema"]["send_tables"][0]["props"].push_back(property(5, "bad_array", 0, 0));
    rejects([&] { state.load_profile(invalid_profile); }, "array without element metadata must fail");
    check(state.class_count() == 1, "invalid profile does not replace loaded schema");
    State anchored;
    anchored.load_profile(profile());
    anchored.set_server_info("de_dust2", 0, 16, 1.0f / 64);
    anchored.consume(12, strings("instancebaseline", "0", baseline), 0);
    anchored.consume(26, full_packet(100), 100);
    for (int tick = 101; tick < 181; ++tick)
        check(anchored.consume(26, health_delta(100, 90), tick), "repeated acknowledged base survives frame-cache eviction");
    check(!anchored.needs_full_update() && anchored.entity_tick() == 180, "valid old base triggers no artificial recovery");
}
void metadata_tests() {
    auto health = property(0, "m_iHealth", 1, 10);
    health["priority"] = 100;
    auto armor = property(0, "m_ArmorValue", 1, 8);
    auto ignore = property(0, "ignored", 64, 0);
    ignore["table"] = "DT_Base";
    auto local_table = property(6, "cslocaldata", 0, 0);
    local_table["table"] = "DT_Local";
    auto base = property(6, "baseclass", 1u << 11, 0);
    base["table"] = "DT_Base";
    Json metadata{{"send_tables", Json::array({
        {{"name", "DT_Player"}, {"props", Json::array({health, local_table, base, ignore})}},
        {{"name", "DT_Local"}, {"props", Json::array({{{"type", 2}, {"name", "m_vecOrigin"}, {"flags", 4}, {"bits", -1}}})}},
        {{"name", "DT_Base"}, {"props", Json::array({armor, property(0, "ignored", 1, 7)})}}
    })}, {"classes", Json::array({{{"id", 0}, {"name", "CCSPlayer"}, {"table", "DT_Player"}}})}};
    State state;
    state.load_profile(metadata);
    state.set_server_info("de_dust2", 0, 16, 1.0f / 64);
    BitWriter empty_fields;
    field_start(empty_fields, 0);
    state.consume(12, strings("instancebaseline", "0", empty_fields.data()), 1);
    BitWriter empty_packet;
    empty_packet.ubitvar(1); empty_packet.bit(false); empty_packet.bit(true); empty_packet.bits(0, 1); empty_packet.bits(1, 10);
    empty_packet.bit_bytes(empty_fields.data(), empty_fields.position());
    ProtoWriter zero;
    zero.u32(1, 2048).u32(2, 1).bytes(7, empty_packet.data());
    check(state.consume(26, Proto(zero.data()), 2), "zero-only baseline snapshot");
    auto status = state.status();
    check(status["local"]["health"] == 0 && status["local"]["armor"] == 0 &&
          status["local"]["position"] == Json::array({0.0, 0.0, 0.0}), "omitted baseline props have Source zero defaults");
    check(status["local"]["fields"].size() == 3, "excluded props are removed from flattened schema");
    BitWriter data;
    data.ubitvar(1); data.bit(false); data.bit(true); data.bits(0, 1); data.bits(1, 10);
    field_start(data, 3);
    data.float32(1); data.float32(2); data.float32(3); data.bits(99, 8); data.bits(78, 10);
    ProtoWriter update;
    update.u32(1, 2048).u32(2, 1).bytes(7, data.data());
    check(state.consume(26, Proto(update.data()), 3), "nested prioritized snapshot");
    status = state.status();
    check(status["local"]["health"] == 78 && status["local"]["armor"] == 99 &&
          status["local"]["position"] == Json::array({1.0, 2.0, 3.0}), "child hierarchy and priority swaps match Source field order");
    auto cyclic = metadata;
    cyclic["send_tables"][2]["props"].push_back(base);
    rejects([&] { state.load_profile(cyclic); }, "cyclic send tables rejected");
}
void user_message_tests() {
    State state;
    auto message = [&](unsigned type, const ProtoWriter& body) {
        ProtoWriter envelope;
        envelope.u32(1, type).bytes(2, body.data());
        check(state.consume(23, Proto(envelope.data()), 123), "user message handled");
        auto events = state.take_events();
        check(events.size() == 1 && events[0]["tick"] == 123, "user message carries server tick");
        // Server plugins sometimes send non-UTF8 decorative bytes. An event
        // must remain valid JSON even when preserving its raw string fields.
        check(Json::parse(events[0].dump()) == events[0], "user message is UTF8-safe JSON");
        return events[0];
    };
    std::string colored = "\x01" "cotton \x03" "Warning! You need cl_lagcompensation 1. \x01";
    colored += static_cast<char>(0xb7);
    ProtoWriter text;
    text.u32(1, 4).string(2, "obsolete field must not be treated as params").string(3, colored).string(3, "").string(3, "");
    auto event = message(7, text);
    const auto readable = event["text"].get<std::string>();
    check(readable.find("Warning! You need cl_lagcompensation 1.") != std::string::npos,
          "TextMsg decodes actual repeated field3 into readable plugin feedback");
    check(readable.find('\x01') == std::string::npos && readable.find('\x03') == std::string::npos,
          "display text removes Source chat colors");
    check(event["params"].size() == 3 && event["destination"] == 4, "TextMsg preserves exact parameter count and destination");
    ProtoWriter connected;
    connected.string(3, "#Game_connected").string(3, "Alice").string(3, "");
    event = message(7, connected);
    check(event["text"] == "#Game_connected: Alice", "untranslated localization token retains readable values");
    ProtoWriter say;
    say.i32(1, 3).string(2, "\x03" "Alice: hello" "\x01").u32(3, 1).u32(4, 1);
    event = message(5, say);
    check(event["text"] == "Alice: hello" && event["entity_index"] == 3 && event["chat"] == true &&
          event["all_chat"] == true, "SayText field2 and chat flags decoded");
    ProtoWriter say2;
    say2.i32(1, 4).u32(2, 1).string(3, "%s1: %s2").string(4, "Alice").string(4, "\x03" "Hello" "\x01").u32(5, 0);
    event = message(6, say2);
    check(event["text"] == "Alice: Hello" && event["message_name"] == "%s1: %s2" && event["params"].size() == 2 &&
          event["chat"] == true && event["all_chat"] == false, "SayText2 actual params field4 substitutes numbered strings");
    ProtoWriter numeric;
    numeric.string(3, "Cost %d1; %s2; %%").string(3, "500").string(3, "ready");
    event = message(7, numeric);
    check(event["text"] == "Cost 500; ready; %", "TextMsg supports numbered values and literal percent");
    ProtoWriter pos, color, hud;
    pos.float32(1, 0.25f).float32(2, 0.5f);
    color.u32(1, 255).u32(2, 0).u32(3, 128).u32(4, 255);
    hud.i32(1, 2).message(2, pos).message(3, color).i32(5, 1).float32(9, 2.5f).string(11, "\x04" "HUD line\nSecond line");
    event = message(8, hud);
    check(event["text"] == "HUD line\nSecond line" && event["channel"] == 2 && event["hold_time"] == 2.5 &&
          event["position"] == Json::array({0.25, 0.5}) && event["color1"] == Json::array({255, 0, 128, 255}),
          "HudMsg decodes text11 and presentation fields while preserving line breaks");
    ProtoWriter hint;
    hint.string(1, "AWP: restricted\nHS-only: off");
    event = message(23, hint);
    check(event["text"] == "AWP: restricted\nHS-only: off", "HintText emits readable string instead of text array");
}
void usercmd_tests() {
    UserCmd zero, neutral;
    neutral.command_number = neutral.tick_count = 1;
    BitWriter out;
    write_usercmd_delta(out, neutral, zero);
    check(out.position() == 20 && out.data() == Bytes({0, 0, 0}), "13881 neutral command fixture is twenty zero flags");
    BitReader input(out.data(), out.position());
    check(read_usercmd_delta(input, zero) == neutral && input.empty(), "neutral decode");
    UserCmd moving = neutral;
    moving.command_number = 2; moving.tick_count = 100;
    moving.viewangles = {30, -75, 0}; moving.aimdirection = {1, 2, 3};
    moving.forwardmove = 450; moving.sidemove = -100; moving.upmove = 9;
    moving.buttons = 0x1234; moving.impulse = 4; moving.weaponselect = 1000;
    moving.weaponsubtype = 33; moving.mousedx = -8; moving.mousedy = 900;
    moving.headangles = {-12, 35, 7}; moving.headoffset = 0x87654321u;
    BitWriter encoded;
    write_usercmd_delta(encoded, moving, neutral);
    BitReader decoded(encoded.data(), encoded.position());
    check(read_usercmd_delta(decoded, neutral) == moving && decoded.empty(), "full usercmd round trip");
    std::array<UserCmd, 1> backup{neutral}, fresh{moving};
    const auto move = make_move(backup, fresh);
    check(move.get_u32(1) == 1 && move.get_u32(2) == 1, "backup/new command counts");
    const auto bytes = move.get_bytes(3);
    BitReader chained(bytes);
    const auto first = read_usercmd_delta(chained, zero);
    check(first == neutral && read_usercmd_delta(chained, first) == moving, "move starts at zero and chains backup then new");
    auto invalid = moving;
    invalid.command_number = 12;
    std::array<UserCmd, 1> gap{invalid};
    rejects([&] { make_move(backup, gap); }, "noncontiguous commands rejected");
    rejects([&] { make_move({}, {}); }, "empty new command list rejected");
    InputController controller;
    controller.set({{"forward", 1}, {"side", -0.5}, {"pitch", 30}, {"yaw", 450},
                    {"buttons", Json::array({"fire", "jump"})}, {"duration_ticks", 2}});
    const auto a = controller.next(100), b = controller.next(101), c = controller.next(102);
    check(a.forwardmove == 450 && b.forwardmove == 450 && c.forwardmove == 0 && c.buttons == 0, "inputs expire in ticks");
    check(c.viewangles[0] == 30 && c.viewangles[1] == 90, "expired input preserves normalized view");
    check((a.buttons & 3u) == 3u && (a.buttons & (1u << 9)), "named action and movement buttons encoded");
    controller.set({{"buttons", Json::array({"walk"})}});
    check((controller.next(103).buttons & (1u << 17)) != 0, "CS:GO walk maps to IN_SPEED");
    controller.select_weapon(888, 6);
    check(controller.next(104).weaponselect == 888 && controller.next(105).weaponselect == 0, "weapon selection is one-shot");
    rejects([&] { controller.set({{"forward", 2}}); }, "out of range input rejected");
    rejects([&] { controller.set({{"buttons", Json::array({"invalid"})}}); }, "unknown button rejected");
    controller.reset();
    check(controller.next(105).command_number == 1, "reset starts clean command sequence");
    controller.set({{"forward", 1}, {"yaw", 45}, {"duration_ticks", 2}});
    check(controller.next(200).forwardmove == 450 && controller.next(200).forwardmove == 450,
          "repeated server ticks do not consume input duration");
    check(controller.next(220).forwardmove == 0 && controller.next(220).viewangles[1] == 45,
          "skipped server ticks expire input while preserving view");
    controller.set({{"forward", 1}, {"duration_ticks", 2}});
    check(controller.next(std::numeric_limits<std::int32_t>::max() - 1).forwardmove == 450,
          "input starts near tick wrap");
    check(controller.next(std::numeric_limits<std::int32_t>::min()).forwardmove == 0,
          "input expiration handles server tick wrap");
    controller.set({{"forward", 1}, {"duration_ticks", 10}});
    check(controller.next(500).forwardmove == 450 && controller.next(20).forwardmove == 0,
          "backward server tick reset neutralizes pending input");
}
Bytes unhex(const std::string& value) {
    check(value.size() % 2 == 0, "capture contains odd-length hex");
    auto nibble = [](char character) -> unsigned {
        if (character >= '0' && character <= '9') return character - '0';
        if (character >= 'a' && character <= 'f') return character - 'a' + 10;
        if (character >= 'A' && character <= 'F') return character - 'A' + 10;
        throw std::runtime_error("capture contains invalid hex");
    };
    Bytes result;
    result.reserve(value.size() / 2);
    for (std::size_t i = 0; i < value.size(); i += 2)
        result.push_back(static_cast<std::uint8_t>((nibble(value[i]) << 4) | nibble(value[i + 1])));
    return result;
}
int replay(const char* profile_path, const char* capture_path) {
    std::ifstream profile_file(profile_path), capture_file(capture_path);
    check(bool(profile_file) && bool(capture_file), "cannot open replay profile or capture");
    Json metadata;
    profile_file >> metadata;
    State state;
    state.load_profile(metadata);
    ChannelConfig config;
    config.passive = true;
    config.host_version = metadata.value("host_version", 13881u);
    config.encryption_key = default_ice_key(config.host_version);
    Netchannel channel(config), client_channel(config);
    int tick = 0;
    std::size_t line_number = 0, packets = 0, messages = 0, snapshots = 0, recoveries = 0, stale = 0, errors = 0;
    std::size_t captured_moves = 0, captured_commands = 0, move_errors = 0;
    Json reasons = Json::array();
    std::string line;
    auto failure = [&](const std::string& reason, int type = -1) {
        ++errors;
        if (reasons.size() < 16) reasons.push_back({{"line", line_number}, {"message_type", type}, {"reason", reason}});
    };
    while (std::getline(capture_file, line)) {
        ++line_number;
        if (line.empty()) continue;
        try {
            const auto record = Json::parse(line);
            const auto direction = record.at("direction").get<std::string>();
            if (direction != "server_to_client" && direction != "client_to_server") continue;
            const bool outbound = direction == "client_to_server";
            const auto bytes = unhex(record.at("hex").get<std::string>());
            auto packet = (outbound ? client_channel : channel).receive(bytes);
            if (packet.pending || packet.connectionless) continue;
            if (!packet.valid) {
                if (packet.error == "stale_packet") ++stale;
                else failure(packet.error);
                continue;
            }
            ++packets;
            for (const auto& message : packet.messages) {
                if (outbound) {
                    if (message.type != 9) continue;
                    try {
                        const Proto body(message.bytes);
                        const auto backups = body.get_u32(1), fresh = body.get_u32(2);
                        check(backups <= 7 && fresh <= 15 && backups + fresh > 0, "invalid captured move counts");
                        const auto data = body.get_bytes(3);
                        BitReader commands(data);
                        BitWriter reproduced;
                        UserCmd previous;
                        for (unsigned i = 0; i < backups + fresh; ++i) {
                            const auto command = read_usercmd_delta(commands, previous);
                            write_usercmd_delta(reproduced, command, previous);
                            previous = command;
                        }
                        check(commands.position() == reproduced.position(), "captured move round trip changed bit length");
                        for (std::size_t i = 0; i < reproduced.position(); ++i)
                            check(((data[i / 8] >> (i % 8)) & 1) == ((reproduced.data()[i / 8] >> (i % 8)) & 1),
                                  "captured move round trip changed wire bits");
                        const auto detail = "captured move has " + std::to_string(commands.remaining()) +
                            " undecoded bits after " + std::to_string(backups + fresh) + " commands (" +
                            std::to_string(data.size() * 8) + " total bits)";
                        check(commands.remaining() <= 7, detail.c_str());
                        ++captured_moves;
                        captured_commands += backups + fresh;
                    } catch (const std::exception& error) {
                        ++move_errors;
                        failure(error.what(), static_cast<int>(message.type));
                    }
                    continue;
                }
                ++messages;
                try {
                    const Proto body(message.bytes);
                    if (message.type == 4) tick = body.get_i32(1);
                    const auto handled = state.consume(message.type, body, tick);
                    if (message.type == 26) { if (handled) ++snapshots; else ++recoveries; }
                    state.take_outgoing();
                    state.take_events();
                } catch (const std::exception& error) { failure(error.what(), static_cast<int>(message.type)); }
            }
        } catch (const std::exception& error) { failure(error.what()); }
    }
    const auto status = state.status();
    const auto pure = state.string_table_userdata("server_query_info", "PureServerWhitelist");
    Json result{{"type", "state_replay_summary"}, {"packets", packets}, {"messages", messages},
        {"snapshots", snapshots}, {"recoveries", recoveries}, {"errors", errors}, {"first_errors", reasons},
        {"stale_packets", stale},
        {"captured_moves", captured_moves}, {"captured_user_commands", captured_commands}, {"move_errors", move_errors},
        {"map", status.at("map")}, {"tick", status.at("tick")}, {"entity_tick", state.entity_tick()},
        {"entity_count", status.at("entity_count")}, {"players", status.at("players").size()},
        {"has_local_player", !status.at("local").is_null()}, {"has_pure_whitelist", pure.has_value()},
        {"pure_whitelist_bytes", pure ? pure->size() : 0}};
    std::cout << result.dump(2) << '\n';
    return errors || !snapshots ? 1 : 0;
}
}
int main(int argc, char** argv) {
    try {
        if (argc == 3) return replay(argv[1], argv[2]);
        check(argc == 1, "usage: state-tests [PROFILE_JSON CAPTURE_JSONL]");
        state_tests(); metadata_tests(); usercmd_tests(); user_message_tests(); std::cout << "state/usercmd tests passed\n"; return 0;
    }
    catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
