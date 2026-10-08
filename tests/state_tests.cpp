#include "hc/state.hpp"
#include "hc/usercmd.hpp"
#include <cmath>
#include <iostream>
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
    State state;
    state.load_profile(profile());
    state.set_server_info("de_dust2", 0, 16, 1.0f / 64);
    const auto baseline = values(0, 0, 0, 0, 0, 0);
    check(state.consume(12, strings("instancebaseline", "0", baseline), 50), "baseline strings");
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
    std::fill(user_data.begin(), user_data.begin() + 6, 255);
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
}
void usercmd_tests() {
    UserCmd zero, neutral;
    neutral.command_number = neutral.tick_count = 1;
    BitWriter out;
    write_usercmd_delta(out, neutral, zero);
    check(out.position() == 16 && out.data() == Bytes({0, 0}), "neutral command fixture is sixteen zero flags");
    BitReader input(out.data(), out.position());
    check(read_usercmd_delta(input, zero) == neutral && input.empty(), "neutral decode");
    UserCmd moving = neutral;
    moving.command_number = 2; moving.tick_count = 100;
    moving.viewangles = {30, -75, 0}; moving.aimdirection = {1, 2, 3};
    moving.forwardmove = 450; moving.sidemove = -100; moving.upmove = 9;
    moving.buttons = 0x1234; moving.impulse = 4; moving.weaponselect = 1000;
    moving.weaponsubtype = 33; moving.mousedx = -8; moving.mousedy = 900;
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
    controller.select_weapon(888, 6);
    check(controller.next(103).weaponselect == 888 && controller.next(104).weaponselect == 0, "weapon selection is one-shot");
    rejects([&] { controller.set({{"forward", 2}}); }, "out of range input rejected");
    rejects([&] { controller.set({{"buttons", Json::array({"invalid"})}}); }, "unknown button rejected");
    controller.reset();
    check(controller.next(105).command_number == 1, "reset starts clean command sequence");
}
}
int main() {
    try { state_tests(); usercmd_tests(); std::cout << "state/usercmd tests passed\n"; return 0; }
    catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
