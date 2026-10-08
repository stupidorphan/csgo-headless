#include "hc/usercmd.hpp"
#include <algorithm>
#include <cmath>
#include <limits>
#include <stdexcept>
#include <string>
#include <unordered_map>

namespace hc {
namespace {
bool delta_int(BitWriter& out, std::uint32_t to, std::uint32_t from, unsigned bits) {
    const bool changed = to != from;
    out.bit(changed);
    if (changed) out.bits(to, bits);
    return changed;
}
void delta_float(BitWriter& out, float to, float from) {
    if (!std::isfinite(to)) throw std::invalid_argument("User command contains a nonfinite float");
    out.bit(to != from);
    if (to != from) out.float32(to);
}
float read_float(BitReader& in, float from) {
    const auto value = in.bit() ? in.float32() : from;
    if (!std::isfinite(value)) throw std::invalid_argument("User command contains a nonfinite float");
    return value;
}
std::uint32_t increment(std::int32_t value) {
    return static_cast<std::uint32_t>(value) + 1u;
}
float number(const nlohmann::json& args, const char* name, float fallback, float low, float high) {
    const auto value = args.value(name, fallback);
    if (!std::isfinite(value) || value < low || value > high)
        throw std::invalid_argument(std::string(name) + " is outside its permitted range");
    return value;
}
}

void write_usercmd_delta(BitWriter& out, const UserCmd& to, const UserCmd& from) {
    delta_int(out, static_cast<std::uint32_t>(to.command_number), increment(from.command_number), 32);
    delta_int(out, static_cast<std::uint32_t>(to.tick_count), increment(from.tick_count), 32);
    for (std::size_t i = 0; i < 3; ++i) delta_float(out, to.viewangles[i], from.viewangles[i]);
    for (std::size_t i = 0; i < 3; ++i) delta_float(out, to.aimdirection[i], from.aimdirection[i]);
    delta_float(out, to.forwardmove, from.forwardmove);
    delta_float(out, to.sidemove, from.sidemove);
    delta_float(out, to.upmove, from.upmove);
    delta_int(out, to.buttons, from.buttons, 32);
    delta_int(out, to.impulse, from.impulse, 8);
    if (to.weaponselect >= 2048 || to.weaponsubtype >= 64)
        throw std::invalid_argument("Weapon entity index or subtype exceeds Source wire bounds");
    if (delta_int(out, to.weaponselect, from.weaponselect, 11))
        delta_int(out, to.weaponsubtype, from.weaponsubtype, 6);
    delta_int(out, static_cast<std::uint16_t>(to.mousedx), static_cast<std::uint16_t>(from.mousedx), 16);
    delta_int(out, static_cast<std::uint16_t>(to.mousedy), static_cast<std::uint16_t>(from.mousedy), 16);
}

UserCmd read_usercmd_delta(BitReader& in, const UserCmd& from) {
    UserCmd to = from;
    to.command_number = static_cast<std::int32_t>(in.bit() ? in.bits(32) : increment(from.command_number));
    to.tick_count = static_cast<std::int32_t>(in.bit() ? in.bits(32) : increment(from.tick_count));
    for (std::size_t i = 0; i < 3; ++i) to.viewangles[i] = read_float(in, from.viewangles[i]);
    for (std::size_t i = 0; i < 3; ++i) to.aimdirection[i] = read_float(in, from.aimdirection[i]);
    to.forwardmove = read_float(in, from.forwardmove);
    to.sidemove = read_float(in, from.sidemove);
    to.upmove = read_float(in, from.upmove);
    if (in.bit()) to.buttons = in.bits(32);
    if (in.bit()) to.impulse = static_cast<std::uint8_t>(in.bits(8));
    if (in.bit()) {
        to.weaponselect = static_cast<std::uint16_t>(in.bits(11));
        if (in.bit()) to.weaponsubtype = static_cast<std::uint8_t>(in.bits(6));
    }
    if (in.bit()) to.mousedx = static_cast<std::int16_t>(in.bits(16));
    if (in.bit()) to.mousedy = static_cast<std::int16_t>(in.bits(16));
    return to;
}

Proto make_move(std::span<const UserCmd> backup, std::span<const UserCmd> fresh) {
    if (backup.size() > 7 || fresh.empty() || fresh.size() > 15)
        throw std::invalid_argument("Move requires 1..15 new commands and at most 7 backups");
    BitWriter out(65536);
    UserCmd previous;
    bool first = true;
    for (auto commands : {backup, fresh}) {
        for (const auto& command : commands) {
            if (!first && static_cast<std::uint32_t>(command.command_number) != increment(previous.command_number))
                throw std::invalid_argument("Move commands must have contiguous command numbers");
            write_usercmd_delta(out, command, previous);
            previous = command;
            first = false;
        }
    }
    ProtoWriter message;
    message.u32(1, static_cast<std::uint32_t>(backup.size()));
    message.u32(2, static_cast<std::uint32_t>(fresh.size()));
    message.bytes(3, out.data());
    return Proto(message.data());
}

void InputController::set(const nlohmann::json& args) {
    if (!args.is_object()) throw std::invalid_argument("input args must be an object");
    UserCmd next = current_;
    next.forwardmove = number(args, "forward", 0, -1, 1) * 450.0f;
    next.sidemove = number(args, "side", 0, -1, 1) * 450.0f;
    next.upmove = number(args, "up", 0, -1, 1) * 320.0f;
    next.viewangles[0] = number(args, "pitch", current_.viewangles[0], -89, 89);
    const auto yaw = number(args, "yaw", current_.viewangles[1], -360000, 360000);
    next.viewangles[1] = std::remainder(yaw, 360.0f);
    next.viewangles[2] = 0;
    const auto duration = args.value("duration_ticks", args.value("ticks", std::int64_t{1}));
    if (duration < 1 || duration > 65536) throw std::invalid_argument("duration_ticks must be between 1 and 65536");
    next.buttons = 0;
    static const std::unordered_map<std::string, std::uint32_t> buttons{
        {"attack", 1u << 0}, {"fire", 1u << 0}, {"jump", 1u << 1}, {"duck", 1u << 2},
        {"crouch", 1u << 2}, {"forward", 1u << 3}, {"back", 1u << 4}, {"use", 1u << 5},
        {"left", 1u << 7}, {"right", 1u << 8}, {"moveleft", 1u << 9}, {"moveright", 1u << 10},
        {"attack2", 1u << 11}, {"reload", 1u << 13}, {"speed", 1u << 17}, {"walk", 1u << 18},
        {"zoom", 1u << 19}, {"bullrush", 1u << 22}
    };
    if (args.contains("buttons")) {
        if (!args["buttons"].is_array()) throw std::invalid_argument("buttons must be an array of names");
        for (const auto& name : args["buttons"]) {
            const auto found = buttons.find(name.get<std::string>());
            if (found == buttons.end()) throw std::invalid_argument("Unknown input button: " + name.get<std::string>());
            next.buttons |= found->second;
        }
    }
    if (next.forwardmove > 0) next.buttons |= 1u << 3;
    if (next.forwardmove < 0) next.buttons |= 1u << 4;
    if (next.sidemove < 0) next.buttons |= 1u << 9;
    if (next.sidemove > 0) next.buttons |= 1u << 10;
    current_ = next;
    ticks_left_ = static_cast<std::uint32_t>(duration);
}

void InputController::select_weapon(std::uint16_t entity_index, std::uint8_t subtype) {
    if (!entity_index || entity_index >= 2048 || subtype >= 64)
        throw std::invalid_argument("Weapon entity index must be 1..2047 and subtype 0..63");
    current_.weaponselect = entity_index;
    current_.weaponsubtype = subtype;
}

UserCmd InputController::next(std::int32_t server_tick) {
    current_.command_number = static_cast<std::int32_t>(increment(current_.command_number));
    current_.tick_count = server_tick;
    if (!ticks_left_) {
        current_.forwardmove = current_.sidemove = current_.upmove = 0;
        current_.buttons = 0;
    } else --ticks_left_;
    const auto command = current_;
    // Selection is an action, not a permanently held input.
    current_.weaponselect = 0;
    current_.weaponsubtype = 0;
    return command;
}

void InputController::reset() { current_ = {}; ticks_left_ = 0; }

} // namespace hc
