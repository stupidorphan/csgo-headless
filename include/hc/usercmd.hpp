#pragma once

#include "hc/proto.hpp"
#include "hc/wire.hpp"
#include <array>
#include <cstdint>
#include <nlohmann/json.hpp>
#include <span>

namespace hc {

struct UserCmd {
    std::int32_t command_number{};
    std::int32_t tick_count{};
    std::array<float, 3> viewangles{};
    std::array<float, 3> aimdirection{};
    float forwardmove{}, sidemove{}, upmove{};
    std::uint32_t buttons{};
    std::uint8_t impulse{};
    std::uint16_t weaponselect{};
    std::uint8_t weaponsubtype{};
    std::int16_t mousedx{}, mousedy{};
    bool operator==(const UserCmd&) const = default;
};

// CS:GO's non-HL2, non-Portal user-command layout, with head tracking disabled.
void write_usercmd_delta(BitWriter&, const UserCmd& to, const UserCmd& from);
UserCmd read_usercmd_delta(BitReader&, const UserCmd& from);
Proto make_move(std::span<const UserCmd> backup, std::span<const UserCmd> fresh);

class InputController {
public:
    // forward/side/up in [-1,1], pitch in [-89,89], yaw in degrees;
    // buttons is an array of names; duration_ticks is the nonzero duration.
    void set(const nlohmann::json& args);
    void select_weapon(std::uint16_t entity_index, std::uint8_t subtype = 0);
    UserCmd next(std::int32_t server_tick);
    void reset();
private:
    UserCmd current_;
    std::uint32_t ticks_left_{};
};

} // namespace hc
