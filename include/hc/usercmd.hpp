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
    std::array<float, 3> headangles{};
    std::uint32_t headoffset{};
    bool operator==(const UserCmd&) const = default;
};

// Legacy 13881 adds four unconditional head fields after the mouse deltas.
// The installed serializer uses raw floats and a raw 32-bit head-offset value.
void write_usercmd_delta(BitWriter&, const UserCmd& to, const UserCmd& from);
UserCmd read_usercmd_delta(BitReader&, const UserCmd& from);
Proto make_move(std::span<const UserCmd> backup, std::span<const UserCmd> fresh);

class InputController {
public:
    // forward/side/up in [-1,1], pitch in [-89,89], yaw in degrees;
    // buttons is an array of names; duration_ticks is the nonzero duration.
    void set(const nlohmann::json& args);
    // Server angle corrections preserve held input and its original deadline.
    // Relative corrections add yaw only; absolute corrections replace the view.
    void fix_angles(const std::array<float, 3>& angles, bool relative);
    void select_weapon(std::uint16_t entity_index, std::uint8_t subtype = 0);
    UserCmd next(std::int32_t server_tick);
    void reset();
private:
    UserCmd current_;
    std::uint32_t duration_{}, start_tick_{};
    bool start_pending_{};
};

} // namespace hc
