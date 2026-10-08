#pragma once

#include "hc/proto.hpp"
#include <cstdint>
#include <memory>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace hc {

class StateError : public std::runtime_error { using std::runtime_error::runtime_error; };

class State {
public:
    State();
    ~State();
    State(State&&) noexcept;
    State& operator=(State&&) noexcept;
    State(const State&) = delete;
    State& operator=(const State&) = delete;
    void load_profile(const nlohmann::json& profile);
    // Clear session data; preserve the compatibility profile and derived schema.
    void reset();
    void set_server_info(std::string map, std::int32_t player_slot,
                         std::int32_t max_clients, float tick_interval);
    // Returns false for unhandled messages and snapshots requiring a full update.
    // Malformed packets throw StateError without committing a partial snapshot.
    bool consume(std::uint32_t message_type, const Proto&, std::int32_t tick);
    nlohmann::json status() const;
    std::vector<nlohmann::json> take_events();
    std::vector<std::pair<std::uint32_t, Proto>> take_outgoing();
    bool needs_full_update() const;
    void clear_full_update_request();
    std::int32_t entity_tick() const;
    std::size_t class_count() const;
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace hc
