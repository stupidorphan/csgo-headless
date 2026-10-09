#pragma once

#include "hc/auth.hpp"

#include <chrono>
#include <memory>
#include <string>

namespace hc {

// Minimal Steam3 CM client used by SteamAuth.  It intentionally exposes only
// the operations needed to authenticate AppID 730 and issue a game ticket.
class SteamCM {
public:
    SteamCM();
    ~SteamCM();
    SteamCM(const SteamCM&) = delete;
    SteamCM& operator=(const SteamCM&) = delete;

    void connect(std::string account_name, std::string access_token, std::uint64_t expected_steam_id,
                 std::chrono::milliseconds timeout = std::chrono::seconds(20));
    bool logged_in() const noexcept;
    std::uint64_t steam_id() const noexcept;
    SteamCredentials issue_ticket(std::uint32_t appid,
                                   std::chrono::milliseconds timeout = std::chrono::seconds(15));
    void close() noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace hc
