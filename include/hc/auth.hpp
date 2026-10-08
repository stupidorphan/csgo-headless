#pragma once

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <vector>

namespace hc {

struct SteamCredentials {
    std::uint64_t steam_id{};
    std::vector<std::uint8_t> ticket;
};

// A fresh ticket and a callback-pumping helper are retained for each connection.
// Authentication material crosses anonymous pipes only and is never logged.
class SteamAuth {
public:
    explicit SteamAuth(std::filesystem::path helper = {});
    ~SteamAuth();
    SteamAuth(const SteamAuth&) = delete;
    SteamAuth& operator=(const SteamAuth&) = delete;
    SteamCredentials acquire(std::chrono::milliseconds timeout = std::chrono::seconds(15));
    void close() noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace hc
