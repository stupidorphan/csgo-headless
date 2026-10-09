#pragma once

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace hc {

struct SteamCredentials {
    std::uint64_t steam_id{};
    std::vector<std::uint8_t> ticket;
};

using Json = nlohmann::json;

enum class SteamAuthMode {
    qr,
    password,
};

// Steam authentication is independent from the gameplay UDP session. The
// implementation owns its CM/HTTP state and emits only non-secret lifecycle
// information to the caller.
class SteamAuth {
public:
    using EventSink = std::function<void(const Json&)>;

    explicit SteamAuth(std::filesystem::path token_file = {});
    ~SteamAuth();
    SteamAuth(const SteamAuth&) = delete;
    SteamAuth& operator=(const SteamAuth&) = delete;

    void set_event_sink(EventSink sink);
    void start(SteamAuthMode mode);
    void submit(std::string prompt_id, std::string value);
    void poll();
    bool ready() const noexcept;
    Json status() const;
    SteamCredentials acquire_ticket(std::chrono::milliseconds timeout = std::chrono::seconds(15));
    void close() noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace hc
