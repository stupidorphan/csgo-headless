#pragma once
#include <chrono>
#include <filesystem>
#include <functional>
#include <memory>
#include <nlohmann/json.hpp>
#include "hc/proto.hpp"
namespace hc {
using Json=nlohmann::json;
struct ClientConfig {
    std::string server="151.243.93.16:27015";
    std::string name="headless";
    std::filesystem::path profile="profiles/legacy_13881.json";
    std::filesystem::path auth_helper;
    bool trace=false;
};
class Session {
public:
    using EventSink=std::function<void(const Json&)>;
    explicit Session(ClientConfig config,EventSink events={});
    ~Session();
    Json command(std::string_view op,const Json& args=Json::object());
    void poll();
    void disconnect(std::string reason="client disconnect");
    Json status() const;
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
Json parse_interactive(std::string_view line);
Bytes build_connect_packet(uint32_t version,uint32_t challenge,uint64_t steam_id,std::span<const uint8_t> ticket,const Proto& userinfo);
Proto make_userinfo(std::string_view name,uint32_t update_rate=64);
}
