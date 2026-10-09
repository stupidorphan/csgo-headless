#include "hc/steam_cm.hpp"

#include "hc/proto.hpp"

#include <windows.h>
#include <winhttp.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <condition_variable>
#include <cstring>
#include <iostream>
#include <mutex>
#include <random>
#include <stdexcept>
#include <thread>

#pragma comment(lib, "winhttp.lib")

namespace hc {
namespace {
using Clock = std::chrono::steady_clock;

constexpr std::uint32_t kProtoFlag = 0x80000000u;
constexpr std::uint32_t kClientHello = 9805;
constexpr std::uint32_t kClientLogon = 5514;
constexpr std::uint32_t kClientLogonResponse = 751;
constexpr std::uint32_t kClientGameConnectTokens = 779;
constexpr std::uint32_t kClientGetAppOwnershipTicket = 857;
constexpr std::uint32_t kClientGetAppOwnershipTicketResponse = 858;
constexpr std::uint32_t kClientAuthList = 5432;
constexpr std::uint32_t kClientHeartBeat = 703;
constexpr std::uint32_t kClientAuthListAck = 5575;

std::uint32_t load_u32(const std::uint8_t* p) {
    return std::uint32_t(p[0]) | (std::uint32_t(p[1]) << 8) | (std::uint32_t(p[2]) << 16) | (std::uint32_t(p[3]) << 24);
}
void store_u32(Bytes& out, std::uint32_t value) {
    for (unsigned i = 0; i != 4; ++i) out.push_back(static_cast<std::uint8_t>(value >> (8 * i)));
}
std::uint32_t ticket_crc32(std::span<const std::uint8_t> data) {
    std::uint32_t crc = 0xffffffffu;
    for (const auto byte : data) {
        crc ^= byte;
        for (unsigned bit = 0; bit != 8; ++bit) crc = (crc >> 1) ^ (0xedb88320u & (0u - (crc & 1u)));
    }
    return ~crc;
}
void wipe(Bytes& data) noexcept {
    if (!data.empty()) SecureZeroMemory(data.data(), data.size());
    data.clear();
}
struct SecretBytes {
    Bytes data;
    ~SecretBytes() { wipe(data); }
};

} // namespace

struct SteamCM::Impl {
    HINTERNET session{};
    HINTERNET connection{};
    HINTERNET request{};
    HINTERNET socket{};
    std::thread reader;
    std::thread heartbeat;
    mutable std::mutex mutex;
    std::condition_variable changed;
    bool stopping = false;
    bool logged = false;
    std::uint64_t steam_id = 0;
    std::int32_t session_id = 0;
    std::atomic<std::uint64_t> next_job{1};
    std::uint32_t next_sequence = 1;
    std::string error;
    std::vector<Bytes> game_tokens;
    std::uint32_t token_limit = 10;
    Bytes ownership_ticket;
    std::uint64_t ownership_job = 0;
    std::uint32_t waiting_crc = 0;
    bool acknowledged = false;

    ~Impl() { close(); }

    void fail(std::string message) {
        std::lock_guard lock(mutex);
        if (error.empty()) error = std::move(message);
        changed.notify_all();
    }

    Bytes header(std::uint64_t source, std::uint64_t target) {
        ProtoWriter writer;
        writer.fixed64(10, source);
        if (target) writer.fixed64(11, target);
        if (steam_id) writer.fixed64(1, steam_id);
        if (session_id) writer.i32(2, session_id);
        return writer.take();
    }

    void send_raw(std::span<const std::uint8_t> data) {
        std::lock_guard lock(mutex);
        if (!socket || stopping) throw std::runtime_error("Steam CM is disconnected");
        const auto status = WinHttpWebSocketSend(socket, WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE,
                                                 const_cast<BYTE*>(data.data()), static_cast<DWORD>(data.size()));
        if (status != NO_ERROR) throw std::runtime_error("Steam CM send failed: " + std::to_string(status));
    }

    std::uint64_t allocate_job() { return next_job.fetch_add(1, std::memory_order_relaxed); }

    std::uint64_t send_proto_with_job(std::uint32_t message, const Proto& body, std::uint64_t target, std::uint64_t job) {
        const auto proto_header = header(job, target);
        Bytes packet;
        store_u32(packet, message | kProtoFlag);
        store_u32(packet, static_cast<std::uint32_t>(proto_header.size()));
        packet.insert(packet.end(), proto_header.begin(), proto_header.end());
        packet.insert(packet.end(), body.data().begin(), body.data().end());
        send_raw(packet);
        return job;
    }

    std::uint64_t send_proto(std::uint32_t message, const Proto& body, std::uint64_t target = 0) {
        return send_proto_with_job(message, body, target, allocate_job());
    }

    void send_hello() {
        ProtoWriter body; body.u32(1, 65581);
        send_proto(kClientHello, Proto(body.data()));
    }

    void send_logon(std::string_view account, std::string_view access_token) {
        ProtoWriter body;
        body.u32(1, 65581).u32(3, 0).u32(5, 1771).string(6, "english").u32(7, 20)
            .string(50, account).u32(102, 1).string(96, "headless-csgo").string(108, access_token);
        send_proto(kClientLogon, Proto(body.data()));
    }

    void handle(std::span<const std::uint8_t> data) {
        if (data.size() < 8) throw std::runtime_error("Steam CM message is truncated");
        const auto raw = load_u32(data.data());
        if ((raw & kProtoFlag) == 0) return;
        const auto header_size = load_u32(data.data() + 4);
        if (header_size > data.size() - 8 || header_size > 64 * 1024) throw std::runtime_error("Steam CM protobuf header is invalid");
        Proto hp(data.subspan(8, header_size));
        const auto message = raw & ~kProtoFlag;
        const auto body_offset = 8 + header_size;
        Proto body(data.subspan(body_offset));
        const auto source = hp.get_u64(10, UINT64_MAX);
        const auto target = hp.get_u64(11, 0);
        std::lock_guard lock(mutex);
        if (message == kClientLogonResponse) {
            const auto result = body.get_u32(1, 2);
            if (result != 1) { error = "Steam CM login rejected with EResult " + std::to_string(result); }
            else {
                steam_id = hp.get_u64(1, steam_id);
                session_id = hp.get_i32(2, 0);
                logged = true;
            }
            changed.notify_all();
        } else if (message == kClientGameConnectTokens) {
            token_limit = body.get_u32(1, 10);
            for (const auto& field : body.fields(2)) if (field.wire_type == 2) game_tokens.push_back(field.data);
            while (game_tokens.size() > token_limit) game_tokens.erase(game_tokens.begin());
            changed.notify_all();
        } else if (message == kClientGetAppOwnershipTicketResponse && target == ownership_job) {
            if (body.get_u32(1, 2) != 1) error = "Steam rejected the AppID 730 ownership-ticket request";
            else ownership_ticket = body.get_bytes(3);
            changed.notify_all();
        } else if (message == kClientAuthListAck) {
            for (const auto& field : body.fields(1)) if (field.wire_type == 0 && field.varint == waiting_crc) acknowledged = true;
            changed.notify_all();
        }
        (void)source;
    }

    void reader_loop() {
        std::array<std::uint8_t, 64 * 1024> buffer{};
        Bytes message;
        while (true) {
            DWORD received = 0; WINHTTP_WEB_SOCKET_BUFFER_TYPE type{};
            const auto status = WinHttpWebSocketReceive(socket, buffer.data(), static_cast<DWORD>(buffer.size()), &received, &type);
            if (status != NO_ERROR || type == WINHTTP_WEB_SOCKET_CLOSE_BUFFER_TYPE) break;
            if (type != WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE && type != WINHTTP_WEB_SOCKET_BINARY_FRAGMENT_BUFFER_TYPE) continue;
            if (message.size() + received > 4 * 1024 * 1024) { fail("Steam CM message exceeds the safety limit"); break; }
            message.insert(message.end(), buffer.begin(), buffer.begin() + received);
            if (type == WINHTTP_WEB_SOCKET_BINARY_FRAGMENT_BUFFER_TYPE) continue;
            try { handle(message); message.clear(); }
            catch (const std::exception& e) { fail(e.what()); break; }
        }
        std::lock_guard lock(mutex); logged = false; stopping = true; changed.notify_all();
    }

    void heartbeat_loop() {
        while (true) {
            std::unique_lock lock(mutex);
            if (changed.wait_for(lock, std::chrono::seconds(30), [this] { return stopping; })) return;
            lock.unlock();
            try { send_proto(kClientHeartBeat, Proto{}); }
            catch (const std::exception& e) { fail(e.what()); return; }
        }
    }

    void connect(std::string account, std::string access_token, std::uint64_t expected, std::chrono::milliseconds timeout) {
        close();
        session = WinHttpOpen(L"headless-csgo/1.0", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!session) throw std::runtime_error("Steam CM WinHTTP session failed");
        connection = WinHttpConnect(session, L"cm0.steampowered.com", INTERNET_DEFAULT_HTTPS_PORT, 0);
        if (!connection) throw std::runtime_error("Steam CM DNS lookup failed");
        request = WinHttpOpenRequest(connection, L"GET", L"/cmsocket/", nullptr, WINHTTP_NO_REFERER,
                                     WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
        if (!request) throw std::runtime_error("Steam CM WebSocket request failed");
        if (!WinHttpSetOption(request, WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET, nullptr, 0)) throw std::runtime_error("Steam CM WebSocket upgrade setup failed");
        WinHttpSetTimeouts(request, 10000, 10000, 10000, 10000);
        if (!WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
            !WinHttpReceiveResponse(request, nullptr)) throw std::runtime_error("Steam CM WebSocket connection failed");
        socket = WinHttpWebSocketCompleteUpgrade(request, 0);
        if (!socket) throw std::runtime_error("Steam CM WebSocket upgrade was rejected");
        WinHttpCloseHandle(request); request = nullptr;
        { std::lock_guard lock(mutex); stopping = false; logged = false; error.clear(); steam_id = expected; session_id = 0; next_job.store(1, std::memory_order_relaxed); }
        reader = std::thread([this] { reader_loop(); });
        heartbeat = std::thread([this] { heartbeat_loop(); });
        send_hello();
        send_logon(account, access_token);
        std::unique_lock lock(mutex);
        if (!changed.wait_for(lock, timeout, [this] { return logged || !error.empty() || stopping; })) throw std::runtime_error("Steam CM login timed out");
        if (!error.empty()) throw std::runtime_error(error);
        if (!logged) throw std::runtime_error("Steam CM disconnected during login");
    }

    SteamCredentials issue_ticket(std::uint32_t appid, std::chrono::milliseconds timeout) {
        std::unique_lock lock(mutex);
        if (!logged || !socket) throw std::runtime_error("Steam CM is not logged in");
        if (!changed.wait_for(lock, timeout, [this] { return !game_tokens.empty() || !error.empty() || stopping; })) throw std::runtime_error("Steam CM did not provide a game-connect token");
        if (!error.empty()) throw std::runtime_error(error);
        SecretBytes token{std::move(game_tokens.front())}; game_tokens.erase(game_tokens.begin());
        wipe(ownership_ticket);
        ProtoWriter ownership_body; ownership_body.u32(1, appid);
        const auto ownership_job_id = allocate_job();
        ownership_job = ownership_job_id;
        lock.unlock();
        send_proto_with_job(kClientGetAppOwnershipTicket, Proto(ownership_body.data()), 0, ownership_job_id);
        lock.lock();
        if (ownership_job != ownership_job_id) throw std::runtime_error("Steam CM ownership-ticket job correlation changed unexpectedly");
        if (!changed.wait_for(lock, timeout, [this] { return !ownership_ticket.empty() || !error.empty() || stopping; })) throw std::runtime_error("Steam ownership-ticket request timed out");
        if (!error.empty()) throw std::runtime_error(error);

        SecretBytes auth_holder;
        auto& auth = auth_holder.data;
        store_u32(auth, static_cast<std::uint32_t>(token.data.size())); auth.insert(auth.end(), token.data.begin(), token.data.end());
        store_u32(auth, 24); store_u32(auth, 1); store_u32(auth, 2);
        std::array<std::uint8_t, 8> random{}; BCryptGenRandom(nullptr, random.data(), static_cast<ULONG>(random.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG); auth.insert(auth.end(), random.begin(), random.end());
        LARGE_INTEGER counter{};
        if (!QueryPerformanceCounter(&counter)) throw std::runtime_error("Steam ticket timestamp is unavailable");
        store_u32(auth, static_cast<std::uint32_t>(counter.QuadPart)); store_u32(auth, next_sequence++);
        const auto crc = ticket_crc32(auth);
        ProtoWriter ticket; ticket.u64(4, appid).u32(6, crc).bytes(7, auth);
        ProtoWriter list; list.u32(1, static_cast<std::uint32_t>(game_tokens.size())).message(4, ticket).u32(5, appid);
        waiting_crc = crc; acknowledged = false;
        lock.unlock();
        send_proto(kClientAuthList, Proto(list.data()));
        lock.lock();
        const auto acknowledged_in_time = changed.wait_for(lock, std::chrono::seconds(10), [this] { return acknowledged || !error.empty() || stopping; });
        if (stopping) throw std::runtime_error("Steam CM disconnected after submitting the AppID 730 ticket");
        if (!error.empty()) throw std::runtime_error(error);
        if (!acknowledged_in_time && !acknowledged)
            std::cerr << "headless-csgo: Steam did not acknowledge the submitted AppID 730 ticket; server validation remains authoritative\n";
        Bytes result = std::move(auth); const auto length = static_cast<std::uint32_t>(ownership_ticket.size());
        store_u32(result, length); result.insert(result.end(), ownership_ticket.begin(), ownership_ticket.end());
        wipe(ownership_ticket);
        return {steam_id, std::move(result)};
    }

    void close() noexcept {
        {
            std::lock_guard lock(mutex); stopping = true; logged = false; changed.notify_all();
        }
        if (heartbeat.joinable()) heartbeat.join();
        if (socket) WinHttpWebSocketClose(socket, WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS, nullptr, 0);
        if (reader.joinable()) reader.join();
        if (socket) WinHttpCloseHandle(socket); socket = nullptr;
        if (request) WinHttpCloseHandle(request); request = nullptr;
        if (connection) WinHttpCloseHandle(connection); connection = nullptr;
        if (session) WinHttpCloseHandle(session); session = nullptr;
        for (auto& token : game_tokens) wipe(token);
        game_tokens.clear(); wipe(ownership_ticket); error.clear();
    }
};

SteamCM::SteamCM() : impl_(std::make_unique<Impl>()) {}
SteamCM::~SteamCM() = default;
void SteamCM::connect(std::string account_name, std::string access_token, std::uint64_t expected_steam_id, std::chrono::milliseconds timeout) { impl_->connect(std::move(account_name), std::move(access_token), expected_steam_id, timeout); }
bool SteamCM::logged_in() const noexcept { std::lock_guard lock(impl_->mutex); return impl_->logged; }
std::uint64_t SteamCM::steam_id() const noexcept { std::lock_guard lock(impl_->mutex); return impl_->steam_id; }
SteamCredentials SteamCM::issue_ticket(std::uint32_t appid, std::chrono::milliseconds timeout) { return impl_->issue_ticket(appid, timeout); }
void SteamCM::close() noexcept { impl_->close(); }

} // namespace hc
