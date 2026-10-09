#include <windows.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <ncrypt.h>
#include <aclapi.h>

#include "hc/auth.hpp"
#include "hc/qr.hpp"
#include "hc/steam_cm.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <random>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string_view>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "bcrypt.lib")

namespace hc {
namespace {
using Clock = std::chrono::steady_clock;
using Json = nlohmann::json;

std::uint64_t json_u64(const Json& value, std::string_view key, std::uint64_t fallback = 0) {
    if (!value.contains(key)) return fallback;
    const auto& item = value.at(key);
    if (item.is_number_unsigned()) return item.get<std::uint64_t>();
    if (item.is_number_integer()) return static_cast<std::uint64_t>(item.get<std::int64_t>());
    if (item.is_string()) {
        try { return std::stoull(item.get<std::string>()); }
        catch (...) { return fallback; }
    }
    return fallback;
}

double json_number(const Json& value, std::string_view key, double fallback) {
    if (!value.contains(key)) return fallback;
    const auto& item = value.at(key);
    if (item.is_number()) return item.get<double>();
    if (item.is_string()) {
        try { return std::stod(item.get<std::string>()); }
        catch (...) { return fallback; }
    }
    return fallback;
}

void clear(std::string& value) noexcept {
    if (!value.empty()) SecureZeroMemory(value.data(), value.size());
    value.clear();
}

std::filesystem::path executable_directory() {
    std::vector<wchar_t> path(32768);
    const auto size = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    if (!size || size == path.size()) throw std::runtime_error("Cannot locate client executable");
    return std::filesystem::path(std::wstring(path.data(), size)).parent_path();
}

std::vector<std::uint8_t> hex_decode(std::string_view value) {
    if ((value.size() & 1) != 0) throw std::runtime_error("Steam RSA key is not valid hexadecimal");
    auto nibble = [](char c) -> std::uint8_t {
        if (c >= '0' && c <= '9') return static_cast<std::uint8_t>(c - '0');
        if (c >= 'a' && c <= 'f') return static_cast<std::uint8_t>(c - 'a' + 10);
        if (c >= 'A' && c <= 'F') return static_cast<std::uint8_t>(c - 'A' + 10);
        throw std::runtime_error("Steam RSA key is not valid hexadecimal");
    };
    std::vector<std::uint8_t> result;
    result.reserve(value.size() / 2);
    for (size_t i = 0; i < value.size(); i += 2)
        result.push_back(static_cast<std::uint8_t>((nibble(value[i]) << 4) | nibble(value[i + 1])));
    return result;
}

std::string base64(std::span<const std::uint8_t> bytes) {
    constexpr char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string result;
    result.reserve(((bytes.size() + 2) / 3) * 4);
    for (size_t i = 0; i < bytes.size(); i += 3) {
        const auto a = bytes[i];
        const auto b = i + 1 < bytes.size() ? bytes[i + 1] : 0;
        const auto c = i + 2 < bytes.size() ? bytes[i + 2] : 0;
        result.push_back(alphabet[a >> 2]);
        result.push_back(alphabet[((a & 3) << 4) | (b >> 4)]);
        result.push_back(i + 1 < bytes.size() ? alphabet[((b & 15) << 2) | (c >> 6)] : '=');
        result.push_back(i + 2 < bytes.size() ? alphabet[c & 63] : '=');
    }
    return result;
}

std::string url_encode(std::string_view value) {
    constexpr char hex[] = "0123456789ABCDEF";
    std::string result;
    for (const auto c : value) {
        const auto u = static_cast<unsigned char>(c);
        if ((u >= 'a' && u <= 'z') || (u >= 'A' && u <= 'Z') || (u >= '0' && u <= '9') ||
            u == '-' || u == '_' || u == '.' || u == '~') result.push_back(static_cast<char>(u));
        else if (u == ' ') result.push_back('+');
        else { result.push_back('%'); result.push_back(hex[u >> 4]); result.push_back(hex[u & 15]); }
    }
    return result;
}

Json http_post(std::string_view path, const Json& body) {
    const auto form = std::string("input_json=") + url_encode(body.dump());
    HINTERNET session = WinHttpOpen(L"headless-csgo/1.0", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                                    WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) throw std::runtime_error("Steam authentication HTTP session failed");
    auto close_session = [&] { WinHttpCloseHandle(session); };
    HINTERNET connection = WinHttpConnect(session, L"api.steampowered.com", INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!connection) { close_session(); throw std::runtime_error("Steam authentication HTTP connection failed"); }
    auto close_connection = [&] { WinHttpCloseHandle(connection); close_session(); };
    std::wstring wide_path(path.begin(), path.end());
    HINTERNET request = WinHttpOpenRequest(connection, L"POST", wide_path.c_str(), nullptr,
                                           WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                           WINHTTP_FLAG_SECURE);
    if (!request) { close_connection(); throw std::runtime_error("Steam authentication HTTP request failed"); }
    const wchar_t* headers = L"Content-Type: application/x-www-form-urlencoded\r\nAccept: application/json\r\n";
    const bool sent = WinHttpSendRequest(request, headers, static_cast<DWORD>(-1L),
                                         const_cast<char*>(form.data()), static_cast<DWORD>(form.size()),
                                         static_cast<DWORD>(form.size()), 0) != FALSE &&
                      WinHttpReceiveResponse(request, nullptr) != FALSE;
    if (!sent) { WinHttpCloseHandle(request); close_connection(); throw std::runtime_error("Steam authentication HTTP exchange failed"); }
    DWORD status = 0, status_size = sizeof(status);
    if (!WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                             WINHTTP_HEADER_NAME_BY_INDEX, &status, &status_size, WINHTTP_NO_HEADER_INDEX) || status != 200) {
        WinHttpCloseHandle(request); close_connection(); throw std::runtime_error("Steam authentication HTTP request was rejected");
    }
    std::string response;
    for (;;) {
        DWORD available = 0;
        if (!WinHttpQueryDataAvailable(request, &available)) { WinHttpCloseHandle(request); close_connection(); throw std::runtime_error("Steam authentication HTTP read failed"); }
        if (!available) break;
        std::string chunk(available, '\0'); DWORD read = 0;
        if (!WinHttpReadData(request, chunk.data(), available, &read)) { WinHttpCloseHandle(request); close_connection(); throw std::runtime_error("Steam authentication HTTP read failed"); }
        response.append(chunk.data(), read);
        if (response.size() > 1024 * 1024) { WinHttpCloseHandle(request); close_connection(); throw std::runtime_error("Steam authentication response exceeds limit"); }
    }
    WinHttpCloseHandle(request); close_connection();
    try { return Json::parse(response).at("response"); }
    catch (const Json::exception&) { throw std::runtime_error("Steam authentication returned malformed JSON"); }
}

std::vector<std::uint8_t> rsa_encrypt(std::string_view password, std::string_view modulus_hex, std::string_view exponent_hex) {
    auto modulus = hex_decode(modulus_hex), exponent = hex_decode(exponent_hex);
    if (modulus.empty() || exponent.empty() || modulus.size() > 512 || exponent.size() > 8)
        throw std::runtime_error("Steam RSA key dimensions are invalid");
    struct RsaBlob {
        BCRYPT_RSAKEY_BLOB header{};
        std::array<std::uint8_t, 8> exponent{};
        std::array<std::uint8_t, 512> modulus{};
    } blob;
    blob.header.Magic = BCRYPT_RSAPUBLIC_MAGIC;
    blob.header.BitLength = static_cast<ULONG>(modulus.size() * 8);
    blob.header.cbPublicExp = static_cast<ULONG>(exponent.size());
    blob.header.cbModulus = static_cast<ULONG>(modulus.size());
    std::copy(exponent.begin(), exponent.end(), blob.exponent.begin());
    std::copy(modulus.begin(), modulus.end(), blob.modulus.begin());
    BCRYPT_KEY_HANDLE key = nullptr;
    NTSTATUS status = BCryptImportKeyPair(nullptr, nullptr, BCRYPT_RSAPUBLIC_BLOB,
                                          &key, reinterpret_cast<PUCHAR>(&blob),
                                          static_cast<ULONG>(sizeof(blob.header) + exponent.size() + modulus.size()), 0);
    if (status < 0) throw std::runtime_error("Steam RSA public key import failed");
    std::vector<std::uint8_t> output(512); ULONG size = 0;
    status = BCryptEncrypt(key, reinterpret_cast<PUCHAR>(const_cast<char*>(password.data())),
                           static_cast<ULONG>(password.size()), nullptr, nullptr, 0,
                           output.data(), static_cast<ULONG>(output.size()), &size, BCRYPT_PAD_PKCS1);
    BCryptDestroyKey(key);
    if (status < 0) throw std::runtime_error("Steam password encryption failed");
    output.resize(size);
    return output;
}

std::string prompt_kind(std::uint32_t type) {
    switch (type) {
    case 1: return "none";
    case 2: return "email_code";
    case 3: return "totp";
    case 4: return "mobile_confirmation";
    case 5: return "email_confirmation";
    case 6: return "machine_token";
    default: return "steam_guard";
    }
}

} // namespace

struct SteamAuth::Impl {
    explicit Impl(std::filesystem::path path) : token_file(path.empty() ? executable_directory() / L"steam-auth.json" : std::move(path)) {
        load_token();
    }

    ~Impl() { close(); }

    std::filesystem::path token_file;
    EventSink sink;
    SteamAuthMode mode = SteamAuthMode::qr;
    std::string state = "signed_out";
    std::string account;
    std::string password;
    std::string prompt;
    std::string refresh_token;
    std::string access_token;
    std::uint64_t steam_id = 0;
    std::uint64_t access_expiry = 0;
    std::uint64_t client_id = 0;
    std::string request_id;
    std::string challenge_url;
    std::uint32_t guard_type = 0;
    std::chrono::milliseconds poll_interval{5000};
    Clock::time_point next_poll{};
    std::uint64_t sequence = 0;
    std::unique_ptr<SteamCM> cm;
    bool cm_attempted = false;

    static std::uint64_t unix_now() {
        return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    }

    void emit(std::string_view type, Json payload = Json::object()) {
        if (!sink) return;
        payload["type"] = type;
        sink(payload);
    }

    void load_token() {
        std::ifstream file(token_file);
        if (!file) return;
        try {
            Json value; file >> value;
            if (value.value("version", 0) != 1 || value.value("appid", 0) != 730) return;
            steam_id = value.at("steam_id").get<std::uint64_t>();
            refresh_token = value.at("refresh_token").get<std::string>();
            access_token = value.value("access_token", std::string{});
            access_expiry = value.value("access_expires_unix", std::uint64_t{});
            account = value.value("account_name", std::string{});
            if (steam_id && !refresh_token.empty()) state = "token_loaded";
        } catch (...) {
            state = "token_invalid";
        }
    }

    void save_token() {
        if (!steam_id || refresh_token.empty()) throw std::runtime_error("Steam authentication did not return a usable refresh token");
        Json value{{"version", 1}, {"appid", 730}, {"steam_id", steam_id}, {"account_name", account}, {"refresh_token", refresh_token},
                   {"access_token", access_token}, {"access_expires_unix", access_expiry}};
        const auto temporary = token_file.wstring() + L".tmp";
        { std::ofstream file(temporary, std::ios::binary | std::ios::trunc); if (!file) throw std::runtime_error("Cannot create steam-auth.json"); file << value.dump(2) << '\n'; }
        if (!MoveFileExW(temporary.c_str(), token_file.wstring().c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
            DeleteFileW(temporary.c_str()); throw std::runtime_error("Cannot replace steam-auth.json");
        }
        HANDLE token = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) throw std::runtime_error("Cannot inspect the current Windows account for token-file ACL");
        DWORD size = 0;
        GetTokenInformation(token, TokenUser, nullptr, 0, &size);
        std::vector<std::uint8_t> user_buffer(size);
        if (!GetTokenInformation(token, TokenUser, user_buffer.data(), size, &size)) {
            CloseHandle(token); throw std::runtime_error("Cannot inspect the current Windows account for token-file ACL");
        }
        const auto user = reinterpret_cast<TOKEN_USER*>(user_buffer.data());
        EXPLICIT_ACCESSW access{};
        access.grfAccessPermissions = GENERIC_READ | GENERIC_WRITE | DELETE;
        access.grfAccessMode = SET_ACCESS;
        access.grfInheritance = NO_INHERITANCE;
        access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        access.Trustee.TrusteeType = TRUSTEE_IS_USER;
        access.Trustee.ptstrName = reinterpret_cast<LPWSTR>(user->User.Sid);
        PACL acl = nullptr;
        const auto acl_result = SetEntriesInAclW(1, &access, nullptr, &acl);
        CloseHandle(token);
        if (acl_result != ERROR_SUCCESS) throw std::runtime_error("Cannot construct token-file ACL");
        auto name = token_file.wstring();
        const auto security_result = SetNamedSecurityInfoW(name.data(), SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, nullptr, nullptr, acl, nullptr);
        LocalFree(acl);
        if (security_result != ERROR_SUCCESS) throw std::runtime_error("Cannot restrict steam-auth.json to the current Windows account");
    }

    void begin_qr() {
        state = "qr_pending";
        const auto response = http_post("/IAuthenticationService/BeginAuthSessionViaQR/v1/",
            Json{{"device_friendly_name", "headless-csgo"}, {"platform_type", 3},
                 {"device_details", {{"device_friendly_name", "headless-csgo"}, {"platform_type", 3}, {"os_type", 20}}},
                 {"website_id", "Unknown"}});
        client_id = json_u64(response, "client_id");
        request_id = response.value("request_id", std::string{});
        steam_id = json_u64(response, "steamid");
        challenge_url = response.value("challenge_url", std::string{});
        poll_interval = std::chrono::milliseconds(static_cast<int>(std::max(1.0, json_number(response, "interval", 5.0)) * 1000));
        if (!client_id || request_id.empty() || challenge_url.empty()) throw std::runtime_error("Steam did not return a QR challenge");
        next_poll = Clock::now() + poll_interval;
        emit("auth_qr", {{"url", challenge_url}, {"terminal", render_qr(challenge_url)}, {"interval_ms", poll_interval.count()}});
    }

    void begin_password() {
        state = "awaiting_account";
        prompt = "account_name";
        emit("auth_prompt", {{"prompt_id", prompt}, {"kind", "account_name"}});
    }

    void begin_credentials() {
        if (account.empty() || password.empty()) throw std::runtime_error("Steam account name and password are required");
        const auto key = http_post("/IAuthenticationService/GetPasswordRSAPublicKey/v1/", Json{{"account_name", account}});
        const auto encrypted = rsa_encrypt(password, key.value("publickey_mod", std::string{}), key.value("publickey_exp", std::string{}));
        const auto response = http_post("/IAuthenticationService/BeginAuthSessionViaCredentials/v1/",
            Json{{"device_friendly_name", "headless-csgo"}, {"account_name", account},
                 {"encrypted_password", base64(encrypted)}, {"encryption_timestamp", key.value("timestamp", 0ull)},
                 {"remember_login", true}, {"platform_type", 3}, {"persistence", 1}, {"website_id", "Unknown"},
                 {"device_details", {{"device_friendly_name", "headless-csgo"}, {"platform_type", 3}, {"os_type", 20}}}});
        client_id = json_u64(response, "client_id");
        request_id = response.value("request_id", std::string{});
        steam_id = json_u64(response, "steamid", steam_id);
        poll_interval = std::chrono::milliseconds(static_cast<int>(std::max(1.0, json_number(response, "interval", 5.0)) * 1000));
        if (!client_id || request_id.empty()) throw std::runtime_error(response.value("extended_error_message", "Steam rejected the credentials"));
        const auto allowed = response.value("allowed_confirmations", Json::array());
        if (allowed.empty()) throw std::runtime_error("Steam returned no authentication confirmation methods");
        guard_type = allowed.front().value("confirmation_type", 0u);
        state = "guard_pending";
        if (guard_type == 1) { prompt.clear(); next_poll = Clock::now(); return; }
        if (guard_type != 2 && guard_type != 3 && guard_type != 4 && guard_type != 5)
            throw std::runtime_error("Steam returned an unsupported authentication confirmation method");
        prompt = "guard_" + std::to_string(++sequence);
        if (guard_type == 4) emit("auth_prompt", {{"prompt_id", prompt}, {"kind", "mobile_confirmation"}});
        else emit("auth_prompt", {{"prompt_id", prompt}, {"kind", prompt_kind(guard_type)}, {"message", allowed.front().value("associated_message", "")}});
        next_poll = Clock::now();
        clear(password);
    }

    void poll_auth() {
        const auto response = http_post("/IAuthenticationService/PollAuthSessionStatus/v1/", Json{{"client_id", client_id}, {"request_id", request_id}});
        if (response.contains("new_client_id")) client_id = json_u64(response, "new_client_id", client_id);
        const auto refreshed_url = response.value("new_challenge_url", std::string{});
        if (!refreshed_url.empty() && refreshed_url != challenge_url) {
            challenge_url = refreshed_url;
            emit("auth_qr_refresh", {{"url", challenge_url}, {"terminal", render_qr(challenge_url)}, {"interval_ms", poll_interval.count()}});
        }
        if (!response.contains("refresh_token")) { next_poll = Clock::now() + poll_interval; return; }
        refresh_token = response.value("refresh_token", std::string{});
        access_token = response.value("access_token", std::string{});
        account = response.value("account_name", account);
        if (refresh_token.empty() || access_token.empty()) throw std::runtime_error("Steam returned incomplete authentication tokens");
        access_expiry = unix_now() + 86400;
        state = "cm_connecting"; prompt.clear(); request_id.clear(); challenge_url.clear(); client_id = 0;
        ensure_cm();
        if (!steam_id) steam_id = cm->steam_id();
        save_token();
        emit("auth_completed", {{"steam_id", steam_id}});
    }

    void ensure_cm() {
        if (access_token.empty()) throw std::runtime_error("Steam access token is missing; authenticate again");
        if (cm && cm->logged_in()) { state = "authenticated"; return; }
        if (account.empty()) throw std::runtime_error("Steam account name is unavailable; authenticate with password login again");
        cm_attempted = true;
        cm = std::make_unique<SteamCM>();
        try {
            cm->connect(account, access_token, steam_id);
            if (!steam_id) steam_id = cm->steam_id();
            if (!steam_id) throw std::runtime_error("Steam CM did not return an account ID");
            state = "authenticated";
            emit("auth_state", {{"state", state}, {"steam_id", steam_id}});
        } catch (...) {
            cm.reset();
            throw;
        }
    }

    void refresh_access_token() {
        if (refresh_token.empty() || !steam_id) throw std::runtime_error("Steam refresh token is missing; authenticate again");
        const auto response = http_post("/IAuthenticationService/GenerateAccessTokenForApp/v1/",
            Json{{"refresh_token", refresh_token}, {"steamid", steam_id}, {"renewal_type", 1}});
        access_token = response.value("access_token", std::string{});
        const auto rotated = response.value("refresh_token", std::string{});
        if (!rotated.empty()) refresh_token = rotated;
        if (access_token.empty()) throw std::runtime_error("Steam did not return a refreshed access token");
        access_expiry = unix_now() + 86400;
        save_token();
    }

    void start(SteamAuthMode selected) {
        close(); mode = selected;
        if (mode == SteamAuthMode::qr) begin_qr(); else begin_password();
    }

    void submit(std::string id, std::string value) {
        if (id != prompt || value.empty()) throw std::runtime_error("Unknown or empty Steam authentication prompt");
        if (state == "awaiting_account") { account = std::move(value); prompt = "password"; state = "awaiting_password"; emit("auth_prompt", {{"prompt_id", prompt}, {"kind", "password"}}); return; }
        if (state == "awaiting_password") { password = std::move(value); begin_credentials(); return; }
        if (state == "guard_pending" && (guard_type == 2 || guard_type == 3)) {
            const auto response = http_post("/IAuthenticationService/UpdateAuthSessionWithSteamGuardCode/v1/", Json{{"client_id", client_id}, {"steamid", steam_id}, {"code", value}, {"code_type", guard_type}});
            (void)response; prompt.clear(); next_poll = Clock::now(); return;
        }
        throw std::runtime_error("This Steam authentication prompt is completed through mobile approval");
    }

    void poll() {
        if (state == "token_loaded" && !cm_attempted) {
            try {
                if (access_token.empty() || (access_expiry && access_expiry <= unix_now() + 60)) refresh_access_token();
                ensure_cm();
            }
            catch (const std::exception& e) { state = "token_error"; emit("auth_error", {{"message", e.what()}}); }
        }
        if (state == "authenticated" && (!cm || !cm->logged_in())) {
            cm_attempted = false;
            try {
                if (access_token.empty() || (access_expiry && access_expiry <= unix_now() + 60)) refresh_access_token();
                ensure_cm();
            }
            catch (const std::exception& e) { state = "cm_error"; emit("auth_error", {{"message", e.what()}}); }
        }
        if (state == "qr_pending" || state == "guard_pending") {
            if (Clock::now() >= next_poll) poll_auth();
        }
    }

    bool ready() const noexcept { return state == "authenticated" && steam_id != 0 && !access_token.empty() && cm && cm->logged_in(); }

    Json status() const {
        return {{"state", state}, {"steam_id", steam_id}, {"token_file", token_file.string()}, {"qr_url", challenge_url}};
    }

    SteamCredentials acquire_ticket(std::chrono::milliseconds timeout) {
        if (!ready()) throw std::runtime_error("Steam authentication is not ready");
        return cm->issue_ticket(730, timeout);
    }

    void close() noexcept {
        if (cm) cm->close();
        cm.reset(); cm_attempted = false;
        clear(password); clear(access_token); clear(refresh_token); clear(account); request_id.clear(); challenge_url.clear(); prompt.clear();
        client_id = 0; steam_id = 0; access_expiry = 0; state = "signed_out";
    }
};

SteamAuth::SteamAuth(std::filesystem::path token_file) : impl_(std::make_unique<Impl>(std::move(token_file))) {}
SteamAuth::~SteamAuth() = default;
void SteamAuth::set_event_sink(EventSink sink) { impl_->sink = std::move(sink); }
void SteamAuth::start(SteamAuthMode mode) { impl_->start(mode); }
void SteamAuth::submit(std::string prompt_id, std::string value) { impl_->submit(std::move(prompt_id), std::move(value)); }
void SteamAuth::poll() { impl_->poll(); }
bool SteamAuth::ready() const noexcept { return impl_->ready(); }
Json SteamAuth::status() const { return impl_->status(); }
SteamCredentials SteamAuth::acquire_ticket(std::chrono::milliseconds timeout) { return impl_->acquire_ticket(timeout); }
void SteamAuth::close() noexcept { impl_->close(); }

} // namespace hc
