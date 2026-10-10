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

std::vector<std::uint8_t> base64_decode(std::string_view input) {
    auto decode_char = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+' || c == '-') return 62;
        if (c == '/' || c == '_') return 63;
        return -1;
    };
    std::vector<std::uint8_t> out;
    out.reserve(input.size() * 3 / 4);
    int val = 0, valb = -8;
    for (char c : input) {
        if (c == '=') break;
        int d = decode_char(c);
        if (d < 0) continue;
        val = (val << 6) | d;
        valb += 6;
        if (valb >= 0) {
            out.push_back(static_cast<std::uint8_t>((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}

} // namespace

std::uint64_t parse_jwt_steam_id(std::string_view jwt) {
    const auto first_dot = jwt.find('.');
    if (first_dot == std::string_view::npos) return 0;
    const auto second_dot = jwt.find('.', first_dot + 1);
    if (second_dot == std::string_view::npos) return 0;
    const auto payload_b64 = jwt.substr(first_dot + 1, second_dot - first_dot - 1);
    const auto decoded = base64_decode(payload_b64);
    try {
        const auto json = Json::parse(std::string_view(reinterpret_cast<const char*>(decoded.data()), decoded.size()));
        return json_u64(json, "sub");
    } catch (...) {
        return 0;
    }
}

namespace {


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

struct ScopedHInternet {
    HINTERNET handle = nullptr;
    ScopedHInternet() = default;
    ScopedHInternet(HINTERNET h) : handle(h) {}
    ~ScopedHInternet() { if (handle) WinHttpCloseHandle(handle); }
    ScopedHInternet(const ScopedHInternet&) = delete;
    ScopedHInternet& operator=(const ScopedHInternet&) = delete;
    ScopedHInternet(ScopedHInternet&& o) noexcept : handle(o.handle) { o.handle = nullptr; }
    ScopedHInternet& operator=(ScopedHInternet&& o) noexcept {
        if (this != &o) {
            if (handle) WinHttpCloseHandle(handle);
            handle = o.handle;
            o.handle = nullptr;
        }
        return *this;
    }
    operator HINTERNET() const noexcept { return handle; }
};

Json http_request(std::wstring_view method, std::string_view path, const Json& params_or_body) {
    std::string full_path(path);
    std::string body_data;
    const wchar_t* headers = nullptr;

    if (method == L"GET") {
        std::string query;
        for (const auto& [k, v] : params_or_body.items()) {
            if (!query.empty()) query.push_back('&');
            query += url_encode(k);
            query.push_back('=');
            if (v.is_string()) {
                query += url_encode(v.get<std::string>());
            } else {
                query += url_encode(v.dump());
            }
        }
        if (!query.empty()) {
            full_path.push_back('?');
            full_path += query;
        }
        headers = L"Accept: application/json\r\n";
    } else {
        body_data = "input_json=" + url_encode(params_or_body.dump());
        headers = L"Content-Type: application/x-www-form-urlencoded\r\nAccept: application/json\r\n";
    }

    ScopedHInternet session = WinHttpOpen(L"headless-csgo/1.0", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                                          WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) throw std::runtime_error("Steam authentication HTTP session failed");

    ScopedHInternet connection = WinHttpConnect(session, L"api.steampowered.com", INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!connection) throw std::runtime_error("Steam authentication HTTP connection failed");

    std::wstring wide_path(full_path.begin(), full_path.end());
    ScopedHInternet request = WinHttpOpenRequest(connection, method.data(), wide_path.c_str(), nullptr,
                                                 WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                                 WINHTTP_FLAG_SECURE);
    if (!request) throw std::runtime_error("Steam authentication HTTP request failed");

    const bool sent = WinHttpSendRequest(request, headers, static_cast<DWORD>(-1L),
                                         body_data.empty() ? WINHTTP_NO_REQUEST_DATA : const_cast<char*>(body_data.data()),
                                         static_cast<DWORD>(body_data.size()),
                                         static_cast<DWORD>(body_data.size()), 0) != FALSE &&
                      WinHttpReceiveResponse(request, nullptr) != FALSE;
    if (!sent) throw std::runtime_error("Steam authentication HTTP exchange failed");

    DWORD status = 0, status_size = sizeof(status);
    WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &status, &status_size, WINHTTP_NO_HEADER_INDEX);

    DWORD eresult = 0;
    wchar_t eresult_buf[32] = {0};
    DWORD eresult_size = sizeof(eresult_buf);
    if (WinHttpQueryHeaders(request, WINHTTP_QUERY_CUSTOM, L"X-eresult", eresult_buf, &eresult_size, WINHTTP_NO_HEADER_INDEX)) {
        try { eresult = static_cast<DWORD>(std::stoul(eresult_buf)); } catch (...) {}
    }

    std::string response;
    for (;;) {
        DWORD available = 0;
        if (!WinHttpQueryDataAvailable(request, &available)) throw std::runtime_error("Steam authentication HTTP read failed");
        if (!available) break;
        std::string chunk(available, '\0'); DWORD read = 0;
        if (!WinHttpReadData(request, chunk.data(), available, &read)) throw std::runtime_error("Steam authentication HTTP read failed");
        response.append(chunk.data(), read);
        if (response.size() > 1024 * 1024) throw std::runtime_error("Steam authentication response exceeds limit");
    }

    if (status != 200) {
        std::string err_msg = "Steam authentication HTTP request was rejected with HTTP " + std::to_string(status);
        if (eresult != 0) {
            err_msg += " (EResult " + std::to_string(eresult) + ")";
        }
        try {
            auto err_json = Json::parse(response);
            if (err_json.contains("response") && err_json["response"].contains("extended_error_message")) {
                err_msg += ": " + err_json["response"]["extended_error_message"].get<std::string>();
            }
        } catch (...) {}
        throw std::runtime_error(err_msg);
    }

    try {
        auto parsed = Json::parse(response);
        auto resp = parsed.value("response", Json::object());
        if (eresult != 0 && !resp.contains("eresult")) {
            resp["eresult"] = eresult;
        }
        return resp;
    } catch (const Json::exception&) {
        throw std::runtime_error("Steam authentication returned malformed JSON");
    }
}

Json http_get(std::string_view path, const Json& params = Json::object()) {
    return http_request(L"GET", path, params);
}

Json http_post(std::string_view path, const Json& body = Json::object()) {
    return http_request(L"POST", path, body);
}

std::vector<std::uint8_t> rsa_encrypt(std::string_view password, std::string_view modulus_hex, std::string_view exponent_hex) {
    auto modulus = hex_decode(modulus_hex), exponent = hex_decode(exponent_hex);
    if (modulus.empty() || exponent.empty() || modulus.size() > 512 || exponent.size() > 8)
        throw std::runtime_error("Steam RSA key dimensions are invalid");

    BCRYPT_ALG_HANDLE alg = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&alg, BCRYPT_RSA_ALGORITHM, nullptr, 0);
    if (status < 0) throw std::runtime_error("Steam RSA provider initialization failed");
    auto close_alg = [&] { BCryptCloseAlgorithmProvider(alg, 0); };

    BCRYPT_RSAKEY_BLOB header{};
    header.Magic = BCRYPT_RSAPUBLIC_MAGIC;
    header.BitLength = static_cast<ULONG>(modulus.size() * 8);
    header.cbPublicExp = static_cast<ULONG>(exponent.size());
    header.cbModulus = static_cast<ULONG>(modulus.size());
    header.cbPrime1 = 0;
    header.cbPrime2 = 0;

    std::vector<std::uint8_t> blob(sizeof(header) + exponent.size() + modulus.size());
    std::memcpy(blob.data(), &header, sizeof(header));
    std::memcpy(blob.data() + sizeof(header), exponent.data(), exponent.size());
    std::memcpy(blob.data() + sizeof(header) + exponent.size(), modulus.data(), modulus.size());

    BCRYPT_KEY_HANDLE key = nullptr;
    status = BCryptImportKeyPair(alg, nullptr, BCRYPT_RSAPUBLIC_BLOB,
                                 &key, blob.data(), static_cast<ULONG>(blob.size()), 0);
    if (status < 0) { close_alg(); throw std::runtime_error("Steam RSA public key import failed"); }
    auto close_key = [&] { BCryptDestroyKey(key); close_alg(); };

    ULONG size = 0;
    status = BCryptEncrypt(key, reinterpret_cast<PUCHAR>(const_cast<char*>(password.data())),
                           static_cast<ULONG>(password.size()), nullptr, nullptr, 0,
                           nullptr, 0, &size, BCRYPT_PAD_PKCS1);
    if (status < 0 || size == 0) { close_key(); throw std::runtime_error("Steam password encryption sizing failed"); }

    std::vector<std::uint8_t> output(size);
    status = BCryptEncrypt(key, reinterpret_cast<PUCHAR>(const_cast<char*>(password.data())),
                           static_cast<ULONG>(password.size()), nullptr, nullptr, 0,
                           output.data(), static_cast<ULONG>(output.size()), &size, BCRYPT_PAD_PKCS1);
    close_key();
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

void restrict_token_file(const std::filesystem::path& path) {
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
    auto name = path.wstring();
    const auto security_result = SetNamedSecurityInfoW(name.data(), SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, nullptr, nullptr, acl, nullptr);
    LocalFree(acl);
    if (security_result != ERROR_SUCCESS) throw std::runtime_error("Cannot restrict steam-auth.json to the current Windows account");
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
    std::vector<std::uint64_t> active_client_ids;
    bool had_remote_interaction = false;
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
            steam_id = value.value("steam_id", std::uint64_t{});
            refresh_token = value.at("refresh_token").get<std::string>();
            access_token = value.value("access_token", std::string{});
            access_expiry = value.value("access_expires_unix", std::uint64_t{});
            account = value.value("account_name", std::string{});
            if (!steam_id && !refresh_token.empty()) steam_id = parse_jwt_steam_id(refresh_token);
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
        try { restrict_token_file(temporary); }
        catch (...) { DeleteFileW(temporary.c_str()); throw; }
        if (!MoveFileExW(temporary.c_str(), token_file.wstring().c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
            DeleteFileW(temporary.c_str()); throw std::runtime_error("Cannot replace steam-auth.json");
        }
    }

    void begin_qr() {
        state = "qr_pending";
        const auto response = http_post("/IAuthenticationService/BeginAuthSessionViaQR/v1/",
            Json{{"device_friendly_name", "headless-csgo"}, {"platform_type", 1},
                 {"device_details", {{"device_friendly_name", "headless-csgo"}, {"platform_type", 1}, {"os_type", 20}, {"gaming_device_type", 1}}},
                 {"website_id", "Client"}});
        client_id = json_u64(response, "client_id");
        active_client_ids = { client_id };
        request_id = response.value("request_id", std::string{});
        steam_id = json_u64(response, "steamid");
        challenge_url = response.value("challenge_url", std::string{});
        poll_interval = std::chrono::milliseconds(static_cast<int>(std::max(1.0, json_number(response, "interval", 5.0)) * 1000));
        if (!client_id || request_id.empty() || challenge_url.empty()) throw std::runtime_error("Steam did not return a QR challenge");
        next_poll = Clock::now() + poll_interval;
        emit("auth_state", {{"state", state}, {"interval_ms", poll_interval.count()}});
        emit("auth_qr", {{"url", challenge_url}, {"terminal", render_qr(challenge_url)}, {"terminal_ascii", render_qr_ascii(challenge_url)}, {"terminal_squares", render_qr_squares(challenge_url)}, {"interval_ms", poll_interval.count()}});
    }

    void begin_password() {
        state = "awaiting_account";
        prompt = "account_name";
        emit("auth_prompt", {{"prompt_id", prompt}, {"kind", "account_name"}});
    }

    void begin_credentials() {
        if (account.empty() || password.empty()) throw std::runtime_error("Steam account name and password are required");
        try {
            const auto key = http_get("/IAuthenticationService/GetPasswordRSAPublicKey/v1/", Json{{"account_name", account}});
            const auto encrypted = rsa_encrypt(password, key.value("publickey_mod", std::string{}), key.value("publickey_exp", std::string{}));
            const auto response = http_post("/IAuthenticationService/BeginAuthSessionViaCredentials/v1/",
                Json{{"device_friendly_name", "headless-csgo"}, {"account_name", account},
                     {"encrypted_password", base64(encrypted)}, {"encryption_timestamp", json_u64(key, "timestamp")},
                     {"remember_login", true}, {"platform_type", 1}, {"persistence", 1}, {"website_id", "Client"},
                     {"device_details", {{"device_friendly_name", "headless-csgo"}, {"platform_type", 1}, {"os_type", 20}, {"gaming_device_type", 1}}}});
            client_id = json_u64(response, "client_id");
            request_id = response.value("request_id", std::string{});
            steam_id = json_u64(response, "steamid", steam_id);
            poll_interval = std::chrono::milliseconds(static_cast<int>(std::max(1.0, json_number(response, "interval", 5.0)) * 1000));
            if (!client_id || request_id.empty()) {
                std::string err = response.value("extended_error_message", std::string{});
                if (err.empty()) {
                    const auto eres = json_u64(response, "eresult", 0);
                    if (eres == 5) err = "Steam rejected credentials: invalid account name or password (EResult 5)";
                    else if (eres == 84) err = "Steam rate limit exceeded; please wait before retrying (EResult 84)";
                    else if (eres != 0) err = "Steam rejected credentials with EResult " + std::to_string(eres);
                    else err = "Steam rejected the credentials";
                }
                throw std::runtime_error(err);
            }
            const auto allowed = response.value("allowed_confirmations", Json::array());
            if (allowed.empty()) throw std::runtime_error("Steam returned no authentication confirmation methods");

            bool is_email = false;
            std::string msg;
            for (const auto& conf : allowed) {
                const auto t = conf.value("confirmation_type", 0u);
                if (t == 2 || t == 5) {
                    is_email = true;
                    msg = conf.value("associated_message", "");
                    break;
                }
            }
            if (!is_email) {
                for (const auto& conf : allowed) {
                    const auto m = conf.value("associated_message", "");
                    if (!m.empty()) { msg = m; break; }
                }
            }

            guard_type = is_email ? 2 : 3;
            state = "guard_pending";
            clear(password);
            prompt = "guard_" + std::to_string(++sequence);
            emit("auth_prompt", {{"prompt_id", prompt}, {"kind", is_email ? "email_code" : "totp"}, {"message", msg}});
            next_poll = Clock::now();
        } catch (...) {
            clear(password);
            throw;
        }
    }

    void poll_auth() {
        // Keep retries bounded even when Steam is temporarily unavailable or
        // returns a transient HTTP error. The outer session loop runs at 1 ms.
        next_poll = Clock::now() + poll_interval;
        auto response = http_post("/IAuthenticationService/PollAuthSessionStatus/v1/", Json{{"client_id", client_id}, {"request_id", request_id}});
        if (response.contains("new_client_id")) {
            const auto ncid = json_u64(response, "new_client_id", client_id);
            if (ncid && ncid != client_id) {
                client_id = ncid;
                active_client_ids.push_back(ncid);
                if (active_client_ids.size() > 4) active_client_ids.erase(active_client_ids.begin());
            }
        }
        had_remote_interaction = response.value("had_remote_interaction", false);
        emit("auth_state", {{"state", state}, {"had_remote_interaction", had_remote_interaction}, {"interval_ms", poll_interval.count()}});
        const auto refreshed_url = response.value("new_challenge_url", std::string{});
        if (!refreshed_url.empty() && refreshed_url != challenge_url) {
            challenge_url = refreshed_url;
            emit("auth_qr_refresh", {{"url", challenge_url}, {"terminal", render_qr(challenge_url)}, {"terminal_ascii", render_qr_ascii(challenge_url)}, {"terminal_squares", render_qr_squares(challenge_url)}, {"interval_ms", poll_interval.count()}});
        }
        // If the primary client_id hasn't confirmed yet, check recently refreshed client_ids
        if (!response.contains("refresh_token") && active_client_ids.size() > 1) {
            for (auto it = active_client_ids.rbegin() + 1; it != active_client_ids.rend(); ++it) {
                if (*it == client_id) continue;
                try {
                    const auto alt_response = http_post("/IAuthenticationService/PollAuthSessionStatus/v1/", Json{{"client_id", *it}, {"request_id", request_id}});
                    if (alt_response.value("had_remote_interaction", false)) had_remote_interaction = true;
                    if (alt_response.contains("refresh_token")) {
                        response = alt_response;
                        break;
                    }
                } catch (...) {}
            }
        }
        if (!response.contains("refresh_token")) return;
        refresh_token = response.value("refresh_token", std::string{});
        access_token = response.value("access_token", std::string{});
        account = response.value("account_name", account);
        if (refresh_token.empty()) throw std::runtime_error("Steam returned incomplete authentication tokens");
        if (!steam_id) steam_id = parse_jwt_steam_id(refresh_token);
        if (access_token.empty()) {
            refresh_access_token();
        }
        if (refresh_token.empty() || access_token.empty()) throw std::runtime_error("Steam returned incomplete authentication tokens");
        access_expiry = unix_now() + 86400;
        state = "cm_connecting"; prompt.clear(); request_id.clear(); challenge_url.clear(); client_id = 0; active_client_ids.clear();
        emit("auth_state", {{"state", state}, {"had_remote_interaction", had_remote_interaction}});
        establish_cm();
    }

    void ensure_cm() {
        // Steam CM logon uses the refresh token returned by the modern auth
        // service.  The subordinate access token is for Web API/app scopes;
        // sending it to ClientLogon is rejected as EResult 5 (InvalidPassword).
        if (refresh_token.empty()) throw std::runtime_error("Steam refresh token is missing; authenticate again");
        if (cm && cm->logged_in()) { state = "authenticated"; return; }
        if (!steam_id && !refresh_token.empty()) steam_id = parse_jwt_steam_id(refresh_token);
        if (account.empty() && !steam_id) throw std::runtime_error("Steam account name or ID is unavailable; authenticate with password login again");
        cm_attempted = true;
        cm = std::make_unique<SteamCM>();
        try {
            cm->connect(account, refresh_token, steam_id);
            if (!steam_id) steam_id = cm->steam_id();
            if (!steam_id) throw std::runtime_error("Steam CM did not return an account ID");
            state = "authenticated";
            emit("auth_state", {{"state", state}, {"steam_id", steam_id}});
        } catch (...) {
            cm.reset();
            throw;
        }
    }

    void establish_cm() {
        try {
            ensure_cm();
            if (!steam_id) throw std::runtime_error("Steam CM did not return an account ID");
            save_token();
            emit("auth_completed", {{"steam_id", steam_id}});
        } catch (const std::exception& error) {
            cm_attempted = false;
            state = "cm_connecting";
            next_poll = Clock::now() + poll_interval;
            emit("auth_error", {{"message", error.what()}, {"retry_in_ms", poll_interval.count()}});
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

    void start(SteamAuthMode selected, std::string initial_account = {}, std::string initial_password = {}) {
        close(); mode = selected;
        if (mode == SteamAuthMode::qr) {
            begin_qr();
        } else {
            if (!initial_account.empty()) account = std::move(initial_account);
            if (!initial_password.empty()) password = std::move(initial_password);
            if (!account.empty() && !password.empty()) {
                begin_credentials();
            } else if (!account.empty()) {
                prompt = "password"; state = "awaiting_password";
                emit("auth_prompt", {{"prompt_id", prompt}, {"kind", "password"}});
            } else {
                begin_password();
            }
        }
    }

    void import_token(std::string token_or_path, std::string account_name = {}) {
        close();
        std::error_code ec;
        if (std::filesystem::exists(token_or_path, ec)) {
            std::ifstream file(token_or_path);
            if (!file) throw std::runtime_error("Cannot open specified token file to import");
            Json val; file >> val;
            refresh_token = val.value("refresh_token", std::string{});
            account = val.value("account_name", account_name);
            steam_id = val.value("steam_id", std::uint64_t{});
        } else {
            refresh_token = std::move(token_or_path);
            account = std::move(account_name);
        }
        if (refresh_token.empty()) throw std::runtime_error("Import token cannot be empty");
        if (!steam_id) steam_id = parse_jwt_steam_id(refresh_token);
        if (!steam_id) throw std::runtime_error("Cannot extract SteamID from the supplied refresh token");
        state = "cm_connecting";
        emit("auth_state", {{"state", state}});
        refresh_access_token();
        establish_cm();
    }

    void submit(std::string id, std::string value) {
        if (id != prompt || value.empty()) throw std::runtime_error("Unknown or empty Steam authentication prompt");
        if (state == "awaiting_account") { account = std::move(value); prompt = "password"; state = "awaiting_password"; emit("auth_prompt", {{"prompt_id", prompt}, {"kind", "password"}}); return; }
        if (state == "awaiting_password") { password = std::move(value); begin_credentials(); return; }
        if (state == "guard_pending") {
            const auto code_type = (guard_type == 2) ? 2 : 3;
            try {
                const auto response = http_post("/IAuthenticationService/UpdateAuthSessionWithSteamGuardCode/v1/",
                    Json{{"client_id", client_id}, {"steamid", steam_id}, {"code", value}, {"code_type", code_type}});
                (void)response;
                prompt.clear();
                next_poll = Clock::now();
                return;
            } catch (const std::exception& e) {
                prompt = "guard_" + std::to_string(++sequence);
                emit("auth_prompt", {{"prompt_id", prompt}, {"kind", (code_type == 2 ? "email_code" : "totp")}, {"message", std::string("Invalid Steam Guard code (") + e.what() + ")" }});
                throw;
            }
        }
        throw std::runtime_error("Unexpected Steam authentication prompt state");
    }

    void poll() {
        if (state == "token_loaded" && !cm_attempted) {
            try {
                if (access_token.empty() || (access_expiry && access_expiry <= unix_now() + 60)) refresh_access_token();
                ensure_cm();
            }
            catch (const std::exception& e) { state = "cm_connecting"; cm_attempted = false; next_poll = Clock::now() + poll_interval; emit("auth_error", {{"message", e.what()}, {"retry_in_ms", poll_interval.count()}}); }
        }
        if (state == "cm_connecting" && !ready() && Clock::now() >= next_poll) establish_cm();
        if (state == "authenticated" && (!cm || !cm->logged_in())) {
            cm_attempted = false;
            try {
                if (access_token.empty() || (access_expiry && access_expiry <= unix_now() + 60)) refresh_access_token();
                ensure_cm();
            }
            catch (const std::exception& e) { state = "cm_connecting"; next_poll = Clock::now() + poll_interval; emit("auth_error", {{"message", e.what()}, {"retry_in_ms", poll_interval.count()}}); }
        }
        if (state == "qr_pending" || state == "guard_pending") {
            if (Clock::now() >= next_poll) poll_auth();
        }
    }

    bool ready() const noexcept { return state == "authenticated" && steam_id != 0 && !access_token.empty() && cm && cm->logged_in(); }

    Json status() const {
        return {{"state", state}, {"steam_id", steam_id}, {"token_file", token_file.string()}, {"qr_url", challenge_url}, {"had_remote_interaction", had_remote_interaction}};
    }

    SteamCredentials acquire_ticket(std::chrono::milliseconds timeout) {
        if (!ready()) throw std::runtime_error("Steam authentication is not ready");
        return cm->issue_ticket(730, timeout);
    }

    void close() noexcept {
        if (cm) cm->close();
        cm.reset(); cm_attempted = false;
        clear(password); clear(access_token); clear(refresh_token); clear(account); request_id.clear(); challenge_url.clear(); prompt.clear();
        client_id = 0; active_client_ids.clear(); steam_id = 0; access_expiry = 0; had_remote_interaction = false; state = "signed_out";
    }
};

SteamAuth::SteamAuth(std::filesystem::path token_file) : impl_(std::make_unique<Impl>(std::move(token_file))) {}
SteamAuth::~SteamAuth() = default;
void SteamAuth::set_event_sink(EventSink sink) { impl_->sink = std::move(sink); }
void SteamAuth::start(SteamAuthMode mode, std::string initial_account, std::string initial_password) {
    impl_->start(mode, std::move(initial_account), std::move(initial_password));
}
void SteamAuth::import_token(std::string token_or_path, std::string account_name) {
    impl_->import_token(std::move(token_or_path), std::move(account_name));
}
void SteamAuth::submit(std::string prompt_id, std::string value) { impl_->submit(std::move(prompt_id), std::move(value)); }
void SteamAuth::poll() { impl_->poll(); }
bool SteamAuth::ready() const noexcept { return impl_->ready(); }
Json SteamAuth::status() const { return impl_->status(); }
SteamCredentials SteamAuth::acquire_ticket(std::chrono::milliseconds timeout) { return impl_->acquire_ticket(timeout); }
void SteamAuth::close() noexcept { impl_->close(); }

} // namespace hc
