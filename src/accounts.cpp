#include <windows.h>

#include "hc/accounts.hpp"

#include <algorithm>
#include <fstream>
#include <stdexcept>

namespace hc {
namespace {

std::filesystem::path executable_directory() {
    std::vector<wchar_t> buffer(32768);
    const auto size = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
    if (!size || size == buffer.size()) throw std::runtime_error("Cannot locate client executable");
    return std::filesystem::path(std::wstring(buffer.data(), size)).parent_path();
}

std::string clean_label(std::string label, std::uint32_t id) {
    if (label.empty()) label = "account-" + std::to_string(id);
    if (label.size() > 64) throw std::runtime_error("Account label must be at most 64 bytes");
    if (std::any_of(label.begin(), label.end(), [](unsigned char c) { return c < 32 || c == '\\' || c == '/' || c == '"'; }))
        throw std::runtime_error("Account label contains an unsupported character");
    return label;
}

} // namespace

std::filesystem::path default_accounts_path() { return executable_directory() / L"steam-accounts.json"; }

AccountRegistry::AccountRegistry(std::filesystem::path path)
    : path_(path.empty() ? default_accounts_path() : std::move(path)) {
    load();
}

bool AccountRegistry::contains(std::uint32_t id) const noexcept {
    return std::any_of(accounts_.begin(), accounts_.end(), [id](const auto& account) { return account.id == id; });
}

const AccountRecord& AccountRegistry::get(std::uint32_t id) const {
    const auto it = std::find_if(accounts_.begin(), accounts_.end(), [id](const auto& account) { return account.id == id; });
    if (it == accounts_.end()) throw std::runtime_error("Unknown account id: " + std::to_string(id));
    return *it;
}

AccountRecord& AccountRegistry::get(std::uint32_t id) {
    const auto it = std::find_if(accounts_.begin(), accounts_.end(), [id](const auto& account) { return account.id == id; });
    if (it == accounts_.end()) throw std::runtime_error("Unknown account id: " + std::to_string(id));
    return *it;
}

std::uint32_t AccountRegistry::create(std::string label) {
    while (contains(next_id_)) ++next_id_;
    const auto id = next_id_++;
    accounts_.push_back({id, clean_label(std::move(label), id), path_.parent_path() / (L"steam-auth-account-" + std::to_wstring(id) + L".json")});
    save();
    return id;
}

Json AccountRegistry::describe(std::uint32_t active_id) const {
    Json result = Json::array();
    for (const auto& account : accounts_) {
        Json item{{"id", account.id}, {"label", account.label}, {"token_file", account.token_file.string()},
                  {"active", account.id == active_id}, {"state", "signed_out"}};
        std::ifstream token(account.token_file, std::ios::binary);
        if (token) {
            try {
                Json value; token >> value;
                const auto steam_id = value.value("steam_id", std::uint64_t{});
                const auto refresh = value.value("refresh_token", std::string{});
                if (steam_id) item["steam_id"] = steam_id;
                if (steam_id && !refresh.empty()) item["state"] = "token_available";
                else if (!value.empty()) item["state"] = "token_invalid";
            } catch (...) {
                item["state"] = "token_invalid";
            }
        }
        result.push_back(std::move(item));
    }
    return result;
}

void AccountRegistry::load() {
    accounts_.clear();
    next_id_ = 1;
    std::ifstream file(path_, std::ios::binary);
    if (!file) return;
    try {
        Json root; file >> root;
        if (root.value("version", 0) != 1 || !root.value("accounts", Json::array()).is_array())
            throw std::runtime_error("unsupported version");
        next_id_ = root.value("next_id", 1u);
        for (const auto& value : root.at("accounts")) {
            AccountRecord account;
            account.id = value.at("id").get<std::uint32_t>();
            account.label = clean_label(value.value("label", std::string{}), account.id);
            const auto token = value.value("token_file", std::string{});
            account.token_file = token.empty() ? path_.parent_path() / (L"steam-auth-account-" + std::to_wstring(account.id) + L".json") : std::filesystem::path(token);
            if (account.token_file.is_relative()) account.token_file = path_.parent_path() / account.token_file;
            if (account.id == 0 || contains(account.id)) throw std::runtime_error("duplicate account id");
            accounts_.push_back(std::move(account));
            next_id_ = std::max(next_id_, accounts_.back().id + 1);
        }
    } catch (const std::exception& error) {
        throw std::runtime_error("Account registry is invalid: " + std::string(error.what()));
    }
}

void AccountRegistry::save() const {
    const auto parent = path_.parent_path();
    if (!parent.empty()) std::filesystem::create_directories(parent);
    const auto base = parent.empty() ? std::filesystem::current_path() : parent;
    Json root{{"version", 1}, {"next_id", next_id_}, {"accounts", Json::array()}};
    for (const auto& account : accounts_) {
        auto token = account.token_file;
        std::error_code ec;
        auto relative = std::filesystem::relative(token, base, ec);
        if (!ec && !relative.empty()) token = relative;
        root["accounts"].push_back({{"id", account.id}, {"label", account.label}, {"token_file", token.string()}});
    }
    const auto temporary = path_.wstring() + L".tmp";
    { std::ofstream file(temporary, std::ios::binary | std::ios::trunc); if (!file) throw std::runtime_error("Cannot create account registry"); file << root.dump(2) << '\n'; }
    if (!MoveFileExW(temporary.c_str(), path_.wstring().c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DeleteFileW(temporary.c_str());
        throw std::runtime_error("Cannot replace account registry");
    }
}

} // namespace hc
