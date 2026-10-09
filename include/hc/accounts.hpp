#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace hc {

using Json = nlohmann::json;

struct AccountRecord {
    std::uint32_t id{};
    std::string label;
    std::filesystem::path token_file;
};

// Stores account labels and per-account token-file locations. Secrets remain
// in the token files owned by SteamAuth and are never written to this index.
class AccountRegistry {
public:
    explicit AccountRegistry(std::filesystem::path path);

    const std::filesystem::path& path() const noexcept { return path_; }
    const std::vector<AccountRecord>& accounts() const noexcept { return accounts_; }
    bool empty() const noexcept { return accounts_.empty(); }
    bool contains(std::uint32_t id) const noexcept;
    const AccountRecord& get(std::uint32_t id) const;
    AccountRecord& get(std::uint32_t id);
    std::uint32_t create(std::string label = {});
    Json describe(std::uint32_t active_id = 0) const;

private:
    std::filesystem::path path_;
    std::vector<AccountRecord> accounts_;
    std::uint32_t next_id_ = 1;

    void load();
    void save() const;
};

std::filesystem::path default_accounts_path();

} // namespace hc
