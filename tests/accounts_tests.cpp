#include "hc/accounts.hpp"

#include <filesystem>
#include <iostream>
#include <stdexcept>

namespace {
void check(bool condition, const char* message) { if (!condition) throw std::runtime_error(message); }
}

int main() {
    try {
        const auto root = std::filesystem::temp_directory_path() / "headless-csgo-accounts-test";
        std::error_code ec; std::filesystem::remove_all(root, ec); std::filesystem::create_directories(root);
        const auto path = root / "accounts.json";
        hc::AccountRegistry registry(path);
        check(registry.empty(), "new registry should be empty");
        const auto first = registry.create("primary");
        const auto second = registry.create("backup");
        check(first == 1 && second == 2, "account IDs should be stable and sequential");
        check(registry.get(first).token_file != registry.get(second).token_file, "token files must be isolated");
        check(registry.describe(first)[0]["active"].get<bool>(), "active account is reported");
        hc::AccountRegistry reloaded(path);
        check(reloaded.accounts().size() == 2 && reloaded.get(second).label == "backup", "registry survives reload");
        std::filesystem::remove_all(root, ec);
        std::cout << "account registry tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
