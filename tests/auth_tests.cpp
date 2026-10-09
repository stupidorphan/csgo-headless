#include "hc/auth.hpp"
#include "hc/qr.hpp"

#include <cassert>
#include <filesystem>
#include <fstream>
#include <string>

int main() {
    const auto path = std::filesystem::temp_directory_path() / "headless-csgo-auth-test.json";
    {
        std::ofstream file(path, std::ios::trunc);
        file << "{ this is not valid json }\n";
    }
    hc::SteamAuth auth(path);
    assert(auth.status().at("state") == "token_invalid");
    const auto qr = hc::render_qr("steam://challenge/0123456789");
    assert(qr.find("\xE2\x96\x88") != std::string::npos);
    assert(qr.find('\n') != std::string::npos);
    const auto ascii = hc::render_qr_ascii("steam://challenge/0123456789");
    assert(ascii.find("##") != std::string::npos);
    assert(ascii.find('\xE2') == std::string::npos);
    auth.close();
    assert(auth.status().at("state") == "signed_out");
    std::error_code error;
    std::filesystem::remove(path, error);
}
