#include "hc/auth.hpp"
#include "hc/qr.hpp"
#include "hc/tinf.h"

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
    const auto squares = hc::render_qr_squares("steam://challenge/0123456789");
    assert(squares.find("\xE2\xAC\x9C") != std::string::npos);
    auth.close();
    assert(auth.status().at("state") == "signed_out");
    std::error_code error;
    std::filesystem::remove(path, error);

    // Verify gzip decompression
    {
        const unsigned char gz[] = {
            0x1f, 0x8b, 0x08, 0x00, 0xae, 0x5e, 0xc9, 0x6a, 0x02, 0xff,
            0xf3, 0x48, 0xcd, 0xc9, 0xc9, 0x57, 0x08, 0xcf, 0x2f, 0xca,
            0x49, 0x51, 0x04, 0x00, 0xa3, 0x1c, 0x29, 0x1c, 0x0c, 0x00,
            0x00, 0x00
        };
        unsigned int dest_len = 100;
        std::vector<unsigned char> dest(dest_len);
        int res = tinf_gzip_uncompress(dest.data(), &dest_len, gz, sizeof(gz));
        assert(res == TINF_OK);
        assert(dest_len == 12);
        std::string text(dest.begin(), dest.begin() + dest_len);
        assert(text == "Hello World!");
    }

    // Verify JWT SteamID parsing
    {
        const std::string jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI3NjU2MTE5ODAwMDAwMDAwMSIsImlzcyI6InN0ZWFtIn0.sig";
        const auto id = hc::parse_jwt_steam_id(jwt);
        assert(id == 76561198000000001ULL);
        assert(hc::parse_jwt_steam_id("invalid-jwt") == 0);
    }
}
