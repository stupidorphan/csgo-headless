#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <steam/steam_api.h>
#include <nlohmann/json.hpp>
#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <string>
#include <thread>

namespace {
struct TicketObserver {
    TicketObserver() : callback(this, &TicketObserver::on_ticket) {}
    void on_ticket(GetAuthSessionTicketResponse_t* response) {
        if (response->m_hAuthTicket == handle) { result = response->m_eResult; received = true; }
    }
    HAuthTicket handle = k_HAuthTicketInvalid;
    EResult result = k_EResultFail;
    bool received{};
    CCallback<TicketObserver, GetAuthSessionTicketResponse_t> callback;
};
void fail(const std::string& error) {
    std::cout << nlohmann::json{{"ok", false}, {"error", error}}.dump() << '\n' << std::flush;
}
}

int main(int argc, char** argv) {
    const auto input = GetStdHandle(STD_INPUT_HANDLE), output = GetStdHandle(STD_OUTPUT_HANDLE);
    if (argc != 2 || std::string(argv[1]) != "--private-pipe" ||
        GetFileType(input) != FILE_TYPE_PIPE || GetFileType(output) != FILE_TYPE_PIPE) return 2;
    SetEnvironmentVariableA("SteamAppId", "730");
    SetEnvironmentVariableA("SteamGameId", "730");
    if (!SteamAPI_Init()) { fail("Steam initialization failed; start Steam and sign in to an account with AppID 730"); return 1; }
    int exit_code = 1;
    {
        TicketObserver observer;
        std::array<unsigned char, 8192> ticket{};
        std::uint32_t ticket_size{};
        if (!SteamUser() || !SteamUtils() || !SteamApps() || SteamUtils()->GetAppID() != 730 ||
            !SteamUser()->BLoggedOn() || !SteamApps()->BIsSubscribedApp(730)) {
            fail("Steam is not logged on to AppID 730");
        } else {
            observer.handle = SteamUser()->GetAuthSessionTicket(ticket.data(), static_cast<int>(ticket.size()), &ticket_size);
            const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(12);
            while (observer.handle != k_HAuthTicketInvalid && !observer.received && std::chrono::steady_clock::now() < deadline) {
                SteamAPI_RunCallbacks();
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
            if (observer.handle == k_HAuthTicketInvalid || !observer.received || observer.result != k_EResultOK || !ticket_size || ticket_size > ticket.size()) {
                fail("Steam rejected the session ticket or did not confirm it before timeout (result " + std::to_string(observer.result) + ")");
            } else {
                constexpr char digits[] = "0123456789abcdef";
                std::string hex;
                hex.reserve(ticket_size * 2);
                for (std::uint32_t i = 0; i < ticket_size; ++i) { hex += digits[ticket[i] >> 4]; hex += digits[ticket[i] & 15]; }
                std::cout << nlohmann::json{{"ok", true}, {"steam_id", SteamUser()->GetSteamID().ConvertToUint64()}, {"ticket_hex", hex}}.dump() << '\n' << std::flush;
                SecureZeroMemory(hex.data(), hex.size());
                exit_code = 0;
                std::string commands;
                while (true) {
                    SteamAPI_RunCallbacks();
                    DWORD available{};
                    if (!PeekNamedPipe(input, nullptr, 0, nullptr, &available, nullptr)) break;
                    if (available) {
                        std::array<char, 64> buffer{};
                        DWORD read{};
                        if (!ReadFile(input, buffer.data(), static_cast<DWORD>((std::min)(static_cast<size_t>(available), buffer.size())), &read, nullptr) || !read) break;
                        commands.append(buffer.data(), read);
                        if (commands.find('\n') != std::string::npos || commands.size() > 256) break;
                    }
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                }
            }
            if (observer.handle != k_HAuthTicketInvalid) SteamUser()->CancelAuthTicket(observer.handle);
        }
        SecureZeroMemory(ticket.data(), ticket.size());
    }
    SteamAPI_Shutdown();
    return exit_code;
}
