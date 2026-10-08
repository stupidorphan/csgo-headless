#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include "hc/auth.hpp"
#include <nlohmann/json.hpp>
#include <algorithm>
#include <array>
#include <stdexcept>
#include <string>
#include <thread>

namespace hc {
namespace {
void release(HANDLE& handle) noexcept {
    if (handle && handle != INVALID_HANDLE_VALUE) CloseHandle(handle);
    handle = nullptr;
}
std::filesystem::path executable_directory() {
    std::vector<wchar_t> path(32768);
    const auto size = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    if (!size || size == path.size()) throw std::runtime_error("Cannot locate authentication helper");
    return std::filesystem::path(std::wstring(path.data(), size)).parent_path();
}
}

struct SteamAuth::Impl {
    explicit Impl(std::filesystem::path path) : helper(std::move(path)) {}
    std::filesystem::path helper;
    HANDLE process{}, to_child{}, from_child{};
};

SteamAuth::SteamAuth(std::filesystem::path helper) : impl_(std::make_unique<Impl>(std::move(helper))) {}
SteamAuth::~SteamAuth() { close(); }

void SteamAuth::close() noexcept {
    if (impl_->to_child) {
        constexpr char command[] = "close\n";
        DWORD written{};
        WriteFile(impl_->to_child, command, sizeof(command) - 1, &written, nullptr);
    }
    release(impl_->to_child);
    release(impl_->from_child);
    if (impl_->process) {
        // The helper cancels the ticket before exiting, including on stdin EOF.
        if (WaitForSingleObject(impl_->process, 3000) == WAIT_TIMEOUT) {
            TerminateProcess(impl_->process, 1);
            WaitForSingleObject(impl_->process, 1000);
        }
        release(impl_->process);
    }
}

SteamCredentials SteamAuth::acquire(std::chrono::milliseconds timeout) {
    close();
    if (timeout <= std::chrono::milliseconds::zero()) throw std::runtime_error("Invalid Steam authentication timeout");
    const auto helper = impl_->helper.empty() ? executable_directory() / L"steam_auth_helper.exe" : impl_->helper;
    if (!std::filesystem::is_regular_file(helper)) throw std::runtime_error("Steam authentication helper is missing");

    SECURITY_ATTRIBUTES security{sizeof(security), nullptr, TRUE};
    HANDLE child_read{}, child_write{}, null_error{};
    auto cleanup = [&] { release(child_read); release(child_write); release(null_error); };
    if (!CreatePipe(&child_read, &impl_->to_child, &security, 0) ||
        !CreatePipe(&impl_->from_child, &child_write, &security, 0)) {
        cleanup(); close(); throw std::runtime_error("Cannot create private Steam authentication pipes");
    }
    if (!SetHandleInformation(impl_->to_child, HANDLE_FLAG_INHERIT, 0) ||
        !SetHandleInformation(impl_->from_child, HANDLE_FLAG_INHERIT, 0)) {
        cleanup(); close(); throw std::runtime_error("Cannot isolate Steam authentication pipes");
    }
    null_error = CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &security, OPEN_EXISTING, 0, nullptr);
    if (null_error == INVALID_HANDLE_VALUE) { cleanup(); close(); throw std::runtime_error("Cannot isolate Steam authentication diagnostics"); }

    SIZE_T attribute_size{};
    InitializeProcThreadAttributeList(nullptr, 1, 0, &attribute_size);
    std::vector<std::uint8_t> attribute_memory(attribute_size);
    auto* attributes = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attribute_memory.data());
    if (!InitializeProcThreadAttributeList(attributes, 1, 0, &attribute_size)) {
        cleanup(); close(); throw std::runtime_error("Cannot initialize Steam helper handle isolation");
    }
    std::array<HANDLE, 3> handles{child_read, child_write, null_error};
    if (!UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, handles.data(), sizeof(handles), nullptr, nullptr)) {
        DeleteProcThreadAttributeList(attributes); cleanup(); close();
        throw std::runtime_error("Cannot isolate Steam helper inherited handles");
    }
    STARTUPINFOEXW startup{};
    startup.StartupInfo.cb = sizeof(startup);
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = child_read;
    startup.StartupInfo.hStdOutput = child_write;
    startup.StartupInfo.hStdError = null_error;
    startup.lpAttributeList = attributes;
    PROCESS_INFORMATION process{};
    std::wstring command = L"\"" + helper.wstring() + L"\" --private-pipe";
    const auto directory = helper.parent_path().wstring();
    const bool started = CreateProcessW(helper.c_str(), command.data(), nullptr, nullptr, TRUE,
        CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT, nullptr,
        directory.empty() ? nullptr : directory.c_str(), &startup.StartupInfo, &process) != FALSE;
    DeleteProcThreadAttributeList(attributes);
    cleanup();
    if (!started) { close(); throw std::runtime_error("Cannot launch Steam authentication helper"); }
    impl_->process = process.hProcess;
    CloseHandle(process.hThread);

    try {
        std::string response;
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        while (std::chrono::steady_clock::now() < deadline) {
            DWORD available{};
            if (!PeekNamedPipe(impl_->from_child, nullptr, 0, nullptr, &available, nullptr))
                throw std::runtime_error("Steam authentication helper closed its pipe");
            if (available) {
                std::array<char, 2048> buffer{};
                DWORD read{};
                if (!ReadFile(impl_->from_child, buffer.data(), static_cast<DWORD>((std::min)(buffer.size(), static_cast<size_t>(available))), &read, nullptr))
                    throw std::runtime_error("Cannot read Steam authentication response");
                response.append(buffer.data(), read);
                if (response.size() > 65536) throw std::runtime_error("Oversized Steam authentication response");
                if (response.find('\n') != std::string::npos) {
                    auto result = nlohmann::json::parse(response.substr(0, response.find('\n')));
                    if (!result.value("ok", false)) throw std::runtime_error(result.value("error", "Steam authentication failed"));
                    SteamCredentials credentials;
                    credentials.steam_id = result.at("steam_id").get<std::uint64_t>();
                    const auto ticket = result.at("ticket_hex").get<std::string>();
                    if (!credentials.steam_id || ticket.empty() || (ticket.size() & 1) || ticket.size() > 16384)
                        throw std::runtime_error("Invalid Steam authentication credentials");
                    const auto nibble = [](char c) -> unsigned {
                        if (c >= '0' && c <= '9') return c - '0';
                        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                        throw std::runtime_error("Invalid Steam ticket encoding");
                    };
                    credentials.ticket.reserve(ticket.size() / 2);
                    for (size_t i = 0; i < ticket.size(); i += 2)
                        credentials.ticket.push_back(static_cast<std::uint8_t>(nibble(ticket[i]) * 16 + nibble(ticket[i + 1])));
                    SecureZeroMemory(response.data(), response.size());
                    return credentials;
                }
            }
            if (WaitForSingleObject(impl_->process, 0) == WAIT_OBJECT_0 && !available)
                throw std::runtime_error("Steam authentication helper exited before returning credentials");
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        throw std::runtime_error("Steam authentication timed out; sign in to Steam with an account that owns AppID 730");
    } catch (const nlohmann::json::exception&) {
        close(); throw std::runtime_error("Invalid private Steam authentication response");
    } catch (...) { close(); throw; }
}
} // namespace hc
