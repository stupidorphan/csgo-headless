// Offline x86 auditor positive control. It opens only the supplied fixture file.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <cstddef>
#include <string>

static_assert(sizeof(void*) == 4, "Auditor fixture must be built as x86.");
static_assert(offsetof(OBJECT_ATTRIBUTES, ObjectName) == 8);

bool open_counted_native_path(const wchar_t* path) {
    using Open = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
                                 PIO_STATUS_BLOCK, ULONG, ULONG);
    const auto open = reinterpret_cast<Open>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtOpenFile"));
    if (!open) return false;
    std::wstring name = L"\\??\\" + std::wstring(path);
    const auto length = static_cast<USHORT>(name.size() * sizeof(wchar_t));
    // The suffix lies outside Length. Correct %msu decoding must exclude it.
    name += L" SENTINEL_OUTSIDE_UNICODE_STRING_LENGTH";
    UNICODE_STRING unicode{length, static_cast<USHORT>((name.size() + 1) * sizeof(wchar_t)), name.data()};
    OBJECT_ATTRIBUTES attributes{sizeof(attributes), nullptr, &unicode, 0, nullptr, nullptr};
    IO_STATUS_BLOCK status{};
    HANDLE file{};
    const auto result = open(&file, GENERIC_READ | SYNCHRONIZE, &attributes, &status,
                             FILE_SHARE_READ, 0x20 | 0x40);
    if (result < 0) return false;
    char byte{};
    DWORD read{};
    const bool ok = ReadFile(file, &byte, 1, &read, nullptr) != FALSE && read == 1;
    CloseHandle(file);
    return ok;
}

int wmain(int argc, wchar_t** argv) {
    if (argc < 2 || argc > 3) return 2;
    HANDLE file = CreateFileW(argv[1], GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (file == INVALID_HANDLE_VALUE) return 3;
    char byte{};
    DWORD read{};
    const bool ok = ReadFile(file, &byte, 1, &read, nullptr) != FALSE && read == 1;
    CloseHandle(file);
    if (!ok) return 4;
    if (!open_counted_native_path(argv[1])) return 7;
    if (argc == 3) return 0;
    wchar_t executable[32768]{};
    if (!GetModuleFileNameW(nullptr, executable, 32768)) return 5;
    std::wstring command = L"\"" + std::wstring(executable) + L"\" \"" + argv[1] + L"\" --child";
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(executable, command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                        nullptr, nullptr, &startup, &process)) return 6;
    WaitForSingleObject(process.hProcess, 10000);
    DWORD code{};
    GetExitCodeProcess(process.hProcess, &code);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return static_cast<int>(code);
}
