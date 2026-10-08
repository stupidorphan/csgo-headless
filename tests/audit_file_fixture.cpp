// Offline x86 auditor positive control. It opens only the supplied fixture file.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <cstddef>
#include <filesystem>
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

bool open_relative_native_path(const wchar_t* path) {
    using Open = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
                                 PIO_STATUS_BLOCK, ULONG, ULONG);
    using Create = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
                                   PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
    const auto ntdll = GetModuleHandleW(L"ntdll.dll");
    const auto open = reinterpret_cast<Open>(GetProcAddress(ntdll, "NtOpenFile"));
    const auto create = reinterpret_cast<Create>(GetProcAddress(ntdll, "NtCreateFile"));
    if (!open || !create) return false;
    const auto directory = std::filesystem::path(path).parent_path();
    HANDLE root = CreateFileW(directory.c_str(), GENERIC_READ | SYNCHRONIZE,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                              OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (root == INVALID_HANDLE_VALUE) return false;
    std::wstring name = std::filesystem::path(path).filename();
    UNICODE_STRING unicode{static_cast<USHORT>(name.size() * sizeof(wchar_t)),
                           static_cast<USHORT>((name.size() + 1) * sizeof(wchar_t)), name.data()};
    OBJECT_ATTRIBUTES attributes{sizeof(attributes), root, &unicode, 0, nullptr, nullptr};
    IO_STATUS_BLOCK status{};
    HANDLE file{};
    bool ok = open(&file, GENERIC_READ | SYNCHRONIZE, &attributes, &status, FILE_SHARE_READ, 0x20 | 0x40) >= 0;
    if (ok) CloseHandle(file);
    ok = ok && create(&file, GENERIC_READ | SYNCHRONIZE, &attributes, &status, nullptr,
                       0, FILE_SHARE_READ, 1, 0x20 | 0x40, nullptr, 0) >= 0;
    if (ok) CloseHandle(file);
    unicode.Length = 0;  // Reopen the directory using an empty relative name.
    ok = ok && open(&file, GENERIC_READ | SYNCHRONIZE, &attributes, &status,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 0x20 | 1) >= 0;
    if (ok) CloseHandle(file);
    CloseHandle(root);
    return ok;
}

bool open_empty_native_pipe() {
    using Open = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
                                 PIO_STATUS_BLOCK, ULONG, ULONG);
    const auto open = reinterpret_cast<Open>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtOpenFile"));
    if (!open) return false;
    HANDLE read{}, write{};
    if (!CreatePipe(&read, &write, nullptr, 0)) return false;
    wchar_t empty{};
    UNICODE_STRING unicode{0, sizeof(empty), &empty};
    OBJECT_ATTRIBUTES attributes{sizeof(attributes), read, &unicode, 0, nullptr, nullptr};
    IO_STATUS_BLOCK status{};
    HANDLE reopened{};
    bool ok = GetFileType(read) == FILE_TYPE_PIPE && GetFileType(write) == FILE_TYPE_PIPE;
    // Reopening an anonymous pipe may be rejected by Windows. The audit must
    // still identify this native API argument as a pipe, never a disk asset.
    if (open(&reopened, GENERIC_READ | SYNCHRONIZE, &attributes, &status, 7, 0x20) >= 0) {
        ok = ok && GetFileType(reopened) == FILE_TYPE_PIPE;
        CloseHandle(reopened);
    }
    attributes.RootDirectory = write;
    const bool write_ok = open(&reopened, GENERIC_WRITE | SYNCHRONIZE, &attributes, &status, 7, 0x20) >= 0;
    if (write_ok) {
        ok = ok && GetFileType(reopened) == FILE_TYPE_PIPE;
        CloseHandle(reopened);
    }
    CloseHandle(read);
    CloseHandle(write);
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
    if (!open_relative_native_path(argv[1])) return 8;
    if (!open_empty_native_pipe()) return 9;
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
