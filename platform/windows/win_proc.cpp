#include "win_proc.h"
#include "signature.h"
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <string>
#include <vector>

static std::string wstring_to_utf8(const wchar_t* wstr, int len) {
    if (len <= 0) return {};
    int size = WideCharToMultiByte(CP_UTF8, 0, wstr, len, nullptr, 0, nullptr, nullptr);
    if (size <= 0) return {};
    std::string result(size, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wstr, len, &result[0], size, nullptr, nullptr);
    return result;
}

static std::string get_process_path(HANDLE hProcess) {
    wchar_t path[MAX_PATH] = {};
    DWORD size = MAX_PATH;
    if (QueryFullProcessImageNameW(hProcess, 0, path, &size)) {
        return wstring_to_utf8(path, static_cast<int>(size));
    }

    std::vector<wchar_t> buffer(MAX_PATH);
    DWORD buf_size = static_cast<DWORD>(buffer.size());
    HMODULE mod = nullptr;
    DWORD needed = 0;
    if (EnumProcessModules(hProcess, &mod, sizeof(mod), &needed)) {
        if (GetModuleFileNameExW(hProcess, mod, buffer.data(), buf_size)) {
            return wstring_to_utf8(buffer.data(), static_cast<int>(wcslen(buffer.data())));
        }
    }

    return {};
}

std::optional<ProcessInfo> get_process_info(uint32_t pid) {
    if (pid == 0) return std::nullopt;

    ProcessInfo info;
    info.pid = pid;

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess) {
        info.path = get_process_path(hProcess);
        CloseHandle(hProcess);
    }

    if (!info.path.empty()) {
        auto sig = verify_signature(info.path);
        if (sig.has_value()) {
            info.signed_binary = sig->signed_binary;
            info.publisher = sig->publisher;
        }
    }

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return info;
    }

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            if (pe.th32ProcessID == pid) {
                info.name = wstring_to_utf8(pe.szExeFile, static_cast<int>(wcslen(pe.szExeFile)));
                break;
            }
        } while (Process32NextW(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    return info;
}
