#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winioctl.h>
#include <tlhelp32.h>
#include <dbghelp.h>
#include <psapi.h>

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdlib>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "../NetrBridgeProtocol.h"

namespace {

using NtDebugActiveProcessFn = LONG(NTAPI*)(HANDLE, HANDLE);
using NtQueryInformationThreadFn = LONG(NTAPI*)(
    HANDLE, ULONG, PVOID, ULONG, PULONG);
using RtlNtStatusToDosErrorFn = ULONG(NTAPI*)(LONG);
using WaitForDebugEventFn = BOOL(WINAPI*)(LPDEBUG_EVENT, DWORD);
using WaitForDebugEventExFn = BOOL(WINAPI*)(LPDEBUG_EVENT, DWORD);
using ContinueDebugEventFn = BOOL(WINAPI*)(DWORD, DWORD, DWORD);
using DebugActiveProcessFn = BOOL(WINAPI*)(DWORD);
using DebugActiveProcessStopFn = BOOL(WINAPI*)(DWORD);
using ReadProcessMemoryFn = BOOL(WINAPI*)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*);
using WriteProcessMemoryFn = BOOL(WINAPI*)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
using VirtualProtectExFn = BOOL(WINAPI*)(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);
using GetThreadContextFn = BOOL(WINAPI*)(HANDLE, LPCONTEXT);
using SetThreadContextFn = BOOL(WINAPI*)(HANDLE, const CONTEXT*);
using CreateProcessWFn = BOOL(WINAPI*)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES,
    LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW,
    LPPROCESS_INFORMATION);
using CreateProcessAFn = BOOL(WINAPI*)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES,
    LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA,
    LPPROCESS_INFORMATION);

#ifdef _WIN64
using Wow64GetThreadContextFn = BOOL(WINAPI*)(HANDLE, PWOW64_CONTEXT);
using Wow64SetThreadContextFn = BOOL(WINAPI*)(HANDLE, const WOW64_CONTEXT*);
#endif

struct VirtualDebugState {
    std::uint64_t Dr[4]{};
    std::uint64_t Dr7{};
};

struct SoftwareBreakpointState {
    unsigned char OriginalByte{};
};

enum class TargetAddressClass {
    Unknown,
    WindowsSystemModule,
    UserModule,
    UserPrivateMemory
};

struct PendingPrivateEvent {
    std::uint64_t Sequence{};
    std::uint64_t BreakpointAddress{};
    HANDLE Thread = nullptr;
    ULONG Kind{HV_BRIDGE_PRIVATE_EVENT_SWBP};
    bool DriverContinued{};
    bool ContextRipAdvanced{};
    bool Wow64Context{};
};

struct PendingPrivateDbgkEvent {
    std::uint64_t Sequence{};
    ULONG State{};
    HANDLE Process = nullptr;
    HANDLE Thread = nullptr;
};

struct PendingVtStep {
    DWORD Pid{};
    DWORD Tid{};
    std::uint64_t Address{};
    bool OwnsSwBpGate{};
};

struct ModulePatchState {
    ULONGLONG FirstSeen{};
    DWORD ImageSize{};
    wchar_t Path[MAX_PATH]{};
    bool Complete{};
};

struct ModulePatchResult {
    bool ScanSucceeded{};
    size_t CandidateEntries{};
    size_t PatchedEntries{};
    size_t AlreadyPatchedEntries{};
    size_t FailedEntries{};
};

struct IatPatchRecord {
    PVOID volatile* Slot{};
    PVOID Original{};
    PVOID Replacement{};
    DWORD OriginalProtection{};
    bool Applied{};
};

struct PatchJournal {
    IatPatchRecord* Records{};
    size_t Count{};
    size_t Capacity{};
};

struct PatchPassResult {
    bool SnapshotSucceeded{};
    bool ModulePinned{};
    bool ApplySucceeded{};
    bool RollbackSucceeded{true};
    size_t EligibleModules{};
    size_t ScannedModules{};
    size_t FailedModules{};
    size_t CandidateEntries{};
    size_t PatchedEntries{};
    size_t AlreadyPatchedEntries{};
    size_t FailedEntries{};

    bool CommitReady() const
    {
        return SnapshotSucceeded && EligibleModules != 0 &&
               ModulePinned && ApplySucceeded && RollbackSucceeded &&
               FailedModules == 0 && FailedEntries == 0 &&
               (PatchedEntries + AlreadyPatchedEntries) != 0;
    }
};

HMODULE g_module = nullptr;
HANDLE g_device = INVALID_HANDLE_VALUE;
HANDLE g_ready_event = nullptr;
HANDLE g_commit_event = nullptr;
HANDLE g_committed_event = nullptr;
HANDLE g_abort_event = nullptr;
bool g_module_pinned = false;
bool g_patch_integrity_lost = false;
std::atomic<bool> g_stop{false};
SRWLOCK g_target_lock = SRWLOCK_INIT;
SRWLOCK g_patch_lock = SRWLOCK_INIT;
SRWLOCK g_debug_state_lock = SRWLOCK_INIT;
SRWLOCK g_swbp_lock = SRWLOCK_INIT;
SRWLOCK g_private_event_lock = SRWLOCK_INIT;
SRWLOCK g_vt_step_lock = SRWLOCK_INIT;
SRWLOCK g_log_lock = SRWLOCK_INIT;
std::unordered_set<DWORD> g_targets;
std::unordered_set<DWORD> g_scrubbed_targets;
std::unordered_map<DWORD, VirtualDebugState> g_debug_states;
std::unordered_map<DWORD,
    std::unordered_map<std::uint64_t, SoftwareBreakpointState>> g_sw_breakpoints;
std::unordered_map<std::uint64_t, PendingPrivateEvent> g_pending_private_events;
std::unordered_map<std::uint64_t, PendingPrivateDbgkEvent> g_pending_private_dbgk_events;
std::unordered_map<DWORD, DWORD> g_private_launches;
std::unordered_map<DWORD, DWORD> g_private_initial_threads;
std::unordered_map<std::uint64_t, PendingVtStep> g_pending_vt_steps;
// One-shot suppress window for native EXCEPTION_SINGLE_STEP after a private
// HV_BRIDGE_PRIVATE_EVENT_STEP stop was already delivered (dual-notify).
std::unordered_map<std::uint64_t, ULONGLONG> g_suppress_native_single_step;
SRWLOCK g_suppress_ss_lock = SRWLOCK_INIT;
std::unordered_map<HMODULE, ModulePatchState> g_module_patch_states;
HANDLE g_log_file = INVALID_HANDLE_VALUE;
wchar_t g_log_path[MAX_PATH] = {};
std::atomic<bool> g_cleanup_started{false};
std::atomic<unsigned long long> g_read_sequence{0};
std::atomic<unsigned long long> g_event_sequence{0};
std::atomic<unsigned long long> g_continue_sequence{0};
std::atomic<unsigned long long> g_context_sequence{0};
std::atomic<unsigned long long> g_protect_sequence{0};
std::atomic<unsigned long long> g_kernel_event_sequence{0};
std::atomic<unsigned long long> g_private_dbgk_poll_error_sequence{0};
std::atomic<ULONG> g_granted_capabilities{0};
std::atomic<bool> g_private_dbgk_mode{false};
std::atomic<bool> g_private_dbgk_transport_dead{false};
std::atomic<LONG> g_private_dbgk_terminal_status{0};

NtDebugActiveProcessFn g_nt_debug_active_process = nullptr;
NtQueryInformationThreadFn g_nt_query_information_thread = nullptr;
RtlNtStatusToDosErrorFn g_rtl_nt_status_to_dos_error = nullptr;
WaitForDebugEventFn g_wait_for_debug_event = nullptr;
WaitForDebugEventExFn g_wait_for_debug_event_ex = nullptr;
ContinueDebugEventFn g_continue_debug_event = nullptr;
DebugActiveProcessFn g_debug_active_process = nullptr;
DebugActiveProcessStopFn g_debug_active_process_stop = nullptr;
ReadProcessMemoryFn g_read_process_memory = nullptr;
WriteProcessMemoryFn g_write_process_memory = nullptr;
VirtualProtectExFn g_virtual_protect_ex = nullptr;
GetThreadContextFn g_get_thread_context = nullptr;
SetThreadContextFn g_set_thread_context = nullptr;
CreateProcessWFn g_create_process_w = nullptr;
CreateProcessAFn g_create_process_a = nullptr;

#ifdef _WIN64
Wow64GetThreadContextFn g_wow64_get_thread_context = nullptr;
Wow64SetThreadContextFn g_wow64_set_thread_context = nullptr;
#endif

LONG NTAPI BridgeNtDebugActiveProcess(HANDLE process, HANDLE debug_object);
BOOL WINAPI BridgeWaitForDebugEvent(LPDEBUG_EVENT event, DWORD timeout);
BOOL WINAPI BridgeWaitForDebugEventEx(LPDEBUG_EVENT event, DWORD timeout);
BOOL WINAPI BridgeContinueDebugEvent(DWORD pid, DWORD tid, DWORD status);
BOOL WINAPI BridgeDebugActiveProcess(DWORD pid);
BOOL WINAPI BridgeDebugActiveProcessStop(DWORD pid);
BOOL WINAPI BridgeReadProcessMemory(HANDLE process, LPCVOID address, LPVOID buffer,
                                    SIZE_T size, SIZE_T* transferred);
BOOL WINAPI BridgeWriteProcessMemory(HANDLE process, LPVOID address, LPCVOID buffer,
                                     SIZE_T size, SIZE_T* transferred);
BOOL WINAPI BridgeVirtualProtectEx(HANDLE process, LPVOID address, SIZE_T size,
                                   DWORD protection, PDWORD old_protection);
BOOL WINAPI BridgeGetThreadContext(HANDLE thread, LPCONTEXT context);
BOOL WINAPI BridgeSetThreadContext(HANDLE thread, const CONTEXT* context);
BOOL WINAPI BridgeCreateProcessW(LPCWSTR application_name, LPWSTR command_line,
    LPSECURITY_ATTRIBUTES process_attributes, LPSECURITY_ATTRIBUTES thread_attributes,
    BOOL inherit_handles, DWORD creation_flags, LPVOID environment,
    LPCWSTR current_directory, LPSTARTUPINFOW startup_info,
    LPPROCESS_INFORMATION process_info);
BOOL WINAPI BridgeCreateProcessA(LPCSTR application_name, LPSTR command_line,
    LPSECURITY_ATTRIBUTES process_attributes, LPSECURITY_ATTRIBUTES thread_attributes,
    BOOL inherit_handles, DWORD creation_flags, LPVOID environment,
    LPCSTR current_directory, LPSTARTUPINFOA startup_info,
    LPPROCESS_INFORMATION process_info);

void ObserveDebugEvent(const DEBUG_EVENT* event);

#ifdef _WIN64
BOOL WINAPI BridgeWow64GetThreadContext(HANDLE thread, PWOW64_CONTEXT context);
BOOL WINAPI BridgeWow64SetThreadContext(HANDLE thread, const WOW64_CONTEXT* context);
#endif

TargetAddressClass ClassifyTargetAddress(
    HANDLE process, DWORD pid, LPCVOID address, SIZE_T size);

struct StaleLogEntry {
    wchar_t Path[MAX_PATH]{};
    ULONGLONG LastWriteTime{};
};

ULONGLONG FileTimeValue(const FILETIME& value)
{
    ULARGE_INTEGER time = {};
    time.LowPart = value.dwLowDateTime;
    time.HighPart = value.dwHighDateTime;
    return time.QuadPart;
}

bool IsLogOwnerActive(
    const wchar_t* file_name,
    const FILETIME& log_write_time)
{
    static constexpr wchar_t prefix[] = L"GuardMetaBridge-";
    if (!file_name ||
        _wcsnicmp(file_name, prefix, _countof(prefix) - 1) != 0) {
        return false;
    }

    wchar_t* suffix = nullptr;
    const unsigned long pid = wcstoul(
        file_name + _countof(prefix) - 1, &suffix, 10);
    if (pid == 0 || !suffix || _wcsicmp(suffix, L".log") != 0) {
        return false;
    }
    if (pid == GetCurrentProcessId()) return true;

    const HANDLE process = OpenProcess(
        SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
        FALSE, static_cast<DWORD>(pid));
    if (!process) {
        return GetLastError() == ERROR_ACCESS_DENIED;
    }

    FILETIME process_created = {};
    FILETIME process_exited = {};
    FILETIME process_kernel = {};
    FILETIME process_user = {};
    if (GetProcessTimes(process, &process_created, &process_exited,
                        &process_kernel, &process_user) &&
        FileTimeValue(process_created) > FileTimeValue(log_write_time)) {
        CloseHandle(process);
        return false;
    }

    const DWORD wait = WaitForSingleObject(process, 0);
    CloseHandle(process);
    return wait == WAIT_TIMEOUT;
}

void CleanupLogDirectory(const wchar_t* directory)
{
    if (!directory || directory[0] == L'\0') return;

    wchar_t pattern[MAX_PATH] = {};
    if (_snwprintf_s(pattern, _countof(pattern), _TRUNCATE,
                     L"%s\\GuardMetaBridge-*.log", directory) < 0) {
        return;
    }

    WIN32_FIND_DATAW data = {};
    const HANDLE find = FindFirstFileW(pattern, &data);
    if (find == INVALID_HANDLE_VALUE) return;

    FILETIME now_file_time = {};
    GetSystemTimeAsFileTime(&now_file_time);
    ULARGE_INTEGER now = {};
    now.LowPart = now_file_time.dwLowDateTime;
    now.HighPart = now_file_time.dwHighDateTime;
    constexpr ULONGLONG ticks_per_day = 24ULL * 60ULL * 60ULL * 10000000ULL;
    constexpr ULONGLONG max_log_age = 7ULL * ticks_per_day;
    std::vector<StaleLogEntry> stale_logs;

    do {
        if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 ||
            IsLogOwnerActive(data.cFileName, data.ftLastWriteTime)) {
            continue;
        }

        wchar_t path[MAX_PATH] = {};
        if (_snwprintf_s(path, _countof(path), _TRUNCATE,
                         L"%s\\%s", directory, data.cFileName) < 0) {
            continue;
        }

        ULARGE_INTEGER write_time = {};
        write_time.LowPart = data.ftLastWriteTime.dwLowDateTime;
        write_time.HighPart = data.ftLastWriteTime.dwHighDateTime;
        const bool empty = data.nFileSizeHigh == 0 && data.nFileSizeLow == 0;
        const bool expired = now.QuadPart > write_time.QuadPart &&
            now.QuadPart - write_time.QuadPart > max_log_age;
        if (empty || expired) {
            (void)DeleteFileW(path);
            continue;
        }

        StaleLogEntry entry = {};
        wcscpy_s(entry.Path, path);
        entry.LastWriteTime = write_time.QuadPart;
        stale_logs.push_back(entry);
    } while (FindNextFileW(find, &data));
    FindClose(find);

    std::sort(stale_logs.begin(), stale_logs.end(),
              [](const StaleLogEntry& left, const StaleLogEntry& right) {
                  return left.LastWriteTime > right.LastWriteTime;
              });
    constexpr size_t retained_stale_logs = 8;
    for (size_t index = retained_stale_logs;
         index < stale_logs.size(); ++index) {
        (void)DeleteFileW(stale_logs[index].Path);
    }
}

bool OpenModuleLogFile()
{
    wchar_t module_path[MAX_PATH] = {};
    const DWORD length = GetModuleFileNameW(
        g_module, module_path, static_cast<DWORD>(_countof(module_path)));
    if (length == 0 || length >= _countof(module_path)) return false;

    wchar_t* separator = wcsrchr(module_path, L'\\');
    wchar_t* alternate_separator = wcsrchr(module_path, L'/');
    if (alternate_separator &&
        (!separator || alternate_separator > separator)) {
        separator = alternate_separator;
    }
    if (!separator) return false;
    *separator = L'\0';

    wchar_t log_directory[MAX_PATH] = {};
    if (_snwprintf_s(log_directory, _countof(log_directory), _TRUNCATE,
                     L"%s\\logs", module_path) < 0) {
        return false;
    }
    if (!CreateDirectoryW(log_directory, nullptr) &&
        GetLastError() != ERROR_ALREADY_EXISTS) {
        return false;
    }
    const DWORD attributes = GetFileAttributesW(log_directory);
    if (attributes == INVALID_FILE_ATTRIBUTES ||
        (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
        return false;
    }

    CleanupLogDirectory(log_directory);
    if (_snwprintf_s(g_log_path, _countof(g_log_path), _TRUNCATE,
                     L"%s\\GuardMetaBridge-%lu.log", log_directory,
                     GetCurrentProcessId()) < 0) {
        g_log_path[0] = L'\0';
        return false;
    }
    g_log_file = CreateFileW(
        g_log_path, FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    return g_log_file != INVALID_HANDLE_VALUE;
}

bool OpenTemporaryLogFile()
{
    wchar_t temp_path[MAX_PATH] = {};
    const DWORD length = GetTempPathW(_countof(temp_path), temp_path);
    if (length == 0 || length >= _countof(temp_path)) return false;
    CleanupLogDirectory(temp_path);
    if (_snwprintf_s(g_log_path, _countof(g_log_path), _TRUNCATE,
                     L"%sGuardMetaBridge-%lu.log", temp_path,
                     GetCurrentProcessId()) < 0) {
        g_log_path[0] = L'\0';
        return false;
    }
    g_log_file = CreateFileW(
        g_log_path, FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    return g_log_file != INVALID_HANDLE_VALUE;
}

void Trace(const wchar_t* format, ...)
{
    const DWORD saved_error = GetLastError();
    wchar_t buffer[512] = {};
    va_list args;
    va_start(args, format);
    _vsnwprintf_s(buffer, _countof(buffer), _TRUNCATE, format, args);
    va_end(args);

    wchar_t line[768] = {};
    _snwprintf_s(line, _countof(line), _TRUNCATE,
                 L"[%llu][%lu:%lu] %s",
                 GetTickCount64(), GetCurrentProcessId(),
                 GetCurrentThreadId(), buffer);
    OutputDebugStringW(line);

    AcquireSRWLockExclusive(&g_log_lock);
    if (g_log_file == INVALID_HANDLE_VALUE) {
        if (!OpenModuleLogFile()) (void)OpenTemporaryLogFile();
    }
    if (g_log_file != INVALID_HANDLE_VALUE) {
        char utf8[2304] = {};
        const int length = WideCharToMultiByte(
            CP_UTF8, 0, line, -1, utf8, static_cast<int>(sizeof(utf8)),
            nullptr, nullptr);
        if (length > 1) {
            DWORD written = 0;
            WriteFile(g_log_file, utf8, static_cast<DWORD>(length - 1),
                      &written, nullptr);
            FlushFileBuffers(g_log_file);
        }
    }
    ReleaseSRWLockExclusive(&g_log_lock);
    SetLastError(saved_error);
}

const wchar_t* CopyStageName(ULONG stage)
{
    switch (stage) {
    case 1: return L"validate";
    case 2: return L"buffer-lock";
    case 3: return L"process-lookup";
    case 4: return L"target-lock";
    case 5: return L"cr3-resolve";
    case 6: return L"vt-root-copy";
    case 7: return L"complete";
    case 8: return L"mdl-fallback";
    default: return L"unknown";
    }
}

void PollKernelEvents()
{
    if (g_device == INVALID_HANDLE_VALUE) return;

    constexpr ULONG max_events = 512;
    HV_BRIDGE_DBGEVT_PULL_REQUEST request = {};
    request.SinceSequence = g_kernel_event_sequence.load();
    request.MaxCount = max_events;

    std::vector<unsigned char> output(
        sizeof(HV_BRIDGE_DBGEVT_PULL_RESULT) +
        max_events * sizeof(HV_BRIDGE_DBGEVT));
    DWORD returned = 0;
    if (!DeviceIoControl(
            g_device, IOCTL_HV_BRIDGE_GET_DBGEVT,
            &request, sizeof(request), output.data(),
            static_cast<DWORD>(output.size()), &returned, nullptr) ||
        returned < sizeof(HV_BRIDGE_DBGEVT_PULL_RESULT)) {
        return;
    }

    const auto* header =
        reinterpret_cast<const HV_BRIDGE_DBGEVT_PULL_RESULT*>(output.data());
    const ULONG available = static_cast<ULONG>(
        (returned - sizeof(*header)) / sizeof(HV_BRIDGE_DBGEVT));
    const ULONG count = std::min(header->Count, available);
    g_kernel_event_sequence.store(header->NextSequence);

    const auto* events = reinterpret_cast<const HV_BRIDGE_DBGEVT*>(
        output.data() + sizeof(*header));
    for (ULONG index = 0; index < count; ++index) {
        const auto& event = events[index];
        if (event.Category >= 100) continue;

        size_t detail_length = 0;
        while (detail_length < HV_BRIDGE_DBGEVT_DETAIL_MAX &&
               event.Detail[detail_length] != '\0') {
            ++detail_length;
        }
        wchar_t detail[HV_BRIDGE_DBGEVT_DETAIL_MAX + 1] = {};
        if (detail_length != 0) {
            MultiByteToWideChar(
                CP_UTF8, 0, event.Detail, static_cast<int>(detail_length),
                detail, static_cast<int>(_countof(detail) - 1));
        }
        Trace(L"[KERNEL #%llu] sev=%lu cat=%lu status=0x%08X caller=%lu target=%lu address=0x%llX size=0x%llX detail=%s\n",
              event.Sequence, event.Severity, event.Category,
              static_cast<unsigned long>(event.Status),
              event.CallerPid, event.TargetPid,
              static_cast<unsigned long long>(event.Address),
              static_cast<unsigned long long>(event.Size), detail);
    }
}

bool IsNtSuccess(LONG status)
{
    return status >= 0;
}

void SetLastErrorFromNtStatus(LONG status)
{
    DWORD error = ERROR_GEN_FAILURE;
    if (g_rtl_nt_status_to_dos_error) {
        const ULONG mapped = g_rtl_nt_status_to_dos_error(status);
        if (mapped != ERROR_MR_MID_NOT_FOUND) error = mapped;
    }
    SetLastError(error);
}

bool ReadDeviceLeaf(wchar_t* leaf, DWORD leaf_chars)
{
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"Software\\NetrSvc", 0,
                      KEY_READ, &key) != ERROR_SUCCESS) {
        return false;
    }

    DWORD type = 0;
    DWORD bytes = leaf_chars * sizeof(wchar_t);
    const LSTATUS status = RegQueryValueExW(
        key, L"DeviceName", nullptr, &type,
        reinterpret_cast<BYTE*>(leaf), &bytes);
    RegCloseKey(key);

    if (status != ERROR_SUCCESS || type != REG_SZ || bytes < sizeof(wchar_t)) {
        return false;
    }
    leaf[leaf_chars - 1] = L'\0';
    return leaf[0] != L'\0';
}

bool OpenDriver()
{
    wchar_t leaf[64] = {};
    if (!ReadDeviceLeaf(leaf, _countof(leaf))) return false;

    wchar_t path[80] = {};
    _snwprintf_s(path, _countof(path), _TRUNCATE, L"\\\\.\\%s", leaf);
    g_device = CreateFileW(path, GENERIC_READ | GENERIC_WRITE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    Trace(L"[OPEN] device=%s handle=%p win32=%lu\n",
          path, g_device,
          g_device == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS);
    return g_device != INVALID_HANDLE_VALUE;
}

bool NormalizeKernelPath(const wchar_t* source, wchar_t* target, size_t count)
{
    if (!source || !*source || !target || count == 0) return false;
    if (_wcsnicmp(source, L"\\SystemRoot\\", 12) == 0) {
        wchar_t windows[MAX_PATH] = {};
        const UINT length = GetWindowsDirectoryW(windows, _countof(windows));
        if (length == 0 || length >= _countof(windows)) return false;
        return _snwprintf_s(target, count, _TRUNCATE, L"%s\\%s",
                            windows, source + 12) > 0;
    }
    if (_wcsnicmp(source, L"\\??\\", 4) == 0) source += 4;
    return wcscpy_s(target, count, source) == 0;
}

bool ResolveKernelSymbol(HANDLE process, const char* name, ULONG64* address)
{
    if (!name || !address) return false;
    alignas(SYMBOL_INFO) unsigned char storage[
        sizeof(SYMBOL_INFO) + MAX_SYM_NAME] = {};
    auto* symbol = reinterpret_cast<SYMBOL_INFO*>(storage);
    symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
    symbol->MaxNameLen = MAX_SYM_NAME;
    char qualified[MAX_SYM_NAME] = {};
    _snprintf_s(qualified, _countof(qualified), _TRUNCATE, "nt!%s", name);
    if (!SymFromName(process, qualified, symbol) &&
        !SymFromName(process, name, symbol)) {
        Trace(L"[DBGK-SYMBOL] missing %S win32=%lu\n", name, GetLastError());
        return false;
    }
    *address = symbol->Address;
    Trace(L"[DBGK-SYMBOL] %S=0x%llX\n", name,
          static_cast<unsigned long long>(*address));
    return true;
}

std::vector<std::wstring> SelectSymbolCacheDirectories()
{
    constexpr const wchar_t* candidates[] = {
        L"E:\\Symbols",
        L"D:\\Symbols",
        L"C:\\Symbols",
    };
    std::vector<std::wstring> directories;
    for (const auto* candidate : candidates) {
        wchar_t root[] = {candidate[0], L':', L'\\', L'\0'};
        if (GetDriveTypeW(root) == DRIVE_NO_ROOT_DIR) continue;
        if (CreateDirectoryW(candidate, nullptr) ||
            GetLastError() == ERROR_ALREADY_EXISTS) {
            directories.emplace_back(candidate);
        }
    }
    if (directories.empty()) directories.emplace_back(L"C:\\Symbols");
    return directories;
}

bool ConfigurePrivateDbgkSymbols()
{
    if (!g_private_dbgk_mode.load()) return true;
    LPVOID drivers[1024] = {};
    DWORD needed = 0;
    if (!EnumDeviceDrivers(drivers, sizeof(drivers), &needed) ||
        needed < sizeof(drivers[0]) || !drivers[0]) {
        Trace(L"[DBGK-SYMBOL] EnumDeviceDrivers failed win32=%lu\n", GetLastError());
        return false;
    }
    wchar_t raw_path[MAX_PATH] = {};
    wchar_t kernel_path[MAX_PATH] = {};
    if (!GetDeviceDriverFileNameW(drivers[0], raw_path, _countof(raw_path)) ||
        !NormalizeKernelPath(raw_path, kernel_path, _countof(kernel_path))) {
        Trace(L"[DBGK-SYMBOL] kernel path failed win32=%lu raw=%s\n",
              GetLastError(), raw_path);
        return false;
    }

    /* Match Unreal's runtime model: the package carries no PDB. DbgHelp's
     * symbol path downloads the exact kernel PDB into a cache on demand and
     * resolves the complete private Dbgk/debugger-proxy publication set. */
    const std::vector<std::wstring> symbol_caches = SelectSymbolCacheDirectories();
    const std::wstring& symbol_cache = symbol_caches.front();
    std::wstring symbol_path;
    for (const auto& cache : symbol_caches) {
        if (!symbol_path.empty()) symbol_path.append(L";");
        symbol_path.append(cache);
    }
    symbol_path.append(L";srv*");
    symbol_path.append(symbol_cache);
    symbol_path.append(L"*https://msdl.microsoft.com/download/symbols");
    wchar_t environment_path[1536] = {};
    const DWORD environment_length = GetEnvironmentVariableW(
        L"_NT_SYMBOL_PATH", environment_path, _countof(environment_path));
    if (environment_length > 0 && environment_length < _countof(environment_path)) {
        symbol_path.append(L";");
        symbol_path.append(environment_path);
    }

    HANDLE process = GetCurrentProcess();
    SymSetOptions(SYMOPT_DEFERRED_LOADS | SYMOPT_UNDNAME |
                  SYMOPT_FAIL_CRITICAL_ERRORS | SYMOPT_LOAD_LINES);
    if (!SymInitializeW(process, symbol_path.c_str(), FALSE)) {
        Trace(L"[DBGK-SYMBOL] SymInitialize failed win32=%lu path=%s\n",
              GetLastError(), symbol_path.c_str());
        return false;
    }
    const DWORD64 module = SymLoadModuleExW(
        process, nullptr, kernel_path, L"nt",
        reinterpret_cast<DWORD64>(drivers[0]), 0, nullptr, 0);
    if (!module) {
        Trace(L"[DBGK-SYMBOL] SymLoadModuleEx failed win32=%lu image=%s base=%p\n",
              GetLastError(), kernel_path, drivers[0]);
        SymCleanup(process);
        return false;
    }

    HV_BRIDGE_DBGK_SYMBOLS_REQUEST request = {};
    request.Version = HV_BRIDGE_PROTOCOL_VERSION;
    const bool resolved =
        ResolveKernelSymbol(process, "NtCreateDebugObject", &request.NtCreateDebugObject) &&
        ResolveKernelSymbol(process, "NtDebugActiveProcess", &request.NtDebugActiveProcess) &&
        ResolveKernelSymbol(process, "NtSetInformationDebugObject", &request.NtSetInformationDebugObject) &&
        ResolveKernelSymbol(process, "NtWaitForDebugEvent", &request.NtWaitForDebugEvent) &&
        ResolveKernelSymbol(process, "NtDebugContinue", &request.NtDebugContinue) &&
        ResolveKernelSymbol(process, "NtRemoveProcessDebug", &request.NtRemoveProcessDebug) &&
        ResolveKernelSymbol(process, "DbgkForwardException", &request.DbgkForwardException) &&
        ResolveKernelSymbol(process, "DbgkCreateThread", &request.DbgkCreateThread) &&
        ResolveKernelSymbol(process, "DbgkExitThread", &request.DbgkExitThread) &&
        ResolveKernelSymbol(process, "DbgkExitProcess", &request.DbgkExitProcess) &&
        ResolveKernelSymbol(process, "DbgkMapViewOfSection", &request.DbgkMapViewOfSection) &&
        ResolveKernelSymbol(process, "DbgkUnMapViewOfSection", &request.DbgkUnMapViewOfSection) &&
        ResolveKernelSymbol(process, "PsGetNextProcessThread", &request.PsGetNextProcessThread) &&
        ResolveKernelSymbol(process, "NtSetContextThread", &request.NtSetContextThread) &&
        ResolveKernelSymbol(process, "NtReadVirtualMemory", &request.NtReadVirtualMemory) &&
        ResolveKernelSymbol(process, "NtWriteVirtualMemory", &request.NtWriteVirtualMemory);
    SymCleanup(process);
    if (!resolved) return false;

    HV_BRIDGE_OPERATION_RESULT result = {};
    DWORD returned = 0;
    const BOOL ok = DeviceIoControl(
        g_device, IOCTL_HV_BRIDGE_DBGK_SYMBOLS,
        &request, sizeof(request), &result, sizeof(result), &returned, nullptr);
    const bool configured =
        ok == TRUE &&
        returned == sizeof(result) &&
        result.Status == HV_BRIDGE_STATUS_SUCCESS;
    Trace(L"[DBGK-SYMBOL] configure ok=%d returned=%lu bridge=%lu ntstatus=0x%08llX win32=%lu\n",
          configured,
          returned,
          result.Status,
          result.Info,
          ok ? ERROR_SUCCESS : GetLastError());
    return configured;
}

bool RegisterBridge()
{
    HV_BRIDGE_REGISTER_REQUEST request = {};
    request.Version = HV_BRIDGE_PROTOCOL_VERSION;
    request.Capabilities = HV_BRIDGE_CAP_DEBUG_EVENTS |
                           HV_BRIDGE_CAP_MEMORY_IO |
                           HV_BRIDGE_CAP_THREAD_CONTEXT |
                           HV_BRIDGE_CAP_PEB_SCRUB |
                           HV_BRIDGE_CAP_PRIVATE_SWBP |
                           HV_BRIDGE_CAP_VT_HWBP |
                           HV_BRIDGE_CAP_VT_STEP |
                           HV_BRIDGE_CAP_PRIVATE_DEBUG_OBJECT |
                           HV_BRIDGE_CAP_DR_HWBP_FALLBACK |
                           HV_BRIDGE_CAP_OS_MEMORY_PROTECT |
                           HV_BRIDGE_CAP_OS_COW_WRITE;
    Trace(L"[NetrBridge] SWBP policy=user/private modules -> VT, shared Windows modules -> native COW\n");
    HV_BRIDGE_RESULT result = {};
    DWORD returned = 0;
    const BOOL ok = DeviceIoControl(
        g_device, IOCTL_HV_BRIDGE_REGISTER,
        &request, sizeof(request), &result, sizeof(result), &returned, nullptr);
    const DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    const bool valid = ok && returned >= sizeof(result) &&
                       result.Version == HV_BRIDGE_PROTOCOL_VERSION &&
                       result.DebuggerPid == GetCurrentProcessId() &&
                       IsNtSuccess(result.Status);
    Trace(L"[REGISTER] ok=%d valid=%d returned=%lu win32=%lu version=%lu status=0x%08X debugger=%lu bindings=%lu flags=0x%08X\n",
          ok, valid, returned, error, result.Version,
          static_cast<unsigned long>(result.Status), result.DebuggerPid,
          result.ActiveBindings, result.Flags);
    if (valid) {
        Trace(L"[REGISTER-STATE] driver_hide=%d file_hide=%d registry_hide=%d network_hook=%d private_debug_object=%d vt_memory=%d vt_peb_scrub=%d os_protect=%d os_cow=%d\n",
              (result.Flags & HV_BRIDGE_STATE_DRIVER_HIDE) != 0,
              (result.Flags & HV_BRIDGE_STATE_FILE_HIDE) != 0,
              (result.Flags & HV_BRIDGE_STATE_REGISTRY_HIDE) != 0,
              (result.Flags & HV_BRIDGE_STATE_NETWORK_HOOK) != 0,
              (result.Flags & HV_BRIDGE_STATE_PRIVATE_DEBUG_OBJECT) != 0,
              (result.Flags & HV_BRIDGE_CAP_MEMORY_IO) != 0,
              (result.Flags & HV_BRIDGE_CAP_PEB_SCRUB) != 0,
              (result.Flags & HV_BRIDGE_CAP_OS_MEMORY_PROTECT) != 0,
              (result.Flags & HV_BRIDGE_CAP_OS_COW_WRITE) != 0);
    }
    if (valid) {
        g_granted_capabilities.store(result.Flags);
        g_private_dbgk_mode.store(
            (result.Flags & HV_BRIDGE_STATE_PRIVATE_DEBUG_OBJECT) != 0);
        g_private_dbgk_transport_dead.store(false);
        g_private_dbgk_terminal_status.store(0);
    } else {
        g_granted_capabilities.store(0);
        g_private_dbgk_mode.store(false);
        g_private_dbgk_transport_dead.store(false);
        g_private_dbgk_terminal_status.store(0);
        SetLastError(error != ERROR_SUCCESS ? error : ERROR_INVALID_DATA);
    }
    return valid;
}

bool SendTargetIoctl(DWORD code, DWORD pid, DWORD operation_flags = 0)
{
    if (g_device == INVALID_HANDLE_VALUE || pid == 0 ||
        pid == GetCurrentProcessId()) {
        return false;
    }

    HV_BRIDGE_TARGET_REQUEST request = {};
    request.Version = HV_BRIDGE_PROTOCOL_VERSION;
    request.TargetPid = pid;
    request.Flags = operation_flags;
    if (code == IOCTL_HV_BRIDGE_BIND_TARGET) {
        request.Flags |= HV_BRIDGE_BIND_DEFAULT_FLAGS;
        request.Flags |= g_private_dbgk_mode.load()
            ? HV_BRIDGE_BIND_EXPECT_PRIVATE_DBGK
            : HV_BRIDGE_BIND_EXPECT_WINDOWS_DEBUG_OBJECT;
    }
    HV_BRIDGE_RESULT result = {};
    DWORD returned = 0;
    const BOOL ok = DeviceIoControl(
        g_device, code, &request, sizeof(request),
        &result, sizeof(result), &returned, nullptr);
    const DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    const bool valid = ok && returned >= sizeof(result) &&
                       result.Version == HV_BRIDGE_PROTOCOL_VERSION &&
                       result.DebuggerPid == GetCurrentProcessId() &&
                       result.TargetPid == pid && IsNtSuccess(result.Status);
    Trace(L"[TARGET] ioctl=0x%08X pid=%lu ok=%d valid=%d returned=%lu win32=%lu version=%lu status=0x%08X bindings=%lu flags=0x%08X\n",
          code, pid, ok, valid, returned, error, result.Version,
          static_cast<unsigned long>(result.Status),
          result.ActiveBindings, result.Flags);
    return valid;
}

bool IsBoundTarget(DWORD pid)
{
    AcquireSRWLockShared(&g_target_lock);
    const bool found = g_targets.find(pid) != g_targets.end();
    ReleaseSRWLockShared(&g_target_lock);
    return found;
}

std::uint64_t PrivateEventKey(DWORD pid, DWORD tid)
{
    return (static_cast<std::uint64_t>(pid) << 32) | tid;
}

bool SendSoftwareBreakpoint(DWORD code, DWORD target_pid, std::uint64_t address)
{
    if (g_device == INVALID_HANDLE_VALUE || target_pid == 0 || address == 0) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return false;
    }

    HV_BRIDGE_SWBP_REQUEST request = {};
    request.Version = HV_BRIDGE_PROTOCOL_VERSION;
    request.TargetPid = target_pid;
    request.Address = address;

    HV_BRIDGE_OPERATION_RESULT result = {};
    DWORD returned = 0;
    const BOOL ok = DeviceIoControl(
        g_device, code, &request, sizeof(request),
        &result, sizeof(result), &returned, nullptr);
    const DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    if (!ok || returned < sizeof(result)) {
        SetLastError(error != ERROR_SUCCESS ? error : ERROR_INVALID_DATA);
        return false;
    }
    if (result.Status == HV_BRIDGE_STATUS_SUCCESS ||
        (code == IOCTL_HV_BRIDGE_SWBP_DEL &&
         result.Status == HV_BRIDGE_STATUS_NOT_FOUND)) {
        return true;
    }

    SetLastError(result.Status == HV_BRIDGE_STATUS_NOT_FOUND
        ? ERROR_NOT_FOUND : ERROR_INVALID_PARAMETER);
    return false;
}

bool SendVtStep(
    DWORD code,
    DWORD target_pid,
    DWORD target_tid,
    std::uint64_t address)
{
    if (g_device == INVALID_HANDLE_VALUE || target_pid == 0 ||
        target_tid == 0) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return false;
    }

    HV_BRIDGE_STEP_REQUEST request = {};
    request.Version = HV_BRIDGE_PROTOCOL_VERSION;
    request.TargetPid = target_pid;
    request.ThreadId = target_tid;
    request.Address = address;

    HV_BRIDGE_OPERATION_RESULT result = {};
    DWORD returned = 0;
    const BOOL ok = DeviceIoControl(
        g_device, code, &request, sizeof(request),
        &result, sizeof(result), &returned, nullptr);
    const DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    if (!ok || returned < sizeof(result)) {
        SetLastError(error != ERROR_SUCCESS ? error : ERROR_INVALID_DATA);
        return false;
    }
    if (result.Status == HV_BRIDGE_STATUS_SUCCESS ||
        (code == IOCTL_HV_BRIDGE_STEP_CLEAR &&
         result.Status == HV_BRIDGE_STATUS_NOT_FOUND)) {
        return true;
    }

    SetLastError(result.Status == HV_BRIDGE_STATUS_NOT_FOUND
        ? ERROR_NOT_FOUND : ERROR_INVALID_PARAMETER);
    return false;
}

bool LookupPendingVtStep(DWORD pid, DWORD tid, PendingVtStep* step)
{
    const std::uint64_t key = PrivateEventKey(pid, tid);
    AcquireSRWLockShared(&g_vt_step_lock);
    const auto found = g_pending_vt_steps.find(key);
    const bool exists = found != g_pending_vt_steps.end();
    if (exists && step) *step = found->second;
    ReleaseSRWLockShared(&g_vt_step_lock);
    return exists;
}

void ArmNativeSingleStepSuppress(DWORD pid, DWORD tid)
{
    const std::uint64_t key = PrivateEventKey(pid, tid);
    AcquireSRWLockExclusive(&g_suppress_ss_lock);
    g_suppress_native_single_step[key] = GetTickCount64() + 2000ULL;
    ReleaseSRWLockExclusive(&g_suppress_ss_lock);
}

bool ShouldSuppressNativeSingleStep(const DEBUG_EVENT* event)
{
    if (!event || event->dwDebugEventCode != EXCEPTION_DEBUG_EVENT) {
        return false;
    }
    if (event->u.Exception.ExceptionRecord.ExceptionCode !=
        EXCEPTION_SINGLE_STEP) {
        return false;
    }

    const std::uint64_t key =
        PrivateEventKey(event->dwProcessId, event->dwThreadId);
    AcquireSRWLockExclusive(&g_suppress_ss_lock);
    const auto found = g_suppress_native_single_step.find(key);
    if (found == g_suppress_native_single_step.end()) {
        ReleaseSRWLockExclusive(&g_suppress_ss_lock);
        return false;
    }
    const ULONGLONG expire = found->second;
    const ULONGLONG now = GetTickCount64();
    g_suppress_native_single_step.erase(found);
    ReleaseSRWLockExclusive(&g_suppress_ss_lock);
    if (now > expire) {
        return false;
    }
    Trace(L"[VT-STEP] suppressed duplicate native SS pid=%lu tid=%lu\n",
          event->dwProcessId, event->dwThreadId);
    return true;
}

bool ConsumeNativeDebugEvent(LPDEBUG_EVENT event)
{
    if (ShouldSuppressNativeSingleStep(event)) {
        if (g_continue_debug_event) {
            (void)g_continue_debug_event(
                event->dwProcessId, event->dwThreadId, DBG_CONTINUE);
        }
        return false;
    }
    ObserveDebugEvent(event);
    return true;
}

bool InstallVtStepGate(
    DWORD pid,
    std::uint64_t address,
    bool* owns_gate)
{
    if (!owns_gate) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return false;
    }
    *owns_gate = false;
    if ((g_granted_capabilities.load() &
         HV_BRIDGE_CAP_PRIVATE_SWBP) == 0) {
        return true;
    }

    AcquireSRWLockExclusive(&g_swbp_lock);
    const auto process = g_sw_breakpoints.find(pid);
    if (process != g_sw_breakpoints.end() &&
        process->second.find(address) != process->second.end()) {
        ReleaseSRWLockExclusive(&g_swbp_lock);
        return true;
    }

    const bool installed = SendSoftwareBreakpoint(
        IOCTL_HV_BRIDGE_SWBP_ADD, pid, address);
    const DWORD error = installed ? ERROR_SUCCESS : GetLastError();
    ReleaseSRWLockExclusive(&g_swbp_lock);
    if (!installed) {
        SetLastError(error);
        return false;
    }
    *owns_gate = true;
    return true;
}

bool ReleaseVtStepGate(const PendingVtStep& step)
{
    if (!step.OwnsSwBpGate) return true;

    AcquireSRWLockExclusive(&g_swbp_lock);
    const auto process = g_sw_breakpoints.find(step.Pid);
    const bool debugger_owns_breakpoint =
        process != g_sw_breakpoints.end() &&
        process->second.find(step.Address) != process->second.end();
    const bool removed = debugger_owns_breakpoint || SendSoftwareBreakpoint(
        IOCTL_HV_BRIDGE_SWBP_DEL, step.Pid, step.Address);
    const DWORD error = removed ? ERROR_SUCCESS : GetLastError();
    ReleaseSRWLockExclusive(&g_swbp_lock);
    if (!removed) SetLastError(error);
    return removed;
}

bool ClearPendingVtStep(DWORD pid, DWORD tid)
{
    const std::uint64_t key = PrivateEventKey(pid, tid);
    AcquireSRWLockExclusive(&g_vt_step_lock);
    const auto found = g_pending_vt_steps.find(key);
    if (found == g_pending_vt_steps.end()) {
        ReleaseSRWLockExclusive(&g_vt_step_lock);
        return true;
    }

    const PendingVtStep step = found->second;
    if (!SendVtStep(
            IOCTL_HV_BRIDGE_STEP_CLEAR,
            step.Pid,
            step.Tid,
            step.Address)) {
        const DWORD error = GetLastError();
        ReleaseSRWLockExclusive(&g_vt_step_lock);
        SetLastError(error);
        return false;
    }
    if (!ReleaseVtStepGate(step)) {
        const DWORD error = GetLastError();
        ReleaseSRWLockExclusive(&g_vt_step_lock);
        SetLastError(error);
        return false;
    }
    g_pending_vt_steps.erase(found);
    ReleaseSRWLockExclusive(&g_vt_step_lock);
    return true;
}

void ClearTargetVtSteps(DWORD pid)
{
    std::vector<std::uint64_t> keys;
    AcquireSRWLockShared(&g_vt_step_lock);
    keys.reserve(g_pending_vt_steps.size());
    for (const auto& item : g_pending_vt_steps) {
        if (pid == 0 || item.second.Pid == pid) keys.push_back(item.first);
    }
    ReleaseSRWLockShared(&g_vt_step_lock);

    for (const std::uint64_t key : keys) {
        const DWORD step_pid = static_cast<DWORD>(key >> 32);
        const DWORD step_tid = static_cast<DWORD>(key);
        if (!ClearPendingVtStep(step_pid, step_tid)) {
            Trace(L"[VT-STEP] cleanup failed pid=%lu tid=%lu win32=%lu\n",
                  step_pid, step_tid, GetLastError());
        }
    }
}

void ForgetTargetVtSteps(DWORD pid)
{
    AcquireSRWLockExclusive(&g_vt_step_lock);
    for (auto step = g_pending_vt_steps.begin();
         step != g_pending_vt_steps.end();) {
        if (pid == 0 || step->second.Pid == pid) {
            step = g_pending_vt_steps.erase(step);
        } else {
            ++step;
        }
    }
    ReleaseSRWLockExclusive(&g_vt_step_lock);
    AcquireSRWLockExclusive(&g_suppress_ss_lock);
    for (auto it = g_suppress_native_single_step.begin();
         it != g_suppress_native_single_step.end();) {
        const DWORD step_pid = static_cast<DWORD>(it->first >> 32);
        if (pid == 0 || step_pid == pid) {
            it = g_suppress_native_single_step.erase(it);
        } else {
            ++it;
        }
    }
    ReleaseSRWLockExclusive(&g_suppress_ss_lock);
}


bool ArmVtStep(
    DWORD pid,
    DWORD tid,
    std::uint64_t address)
{
    if ((g_granted_capabilities.load() & HV_BRIDGE_CAP_VT_STEP) == 0) {
        SetLastError(ERROR_NOT_SUPPORTED);
        return false;
    }
    if (!ClearPendingVtStep(pid, tid)) return false;

    bool owns_gate = false;
    if (!InstallVtStepGate(pid, address, &owns_gate)) return false;
    if (!SendVtStep(IOCTL_HV_BRIDGE_STEP_ARM, pid, tid, address)) {
        const DWORD error = GetLastError();
        PendingVtStep rollback = {};
        rollback.Pid = pid;
        rollback.Tid = tid;
        rollback.Address = address;
        rollback.OwnsSwBpGate = owns_gate;
        (void)ReleaseVtStepGate(rollback);
        SetLastError(error);
        return false;
    }

    PendingVtStep step = {};
    step.Pid = pid;
    step.Tid = tid;
    step.Address = address;
    step.OwnsSwBpGate = owns_gate;
    AcquireSRWLockExclusive(&g_vt_step_lock);
    g_pending_vt_steps[PrivateEventKey(pid, tid)] = step;
    ReleaseSRWLockExclusive(&g_vt_step_lock);
    Trace(L"[VT-STEP] armed pid=%lu tid=%lu rip=0x%llX swbp_gate=%d\n",
          pid, tid, static_cast<unsigned long long>(address), owns_gate);
    return true;
}

TargetAddressClass ClassifyStepAddress(
    DWORD pid,
    std::uint64_t address)
{
    HANDLE process = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!process) {
        process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    }
    if (!process) return TargetAddressClass::Unknown;
    const TargetAddressClass result = ClassifyTargetAddress(
        process,
        pid,
        reinterpret_cast<LPCVOID>(static_cast<ULONG_PTR>(address)),
        1);
    CloseHandle(process);
    return result;
}

bool ResolvePrivateEventThread(HV_BRIDGE_PRIVATE_EVENT* event)
{
    if (!event || event->ProcessId == 0 || event->ThreadToken == 0) {
        SetLastError(ERROR_INVALID_DATA);
        return false;
    }
    if (event->ThreadId != 0) return true;

    const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return false;

    bool resolved = false;
    THREADENTRY32 entry = {};
    entry.dwSize = sizeof(entry);
    if (Thread32First(snapshot, &entry)) {
        do {
            if (entry.th32OwnerProcessID != event->ProcessId) continue;

            HV_BRIDGE_THREAD_RESOLVE_REQUEST request = {};
            request.Version = HV_BRIDGE_PROTOCOL_VERSION;
            request.ProcessId = event->ProcessId;
            request.ThreadId = entry.th32ThreadID;
            request.ThreadToken = event->ThreadToken;
            HV_BRIDGE_THREAD_RESOLVE_RESULT result = {};
            DWORD returned = 0;
            const BOOL ok = DeviceIoControl(
                g_device,
                IOCTL_HV_BRIDGE_RESOLVE_THREAD,
                &request,
                sizeof(request),
                &result,
                sizeof(result),
                &returned,
                nullptr);
            if (ok && returned >= sizeof(result) &&
                IsNtSuccess(result.Status) &&
                result.ThreadId == entry.th32ThreadID &&
                result.ThreadToken == event->ThreadToken) {
                event->ThreadId = result.ThreadId;
                resolved = true;
                break;
            }
        } while (Thread32Next(snapshot, &entry));
    }
    CloseHandle(snapshot);
    if (!resolved) SetLastError(ERROR_NOT_FOUND);
    return resolved;
}

enum class PrivatePollResult {
    Event,
    Empty,
    Error
};

PrivatePollResult PollPrivateEvent(HV_BRIDGE_PRIVATE_EVENT* event)
{
    if (!event || g_device == INVALID_HANDLE_VALUE) {
        SetLastError(event ? ERROR_INVALID_HANDLE : ERROR_INVALID_PARAMETER);
        return PrivatePollResult::Error;
    }

    HV_BRIDGE_PRIVATE_WAIT_REQUEST request = {};
    request.Version = HV_BRIDGE_PROTOCOL_VERSION;
    request.TimeoutMs = 0;
    HV_BRIDGE_PRIVATE_WAIT_RESULT result = {};
    DWORD returned = 0;
    const BOOL ok = DeviceIoControl(
        g_device, IOCTL_HV_BRIDGE_WAIT_EVENT,
        &request, sizeof(request), &result, sizeof(result), &returned, nullptr);
    const DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    if (!ok || returned < sizeof(result)) {
        SetLastError(error != ERROR_SUCCESS ? error : ERROR_INVALID_DATA);
        return PrivatePollResult::Error;
    }
    if (result.Status == static_cast<LONG>(HV_BRIDGE_STATUS_NOT_FOUND)) {
        return PrivatePollResult::Empty;
    }
    if (result.Status != static_cast<LONG>(HV_BRIDGE_STATUS_SUCCESS) ||
        result.Event.Sequence == 0 || result.Event.ProcessId == 0 ||
        (result.Event.ThreadId == 0 && result.Event.ThreadToken == 0)) {
        SetLastError(ERROR_INVALID_DATA);
        return PrivatePollResult::Error;
    }

    if (result.Event.ThreadId == 0 &&
        !ResolvePrivateEventThread(&result.Event)) {
        // Preserve the event token so the discard path can fail-open the
        // stalled root breakpoint even when Toolhelp cannot resolve a TID.
        Trace(L"[PRIVATE] thread-token resolution failed pid=%lu token=0x%llX seq=%llu win32=%lu\n",
              result.Event.ProcessId,
              static_cast<unsigned long long>(result.Event.ThreadToken),
              static_cast<unsigned long long>(result.Event.Sequence),
              GetLastError());
    }

    *event = result.Event;
    return PrivatePollResult::Event;
}

bool ContinuePrivateEvent(
    const HV_BRIDGE_PRIVATE_EVENT& event,
    DWORD continue_status)
{
    HV_BRIDGE_PRIVATE_CONTINUE_REQUEST request = {};
    request.Version = HV_BRIDGE_PROTOCOL_VERSION;
    request.ContinueStatus = continue_status;
    request.Sequence = event.Sequence;
    request.ProcessId = event.ProcessId;
    request.ThreadId = event.ThreadId;
    request.ThreadToken = event.ThreadToken;

    HV_BRIDGE_OPERATION_RESULT result = {};
    DWORD returned = 0;
    const BOOL ok = DeviceIoControl(
        g_device, IOCTL_HV_BRIDGE_CONTINUE_EVENT,
        &request, sizeof(request), &result, sizeof(result), &returned, nullptr);
    const DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    if (!ok || returned < sizeof(result)) {
        SetLastError(error != ERROR_SUCCESS ? error : ERROR_INVALID_DATA);
        return false;
    }
    if (result.Status != HV_BRIDGE_STATUS_SUCCESS) {
        // VT STEP completion is ring-only; there is no HitPending SWBP entry
        // for Continue to consume. Treat NOT_FOUND as soft success for STEP.
        if (event.Kind == HV_BRIDGE_PRIVATE_EVENT_STEP &&
            result.Status == HV_BRIDGE_STATUS_NOT_FOUND) {
            return true;
        }
        SetLastError(result.Status == HV_BRIDGE_STATUS_NOT_FOUND
            ? ERROR_NOT_FOUND : ERROR_INVALID_PARAMETER);
        return false;
    }
    return true;
}

enum class PrivateDbgkPollResult {
    Event,
    Empty,
    Error,
    Terminal
};

bool IsPrivateDbgkTerminalNtStatus(LONG status)
{
    const ULONG code = static_cast<ULONG>(status);
    return code == 0xC0000354UL || // STATUS_DEBUGGER_INACTIVE
           code == 0xC0000353UL || // STATUS_PROCESS_IS_TERMINATING
           code == 0xC0000022UL || // STATUS_ACCESS_DENIED
           code == 0xC0000008UL;   // STATUS_INVALID_HANDLE
}

DWORD MapPrivateDbgkTerminalWin32(LONG status)
{
    if (g_rtl_nt_status_to_dos_error) {
        const ULONG mapped = g_rtl_nt_status_to_dos_error(status);
        if (mapped != ERROR_MR_MID_NOT_FOUND && mapped != ERROR_SUCCESS) {
            return static_cast<DWORD>(mapped);
        }
    }
    switch (static_cast<ULONG>(status)) {
    case 0xC0000354UL: // STATUS_DEBUGGER_INACTIVE
    case 0xC0000008UL: // STATUS_INVALID_HANDLE
        return ERROR_INVALID_HANDLE;
    case 0xC0000353UL: // STATUS_PROCESS_IS_TERMINATING
    case 0xC0000022UL: // STATUS_ACCESS_DENIED
    default:
        return ERROR_ACCESS_DENIED;
    }
}

// Forward decls: defined later; used only on private Dbgk fail-closed path.
void ReleasePendingPrivateEvents(DWORD pid);
void ReleasePendingPrivateDbgkEvents(DWORD pid);

void FailClosedPrivateDbgkTransport(LONG status)
{
    const bool first = !g_private_dbgk_transport_dead.exchange(true);
    g_private_dbgk_terminal_status.store(status);
    const DWORD win32 = MapPrivateDbgkTerminalWin32(status);

    if (first) {
        Trace(L"[DBGK-WAIT] private transport terminal status=0x%08lX win32=%lu 鈥?fail-closed cleanup\n",
              static_cast<unsigned long>(status), win32);

        // Driver session is already inactive/tearing. Do not thrash CLEAR
        // IOCTLs; drop local VT-step bookkeeping and pending private maps so
        // the external wait path can exit without spinning.
        std::vector<DWORD> targets;
        AcquireSRWLockShared(&g_target_lock);
        targets.assign(g_targets.begin(), g_targets.end());
        ReleaseSRWLockShared(&g_target_lock);
        for (const DWORD pid : targets) {
            ForgetTargetVtSteps(pid);
            ReleasePendingPrivateDbgkEvents(pid);
            ReleasePendingPrivateEvents(pid);
        }
        ForgetTargetVtSteps(0);
        ReleasePendingPrivateDbgkEvents(0);
        ReleasePendingPrivateEvents(0);
    }

    SetLastError(win32);
}

PrivateDbgkPollResult PollPrivateDbgkEvent(
    HV_BRIDGE_DBGK_EVENT* event,
    DWORD timeout)
{
    if (!event || g_device == INVALID_HANDLE_VALUE) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return PrivateDbgkPollResult::Error;
    }
    if (g_private_dbgk_transport_dead.load()) {
        SetLastError(MapPrivateDbgkTerminalWin32(
            g_private_dbgk_terminal_status.load()));
        return PrivateDbgkPollResult::Terminal;
    }

    HV_BRIDGE_PRIVATE_WAIT_REQUEST request = {};
    request.Version = HV_BRIDGE_PROTOCOL_VERSION;
    request.TimeoutMs = timeout;
    HV_BRIDGE_DBGK_WAIT_RESULT result = {};
    DWORD returned = 0;
    const BOOL ok = DeviceIoControl(
        g_device, IOCTL_HV_BRIDGE_DBGK_WAIT,
        &request, sizeof(request), &result, sizeof(result), &returned, nullptr);
    const DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    if (!ok || returned < sizeof(result)) {
        const auto sequence = g_private_dbgk_poll_error_sequence.fetch_add(1) + 1;
        if (sequence <= 8 || (sequence & (sequence - 1)) == 0) {
            Trace(L"[DBGK-WAIT #%llu] ioctl failed ok=%d returned=%lu win32=%lu\n",
                  sequence, ok, returned,
                  error != ERROR_SUCCESS ? error : ERROR_INVALID_DATA);
        }
        // Channel hard-fail after the private session is gone: treat access /
        // invalid-handle style IOCTL errors as terminal so wait does not spin.
        if (error == ERROR_ACCESS_DENIED || error == ERROR_INVALID_HANDLE ||
            error == ERROR_NOT_FOUND || error == ERROR_INVALID_FUNCTION) {
            FailClosedPrivateDbgkTransport(
                error == ERROR_INVALID_HANDLE
                    ? static_cast<LONG>(0xC0000008L)
                    : static_cast<LONG>(0xC0000022L));
            return PrivateDbgkPollResult::Terminal;
        }
        SetLastError(error != ERROR_SUCCESS ? error : ERROR_INVALID_DATA);
        return PrivateDbgkPollResult::Error;
    }
    if (result.Status == static_cast<LONG>(0x00000102L)) {
        return PrivateDbgkPollResult::Empty;
    }
    if (IsPrivateDbgkTerminalNtStatus(result.Status)) {
        const auto sequence = g_private_dbgk_poll_error_sequence.fetch_add(1) + 1;
        if (sequence <= 4 || (sequence & (sequence - 1)) == 0) {
            Trace(L"[DBGK-WAIT #%llu] terminal status=0x%08lX event_seq=%llu pid=%lu tid=%lu\n",
                  sequence, static_cast<unsigned long>(result.Status),
                  static_cast<unsigned long long>(result.Event.Sequence),
                  result.Event.ProcessId, result.Event.ThreadId);
        }
        FailClosedPrivateDbgkTransport(result.Status);
        return PrivateDbgkPollResult::Terminal;
    }
    if (result.Status < 0 || result.Event.Sequence == 0 ||
        result.Event.ProcessId == 0 || result.Event.ThreadId == 0) {
        const auto sequence = g_private_dbgk_poll_error_sequence.fetch_add(1) + 1;
        if (sequence <= 8 || (sequence & (sequence - 1)) == 0) {
            Trace(L"[DBGK-WAIT #%llu] invalid result status=0x%08lX event_seq=%llu pid=%lu tid=%lu\n",
                  sequence, static_cast<unsigned long>(result.Status),
                  static_cast<unsigned long long>(result.Event.Sequence),
                  result.Event.ProcessId, result.Event.ThreadId);
        }
        if (result.Status < 0) {
            SetLastErrorFromNtStatus(result.Status);
        } else {
            SetLastError(ERROR_INVALID_DATA);
        }
        return PrivateDbgkPollResult::Error;
    }
    *event = result.Event;
    return PrivateDbgkPollResult::Event;
}

bool ContinuePrivateDbgkEvent(
    const HV_BRIDGE_DBGK_EVENT& event,
    DWORD continue_status)
{
    HV_BRIDGE_DBGK_CONTINUE_REQUEST request = {};
    request.Version = HV_BRIDGE_PROTOCOL_VERSION;
    request.ContinueStatus = continue_status;
    request.Sequence = event.Sequence;
    request.ProcessId = event.ProcessId;
    request.ThreadId = event.ThreadId;
    HV_BRIDGE_OPERATION_RESULT result = {};
    DWORD returned = 0;
    const BOOL ok = DeviceIoControl(
        g_device, IOCTL_HV_BRIDGE_DBGK_CONTINUE,
        &request, sizeof(request), &result, sizeof(result), &returned, nullptr);
    const DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    if (!ok || returned < sizeof(result) ||
        result.Status != HV_BRIDGE_STATUS_SUCCESS) {
        SetLastError(error != ERROR_SUCCESS ? error : ERROR_INVALID_PARAMETER);
        return false;
    }
    return true;
}

std::uint64_t ResolvePrivateDbgkThreadStartAddress(
    const HV_BRIDGE_DBGK_EVENT& source)
{
    if (source.StartAddress != 0) return source.StartAddress;
    if (!g_nt_query_information_thread || source.ThreadHandle == 0) return 0;

    // ThreadQuerySetWin32StartAddress is the value used by the native Dbgk
    // CREATE_THREAD message.  The private producer currently cannot read the
    // version-dependent ETHREAD.Win32StartAddress field directly.
    constexpr ULONG thread_query_win32_start_address = 9;
    PVOID start_address = nullptr;
    const LONG status = g_nt_query_information_thread(
        reinterpret_cast<HANDLE>(
            static_cast<ULONG_PTR>(source.ThreadHandle)),
        thread_query_win32_start_address,
        &start_address,
        static_cast<ULONG>(sizeof(start_address)),
        nullptr);
    const std::uint64_t resolved = status >= 0
        ? static_cast<std::uint64_t>(
            reinterpret_cast<ULONG_PTR>(start_address))
        : 0;
    Trace(L"[DBGK-THREAD-START] pid=%lu tid=%lu source=0x%llX resolved=0x%llX status=0x%08lX\n",
          source.ProcessId, source.ThreadId,
          static_cast<unsigned long long>(source.StartAddress),
          static_cast<unsigned long long>(resolved),
          static_cast<unsigned long>(status));
    return resolved;
}

void RememberPrivateDbgkInitialThread(DWORD pid, DWORD tid)
{
    AcquireSRWLockExclusive(&g_private_event_lock);
    g_private_initial_threads[pid] = tid;
    ReleaseSRWLockExclusive(&g_private_event_lock);
}

bool ConsumeDuplicatePrivateDbgkInitialThread(DWORD pid, DWORD tid)
{
    bool duplicate = false;
    AcquireSRWLockExclusive(&g_private_event_lock);
    const auto initial = g_private_initial_threads.find(pid);
    if (initial != g_private_initial_threads.end() && initial->second == tid) {
        g_private_initial_threads.erase(initial);
        duplicate = true;
    }
    ReleaseSRWLockExclusive(&g_private_event_lock);
    return duplicate;
}

bool ConvertPrivateDbgkEvent(
    const HV_BRIDGE_DBGK_EVENT& source,
    LPDEBUG_EVENT target)
{
    if (!target) return false;
    ZeroMemory(target, sizeof(*target));
    target->dwProcessId = source.ProcessId;
    target->dwThreadId = source.ThreadId;
    switch (source.State) {
    case HV_BRIDGE_DBGK_CREATE_PROCESS:
        target->dwDebugEventCode = CREATE_PROCESS_DEBUG_EVENT;
        target->u.CreateProcessInfo.hFile =
            reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(source.FileHandle));
        target->u.CreateProcessInfo.hProcess =
            reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(source.ProcessHandle));
        target->u.CreateProcessInfo.hThread =
            reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(source.ThreadHandle));
        target->u.CreateProcessInfo.lpBaseOfImage =
            reinterpret_cast<LPVOID>(static_cast<ULONG_PTR>(source.BaseAddress));
        target->u.CreateProcessInfo.lpStartAddress =
            reinterpret_cast<LPTHREAD_START_ROUTINE>(static_cast<ULONG_PTR>(source.StartAddress));
        break;
    case HV_BRIDGE_DBGK_CREATE_THREAD:
        target->dwDebugEventCode = CREATE_THREAD_DEBUG_EVENT;
        target->u.CreateThread.hThread =
            reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(source.ThreadHandle));
        target->u.CreateThread.lpStartAddress =
            reinterpret_cast<LPTHREAD_START_ROUTINE>(static_cast<ULONG_PTR>(
                ResolvePrivateDbgkThreadStartAddress(source)));
        break;
    case HV_BRIDGE_DBGK_EXIT_THREAD:
        target->dwDebugEventCode = EXIT_THREAD_DEBUG_EVENT;
        target->u.ExitThread.dwExitCode = static_cast<DWORD>(source.ExitStatus);
        break;
    case HV_BRIDGE_DBGK_EXIT_PROCESS:
        target->dwDebugEventCode = EXIT_PROCESS_DEBUG_EVENT;
        target->u.ExitProcess.dwExitCode = static_cast<DWORD>(source.ExitStatus);
        break;
    case HV_BRIDGE_DBGK_EXCEPTION:
    case HV_BRIDGE_DBGK_BREAKPOINT:
    case HV_BRIDGE_DBGK_SINGLE_STEP:
        target->dwDebugEventCode = EXCEPTION_DEBUG_EVENT;
        target->u.Exception.dwFirstChance = source.FirstChance;
        target->u.Exception.ExceptionRecord.ExceptionCode = source.ExceptionCode;
        target->u.Exception.ExceptionRecord.ExceptionFlags = source.ExceptionFlags;
        target->u.Exception.ExceptionRecord.ExceptionAddress =
            reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(source.ExceptionAddress));
        target->u.Exception.ExceptionRecord.NumberParameters =
            std::min<ULONG>(source.NumberParameters, EXCEPTION_MAXIMUM_PARAMETERS);
        memcpy(target->u.Exception.ExceptionRecord.ExceptionInformation,
               source.ExceptionInformation,
               target->u.Exception.ExceptionRecord.NumberParameters * sizeof(ULONG_PTR));
        break;
    case HV_BRIDGE_DBGK_LOAD_DLL:
        target->dwDebugEventCode = LOAD_DLL_DEBUG_EVENT;
        target->u.LoadDll.hFile =
            reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(source.FileHandle));
        target->u.LoadDll.lpBaseOfDll =
            reinterpret_cast<LPVOID>(static_cast<ULONG_PTR>(source.BaseAddress));
        break;
    case HV_BRIDGE_DBGK_UNLOAD_DLL:
        target->dwDebugEventCode = UNLOAD_DLL_DEBUG_EVENT;
        target->u.UnloadDll.lpBaseOfDll =
            reinterpret_cast<LPVOID>(static_cast<ULONG_PTR>(source.BaseAddress));
        break;
    default:
        SetLastError(ERROR_INVALID_DATA);
        return false;
    }
    return true;
}

PrivateDbgkPollResult DeliverPrivateDbgkEvent(
    LPDEBUG_EVENT debug_event,
    DWORD timeout)
{
    HV_BRIDGE_DBGK_EVENT source = {};
    for (;;) {
        const PrivateDbgkPollResult poll_result =
            PollPrivateDbgkEvent(&source, timeout);
        if (poll_result != PrivateDbgkPollResult::Event) {
            return poll_result;
        }
        if (source.State != HV_BRIDGE_DBGK_CREATE_THREAD ||
            !ConsumeDuplicatePrivateDbgkInitialThread(
                source.ProcessId, source.ThreadId)) {
            break;
        }

        const bool continued =
            ContinuePrivateDbgkEvent(source, DBG_CONTINUE);
        const DWORD continue_error = continued
            ? ERROR_SUCCESS : GetLastError();
        if (source.ThreadHandle != 0) {
            CloseHandle(reinterpret_cast<HANDLE>(
                static_cast<ULONG_PTR>(source.ThreadHandle)));
        }
        Trace(L"[DBGK-WAIT] suppressed duplicate initial thread seq=%llu pid=%lu tid=%lu continued=%d win32=%lu\n",
              static_cast<unsigned long long>(source.Sequence),
              source.ProcessId, source.ThreadId,
              continued, continue_error);
        if (!continued) {
            SetLastError(continue_error);
            return PrivateDbgkPollResult::Error;
        }
        source = {};
    }
    if (!ConvertPrivateDbgkEvent(source, debug_event)) {
        const DWORD error = GetLastError();
        (void)ContinuePrivateDbgkEvent(source, DBG_CONTINUE);
        SetLastError(error);
        return PrivateDbgkPollResult::Error;
    }
    if (source.State == HV_BRIDGE_DBGK_CREATE_PROCESS) {
        RememberPrivateDbgkInitialThread(
            source.ProcessId, source.ThreadId);
    }
    PendingPrivateDbgkEvent pending = {};
    pending.Sequence = source.Sequence;
    pending.State = source.State;
    pending.Process = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(source.ProcessHandle));
    pending.Thread = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(source.ThreadHandle));
    AcquireSRWLockExclusive(&g_private_event_lock);
    g_pending_private_dbgk_events[PrivateEventKey(source.ProcessId, source.ThreadId)] = pending;
    ReleaseSRWLockExclusive(&g_private_event_lock);
    Trace(L"[DBGK-WAIT] delivered seq=%llu state=%lu pid=%lu tid=%lu process=%p thread=%p\n",
          static_cast<unsigned long long>(source.Sequence), source.State,
          source.ProcessId, source.ThreadId, pending.Process, pending.Thread);
    ObserveDebugEvent(debug_event);
    return PrivateDbgkPollResult::Event;
}

bool ClearTargetSoftwareBreakpoints(DWORD pid)
{
    std::vector<std::uint64_t> addresses;
    AcquireSRWLockShared(&g_swbp_lock);
    const auto process = g_sw_breakpoints.find(pid);
    if (process != g_sw_breakpoints.end()) {
        addresses.reserve(process->second.size());
        for (const auto& breakpoint : process->second) {
            addresses.push_back(breakpoint.first);
        }
    }
    ReleaseSRWLockShared(&g_swbp_lock);

    bool all_removed = true;
    for (const auto address : addresses) {
        if (SendSoftwareBreakpoint(IOCTL_HV_BRIDGE_SWBP_DEL, pid, address)) {
            AcquireSRWLockExclusive(&g_swbp_lock);
            const auto current_process = g_sw_breakpoints.find(pid);
            if (current_process != g_sw_breakpoints.end()) {
                current_process->second.erase(address);
                if (current_process->second.empty()) {
                    g_sw_breakpoints.erase(current_process);
                }
            }
            ReleaseSRWLockExclusive(&g_swbp_lock);
        } else {
            all_removed = false;
            Trace(L"[SWBP] cleanup failed pid=%lu address=0x%llX win32=%lu\n",
                  pid, static_cast<unsigned long long>(address), GetLastError());
        }
    }
    return all_removed;
}

void ForgetTargetSoftwareBreakpoints(DWORD pid)
{
    AcquireSRWLockExclusive(&g_swbp_lock);
    g_sw_breakpoints.erase(pid);
    ReleaseSRWLockExclusive(&g_swbp_lock);
}

bool DetectWow64Target(DWORD pid, bool* wow64)
{
    if (!wow64 || pid == 0) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return false;
    }
    *wow64 = false;
#ifdef _WIN64
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process) return false;
    BOOL value = FALSE;
    const BOOL ok = IsWow64Process(process, &value);
    const DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    CloseHandle(process);
    if (!ok) {
        SetLastError(error);
        return false;
    }
    *wow64 = value != FALSE;
#endif
    return true;
}

bool PreparePrivateBreakpointContext(
    DWORD pid,
    DWORD tid,
    PendingPrivateEvent* pending)
{
    if (!pending || !pending->Thread || pending->BreakpointAddress == UINT64_MAX) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return false;
    }

    bool wow64 = false;
#ifdef _WIN64
    if (pending->BreakpointAddress <= MAXDWORD &&
        !DetectWow64Target(pid, &wow64)) {
        return false;
    }
    if (wow64) {
        if (!g_wow64_get_thread_context || !g_wow64_set_thread_context ||
            pending->BreakpointAddress > MAXDWORD) {
            SetLastError(ERROR_NOT_SUPPORTED);
            return false;
        }
        WOW64_CONTEXT context = {};
        context.ContextFlags = WOW64_CONTEXT_CONTROL;
        if (!g_wow64_get_thread_context(pending->Thread, &context)) return false;
        const DWORD address = static_cast<DWORD>(pending->BreakpointAddress);
        if (context.Eip != address && context.Eip != address + 1u) {
            Trace(L"[PRIVATE] INT3 context mismatch pid=%lu tid=%lu bp=0x%llX eip=0x%08lX wow64=1\n",
                  pid, tid,
                  static_cast<unsigned long long>(pending->BreakpointAddress),
                  context.Eip);
            SetLastError(ERROR_INVALID_ADDRESS);
            return false;
        }
        if (context.Eip == address) {
            context.Eip = address + 1u;
            if (!g_wow64_set_thread_context(pending->Thread, &context)) return false;
        }
    } else
#endif
    {
        CONTEXT context = {};
        context.ContextFlags = CONTEXT_CONTROL;
        if (!g_get_thread_context(pending->Thread, &context)) return false;
#ifdef _WIN64
        const std::uint64_t ip = context.Rip;
#else
        const std::uint64_t ip = context.Eip;
#endif
        if (ip != pending->BreakpointAddress &&
            ip != pending->BreakpointAddress + 1u) {
            Trace(L"[PRIVATE] INT3 context mismatch pid=%lu tid=%lu bp=0x%llX ip=0x%llX wow64=0\n",
                  pid, tid,
                  static_cast<unsigned long long>(pending->BreakpointAddress),
                  static_cast<unsigned long long>(ip));
            SetLastError(ERROR_INVALID_ADDRESS);
            return false;
        }
        if (ip == pending->BreakpointAddress) {
#ifdef _WIN64
            context.Rip = pending->BreakpointAddress + 1u;
#else
            context.Eip = static_cast<DWORD>(pending->BreakpointAddress + 1u);
#endif
            if (!g_set_thread_context(pending->Thread, &context)) return false;
        }
    }

    pending->ContextRipAdvanced = true;
    pending->Wow64Context = wow64;
    Trace(L"[PRIVATE] emulated INT3 context pid=%lu tid=%lu bp=0x%llX visible_ip=0x%llX wow64=%d\n",
          pid, tid,
          static_cast<unsigned long long>(pending->BreakpointAddress),
          static_cast<unsigned long long>(pending->BreakpointAddress + 1u),
          wow64);
    return true;
}

void NormalizePrivateBreakpointContext(
    DWORD pid,
    DWORD tid,
    const PendingPrivateEvent& pending,
    const wchar_t* reason)
{
    if (!pending.ContextRipAdvanced || !pending.Thread) return;

    std::uint64_t ip = 0;
    bool restored = false;
#ifdef _WIN64
    if (pending.Wow64Context) {
        if (!g_wow64_get_thread_context || !g_wow64_set_thread_context ||
            pending.BreakpointAddress > MAXDWORD) {
            return;
        }
        WOW64_CONTEXT context = {};
        context.ContextFlags = WOW64_CONTEXT_CONTROL;
        if (!g_wow64_get_thread_context(pending.Thread, &context)) return;
        ip = context.Eip;
        if (ip == pending.BreakpointAddress + 1u) {
            context.Eip = static_cast<DWORD>(pending.BreakpointAddress);
            restored = g_wow64_set_thread_context(pending.Thread, &context) != FALSE;
        }
    } else
#endif
    {
        CONTEXT context = {};
        context.ContextFlags = CONTEXT_CONTROL;
        if (!g_get_thread_context(pending.Thread, &context)) return;
#ifdef _WIN64
        ip = context.Rip;
#else
        ip = context.Eip;
#endif
        if (ip == pending.BreakpointAddress + 1u) {
#ifdef _WIN64
            context.Rip = pending.BreakpointAddress;
#else
            context.Eip = static_cast<DWORD>(pending.BreakpointAddress);
#endif
            restored = g_set_thread_context(pending.Thread, &context) != FALSE;
        }
    }

    if (ip == pending.BreakpointAddress + 1u) {
        Trace(L"[PRIVATE] INT3 fallback normalize pid=%lu tid=%lu bp=0x%llX reason=%s restored=%d win32=%lu\n",
              pid, tid,
              static_cast<unsigned long long>(pending.BreakpointAddress),
              reason ? reason : L"unknown", restored,
              restored ? ERROR_SUCCESS : GetLastError());
    } else {
        Trace(L"[PRIVATE] INT3 debugger context pid=%lu tid=%lu bp=0x%llX ip=0x%llX reason=%s\n",
              pid, tid,
              static_cast<unsigned long long>(pending.BreakpointAddress),
              static_cast<unsigned long long>(ip),
              reason ? reason : L"unknown");
    }
}

void ReleasePendingPrivateEvents(DWORD pid)
{
    struct ReleasedEvent {
        std::uint64_t Key;
        PendingPrivateEvent Pending;
    };
    std::vector<ReleasedEvent> released;

    AcquireSRWLockExclusive(&g_private_event_lock);
    for (auto pending = g_pending_private_events.begin();
         pending != g_pending_private_events.end();) {
        const DWORD pending_pid = static_cast<DWORD>(pending->first >> 32);
        if (pid != 0 && pending_pid != pid) {
            ++pending;
            continue;
        }
        released.push_back({pending->first, pending->second});
        pending = g_pending_private_events.erase(pending);
    }
    ReleaseSRWLockExclusive(&g_private_event_lock);

    for (const auto& item : released) {
        const DWORD event_pid = static_cast<DWORD>(item.Key >> 32);
        const DWORD event_tid = static_cast<DWORD>(item.Key);
        NormalizePrivateBreakpointContext(
            event_pid, event_tid, item.Pending, L"cleanup");
        if (!item.Pending.DriverContinued) {
            HV_BRIDGE_PRIVATE_EVENT private_event = {};
            private_event.Sequence = item.Pending.Sequence;
            private_event.ProcessId = event_pid;
            private_event.ThreadId = event_tid;
            if (!ContinuePrivateEvent(private_event, DBG_CONTINUE)) {
                Trace(L"[PRIVATE] cleanup continue failed pid=%lu tid=%lu seq=%llu win32=%lu\n",
                      event_pid, event_tid,
                      static_cast<unsigned long long>(item.Pending.Sequence),
                      GetLastError());
            }
        }
        if (item.Pending.Thread) {
            const DWORD previous = ResumeThread(item.Pending.Thread);
            if (previous == static_cast<DWORD>(-1)) {
                Trace(L"[PRIVATE] cleanup resume failed pid=%lu tid=%lu seq=%llu win32=%lu\n",
                      event_pid, event_tid,
                      static_cast<unsigned long long>(item.Pending.Sequence),
                      GetLastError());
            }
            CloseHandle(item.Pending.Thread);
        }
    }
}

void ReleasePendingPrivateDbgkEvents(DWORD pid)
{
    struct ReleasedEvent {
        std::uint64_t Key;
        PendingPrivateDbgkEvent Pending;
        bool ResumeLaunch;
    };
    std::vector<ReleasedEvent> released;
    std::vector<DWORD> launch_threads;
    AcquireSRWLockExclusive(&g_private_event_lock);
    for (auto pending = g_pending_private_dbgk_events.begin();
         pending != g_pending_private_dbgk_events.end();) {
        const DWORD pending_pid = static_cast<DWORD>(pending->first >> 32);
        if (pid != 0 && pending_pid != pid) {
            ++pending;
            continue;
        }
        const bool resume_launch =
            pending->second.State == HV_BRIDGE_DBGK_CREATE_PROCESS &&
            g_private_launches.erase(pending_pid) != 0;
        released.push_back({pending->first, pending->second, resume_launch});
        pending = g_pending_private_dbgk_events.erase(pending);
    }
    for (auto launch = g_private_launches.begin();
         launch != g_private_launches.end();) {
        if (pid != 0 && launch->first != pid) {
            ++launch;
            continue;
        }
        launch_threads.push_back(launch->second);
        launch = g_private_launches.erase(launch);
    }
    for (auto initial = g_private_initial_threads.begin();
         initial != g_private_initial_threads.end();) {
        if (pid != 0 && initial->first != pid) {
            ++initial;
            continue;
        }
        initial = g_private_initial_threads.erase(initial);
    }
    ReleaseSRWLockExclusive(&g_private_event_lock);

    for (const auto& item : released) {
        HV_BRIDGE_DBGK_EVENT event = {};
        event.Sequence = item.Pending.Sequence;
        event.ProcessId = static_cast<DWORD>(item.Key >> 32);
        event.ThreadId = static_cast<DWORD>(item.Key);
        event.State = item.Pending.State;
        (void)ContinuePrivateDbgkEvent(event, DBG_CONTINUE);
        if (item.ResumeLaunch && item.Pending.Thread) {
            (void)ResumeThread(item.Pending.Thread);
        }
        if (item.Pending.Process) CloseHandle(item.Pending.Process);
        if (item.Pending.Thread) CloseHandle(item.Pending.Thread);
    }
    for (const DWORD tid : launch_threads) {
        HANDLE thread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, tid);
        if (thread) {
            (void)ResumeThread(thread);
            CloseHandle(thread);
        }
    }
}

bool SendHardwareBreakpoint(
    DWORD code,
    DWORD target_pid,
    ULONG slot,
    std::uint64_t address,
    UCHAR length,
    UCHAR type)
{
    const ULONG capabilities = g_granted_capabilities.load();
    ULONG policy = 0;
    if (capabilities & HV_BRIDGE_CAP_VT_HWBP) {
        policy |= HV_BRIDGE_HWBP_ALLOW_VT;
    }
    if (capabilities & HV_BRIDGE_CAP_DR_HWBP_FALLBACK) {
        policy |= HV_BRIDGE_HWBP_ALLOW_DR;
    }
    if (policy == 0) {
        SetLastError(ERROR_NOT_SUPPORTED);
        return false;
    }

    HV_BRIDGE_HWBP_REQUEST request = {};
    request.DebuggerPid = GetCurrentProcessId();
    request.TargetPid = target_pid;
    request.SlotIndex = slot;
    request.Reserved0 = policy;
    request.Address = address;
    request.Length = length;
    request.Type = type;

    HV_BRIDGE_OPERATION_RESULT result = {};
    DWORD returned = 0;
    const BOOL ok = DeviceIoControl(
        g_device, code, &request, sizeof(request),
        &result, sizeof(result), &returned, nullptr);
    if (!ok || returned < sizeof(result)) return false;
    if (result.Status == HV_BRIDGE_STATUS_SUCCESS) {
        Trace(L"[HWBP] ioctl=0x%08X target=%lu slot=%lu policy=0x%X mode=%llu\n",
              code, target_pid, slot, policy,
              static_cast<unsigned long long>(result.Info));
        return true;
    }
    if (code == IOCTL_HV_BRIDGE_CLEAR_HWBP &&
        result.Status == HV_BRIDGE_STATUS_NOT_FOUND) {
        return true;
    }
    SetLastError(result.Status == HV_BRIDGE_STATUS_NOT_FOUND
        ? ERROR_NOT_FOUND : ERROR_INVALID_PARAMETER);
    return false;
}

UCHAR DecodeBreakpointLength(std::uint64_t dr7, ULONG slot, UCHAR type)
{
    if (type == 0) return 1;
    switch ((dr7 >> (18 + slot * 4)) & 3ULL) {
    case 0: return 1;
    case 1: return 2;
    case 2: return 8;
    default: return 4;
    }
}

bool ApplyHardwareState(DWORD pid, const VirtualDebugState& state)
{
    for (ULONG slot = 0; slot < 4; slot++) {
        const bool enabled = ((state.Dr7 >> (slot * 2)) & 3ULL) != 0;
        if (!enabled) {
            if (!SendHardwareBreakpoint(IOCTL_HV_BRIDGE_CLEAR_HWBP,
                                        pid, slot, 0, 0, 0)) {
                return false;
            }
            continue;
        }

        const UCHAR type = static_cast<UCHAR>((state.Dr7 >> (16 + slot * 4)) & 3ULL);
        const UCHAR length = DecodeBreakpointLength(state.Dr7, slot, type);
        if (!SendHardwareBreakpoint(IOCTL_HV_BRIDGE_SET_HWBP,
                                    pid, slot, state.Dr[slot], length, type)) {
            return false;
        }
    }
    return true;
}

void ClearTargetBreakpoints(DWORD pid)
{
    const DWORD saved_error = GetLastError();
    AcquireSRWLockExclusive(&g_debug_state_lock);
    g_debug_states.erase(pid);
    ReleaseSRWLockExclusive(&g_debug_state_lock);
    ClearTargetSoftwareBreakpoints(pid);
    for (ULONG slot = 0; slot < 4; slot++) {
        (void)SendHardwareBreakpoint(
            IOCTL_HV_BRIDGE_CLEAR_HWBP, pid, slot, 0, 0, 0);
    }
    SetLastError(saved_error);
}

bool BindTarget(DWORD pid, DWORD bind_flags = 0)
{
    AcquireSRWLockExclusive(&g_target_lock);
    if (g_stop.load()) {
        ReleaseSRWLockExclusive(&g_target_lock);
        SetLastError(ERROR_OPERATION_ABORTED);
        return false;
    }
    const bool was_tracked = g_targets.find(pid) != g_targets.end();
    if (was_tracked) {
        ReleaseSRWLockExclusive(&g_target_lock);
        return true;
    }
    const bool ok = SendTargetIoctl(
        IOCTL_HV_BRIDGE_BIND_TARGET, pid, bind_flags);
    if (ok) {
        g_targets.insert(pid);
        // A successful bind means the private Dbgk session is live again for
        // this target; clear any previous fail-closed transport state.
        g_private_dbgk_transport_dead.store(false);
        g_private_dbgk_terminal_status.store(0);
    }
    ReleaseSRWLockExclusive(&g_target_lock);
    if (!ok) return false;
    if (!was_tracked) Trace(L"[NetrBridge] bound target PID=%lu\n", pid);
    return true;
}

bool ScrubTargetPeb(DWORD pid)
{
    if ((g_granted_capabilities.load() & HV_BRIDGE_CAP_PEB_SCRUB) == 0) {
        SetLastError(ERROR_NOT_SUPPORTED);
        return false;
    }

    AcquireSRWLockShared(&g_target_lock);
    const bool bound = g_targets.find(pid) != g_targets.end();
    const bool already_scrubbed =
        g_scrubbed_targets.find(pid) != g_scrubbed_targets.end();
    ReleaseSRWLockShared(&g_target_lock);

    if (!bound) return false;
    if (already_scrubbed) return true;

    const bool ok = SendTargetIoctl(
        IOCTL_HV_BRIDGE_SCRUB_PEB,
        pid,
        HV_BRIDGE_PEB_CLOAK_ACTIVATE);
    if (ok) {
        AcquireSRWLockExclusive(&g_target_lock);
        if (g_targets.find(pid) != g_targets.end()) {
            g_scrubbed_targets.insert(pid);
        }
        ReleaseSRWLockExclusive(&g_target_lock);
        Trace(L"[NetrBridge] scrubbed target PEB after initial breakpoint PID=%lu\n",
              pid);
    }
    return ok;
}

bool DriverProtectMemory(
    DWORD pid,
    LPVOID address,
    SIZE_T size,
    DWORD protection,
    PDWORD old_protection)
{
    if ((g_granted_capabilities.load() &
         HV_BRIDGE_CAP_OS_MEMORY_PROTECT) == 0) {
        SetLastError(ERROR_NOT_SUPPORTED);
        return false;
    }

    if (g_device == INVALID_HANDLE_VALUE || !address || size == 0 ||
        !old_protection) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return false;
    }

    HV_BRIDGE_PROTECT_REQUEST request = {};
    request.ProcessId = pid;
    request.NewProtection = protection;
    request.Address = reinterpret_cast<ULONG_PTR>(address);
    request.Size = static_cast<ULONG64>(size);

    HV_BRIDGE_PROTECT_RESULT result = {};
    DWORD returned = 0;
    const BOOL ok = DeviceIoControl(
        g_device, IOCTL_HV_BRIDGE_MEMORY_PROTECT,
        &request, sizeof(request), &result, sizeof(result), &returned, nullptr);
    const DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    Trace(L"[PROTECT] pid=%lu address=%p size=%llu new=0x%08lX ok=%d returned=%lu win32=%lu status=0x%08X old=0x%08lX\n",
          pid, address, static_cast<unsigned long long>(size), protection,
          ok, returned, error, static_cast<unsigned long>(result.Status),
          result.OldProtection);
    if (!ok || returned < sizeof(result)) {
        SetLastError(error != ERROR_SUCCESS ? error : ERROR_INVALID_DATA);
        return false;
    }
    if (!IsNtSuccess(result.Status)) {
        SetLastErrorFromNtStatus(result.Status);
        return false;
    }

    *old_protection = result.OldProtection;
    return true;
}

bool UnbindTarget(DWORD pid)
{
    AcquireSRWLockExclusive(&g_target_lock);
    ReleasePendingPrivateEvents(pid);
    ReleasePendingPrivateDbgkEvents(pid);
    ClearTargetVtSteps(pid);
    ClearTargetBreakpoints(pid);
    const bool ok = SendTargetIoctl(IOCTL_HV_BRIDGE_UNBIND_TARGET, pid);
    if (ok) {
        // The driver-side unbind performs an authoritative debugger+target
        // vwatch cleanup, so any local entries left by an earlier DEL failure
        // are now safe to forget.
        ForgetTargetSoftwareBreakpoints(pid);
        ForgetTargetVtSteps(pid);
        g_targets.erase(pid);
        g_scrubbed_targets.erase(pid);
    }
    ReleaseSRWLockExclusive(&g_target_lock);
    if (ok) Trace(L"[NetrBridge] unbound target PID=%lu\n", pid);
    return ok;
}

void CleanupBridgeState()
{
    if (g_cleanup_started.exchange(true)) return;
    g_stop.store(true);

    for (;;) {
        DWORD pid = 0;
        AcquireSRWLockShared(&g_target_lock);
        if (!g_targets.empty()) pid = *g_targets.begin();
        ReleaseSRWLockShared(&g_target_lock);
        if (!pid) break;
        if (!UnbindTarget(pid)) break;
    }

    AcquireSRWLockExclusive(&g_target_lock);
    ReleasePendingPrivateEvents(0);
    ReleasePendingPrivateDbgkEvents(0);
    ReleaseSRWLockExclusive(&g_target_lock);
    ClearTargetVtSteps(0);
    std::vector<DWORD> remaining_swbp_pids;
    AcquireSRWLockShared(&g_swbp_lock);
    remaining_swbp_pids.reserve(g_sw_breakpoints.size());
    for (const auto& process : g_sw_breakpoints) {
        remaining_swbp_pids.push_back(process.first);
    }
    ReleaseSRWLockShared(&g_swbp_lock);
    for (DWORD pid : remaining_swbp_pids) {
        (void)ClearTargetSoftwareBreakpoints(pid);
    }

    AcquireSRWLockExclusive(&g_debug_state_lock);
    g_debug_states.clear();
    ReleaseSRWLockExclusive(&g_debug_state_lock);
    ForgetTargetVtSteps(0);
    AcquireSRWLockExclusive(&g_target_lock);
    g_targets.clear();
    g_scrubbed_targets.clear();
    ReleaseSRWLockExclusive(&g_target_lock);
    if (g_device != INVALID_HANDLE_VALUE) {
        CloseHandle(g_device);
        g_device = INVALID_HANDLE_VALUE;
    }
    if (g_ready_event) {
        CloseHandle(g_ready_event);
        g_ready_event = nullptr;
    }
    if (g_commit_event) {
        CloseHandle(g_commit_event);
        g_commit_event = nullptr;
    }
    if (g_committed_event) {
        CloseHandle(g_committed_event);
        g_committed_event = nullptr;
    }
    if (g_abort_event) {
        CloseHandle(g_abort_event);
        g_abort_event = nullptr;
    }
}

void ObserveDebugEvent(const DEBUG_EVENT* event)
{
    if (!event || event->dwProcessId == 0) return;
    const auto sequence = g_event_sequence.fetch_add(1) + 1;
    if (event->dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
        const auto& exception = event->u.Exception;
        const ULONG_PTR info0 = exception.ExceptionRecord.NumberParameters > 0
            ? exception.ExceptionRecord.ExceptionInformation[0] : 0;
        const ULONG_PTR info1 = exception.ExceptionRecord.NumberParameters > 1
            ? exception.ExceptionRecord.ExceptionInformation[1] : 0;
        if (sequence <= 512) {
            Trace(L"[EVENT #%llu] exception pid=%lu tid=%lu code=0x%08X first=%lu flags=0x%08X address=%p params=%lu info0=0x%llX info1=0x%llX\n",
                  sequence, event->dwProcessId, event->dwThreadId,
                  exception.ExceptionRecord.ExceptionCode,
                  exception.dwFirstChance,
                  exception.ExceptionRecord.ExceptionFlags,
                  exception.ExceptionRecord.ExceptionAddress,
                  exception.ExceptionRecord.NumberParameters,
                  static_cast<unsigned long long>(info0),
                  static_cast<unsigned long long>(info1));
        }
    } else if (sequence <= 512) {
        Trace(L"[EVENT #%llu] code=%lu pid=%lu tid=%lu\n",
              sequence, event->dwDebugEventCode,
              event->dwProcessId, event->dwThreadId);
    }
    if (event->dwDebugEventCode == EXCEPTION_DEBUG_EVENT &&
        event->u.Exception.ExceptionRecord.ExceptionCode ==
            EXCEPTION_SINGLE_STEP &&
        LookupPendingVtStep(
            event->dwProcessId, event->dwThreadId, nullptr)) {
        const bool cleared = ClearPendingVtStep(
            event->dwProcessId, event->dwThreadId);
        Trace(L"[VT-STEP] completed pid=%lu tid=%lu cleared=%d win32=%lu\n",
              event->dwProcessId, event->dwThreadId,
              cleared, cleared ? ERROR_SUCCESS : GetLastError());
    }
    if (event->dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
        UnbindTarget(event->dwProcessId);
    } else if (BindTarget(event->dwProcessId) &&
               event->dwDebugEventCode == EXCEPTION_DEBUG_EVENT &&
               event->u.Exception.ExceptionRecord.ExceptionCode ==
                   EXCEPTION_BREAKPOINT) {
        (void)ScrubTargetPeb(event->dwProcessId);
    }
}

enum class PrivateDeliveryResult {
    Delivered,
    Empty,
    Skipped,
    Error
};

using PreparePrivateEventContextFn = bool(*)(
    DWORD pid,
    DWORD tid,
    PendingPrivateEvent* pending);

PrivateDeliveryResult TryDeliverPrivateEventCore(
    LPDEBUG_EVENT debug_event,
    DWORD thread_access,
    PreparePrivateEventContextFn prepare_context,
    const wchar_t* route)
{
    HV_BRIDGE_PRIVATE_EVENT private_event = {};
    const PrivatePollResult poll = PollPrivateEvent(&private_event);
    if (poll == PrivatePollResult::Empty) return PrivateDeliveryResult::Empty;
    if (poll == PrivatePollResult::Error) return PrivateDeliveryResult::Error;

    const auto acknowledge_discarded = [&]() {
        if (!ContinuePrivateEvent(private_event, DBG_CONTINUE)) {
            Trace(L"[PRIVATE] discard ack failed pid=%lu tid=%lu seq=%llu win32=%lu\n",
                  private_event.ProcessId, private_event.ThreadId,
                  static_cast<unsigned long long>(private_event.Sequence),
                  GetLastError());
        }
    };

    const bool is_swbp =
        private_event.Kind == HV_BRIDGE_PRIVATE_EVENT_SWBP;
    const bool is_step =
        private_event.Kind == HV_BRIDGE_PRIVATE_EVENT_STEP;
    if (!debug_event || g_stop.load() ||
        (!is_swbp && !is_step) ||
        private_event.ThreadId == 0 ||
        private_event.Rip > static_cast<std::uint64_t>(UINTPTR_MAX)) {
        Trace(L"[PRIVATE] discarded kind=%lu pid=%lu tid=%lu rip=0x%llX seq=%llu\n",
              private_event.Kind, private_event.ProcessId,
              private_event.ThreadId,
              static_cast<unsigned long long>(private_event.Rip),
              static_cast<unsigned long long>(private_event.Sequence));
        acknowledge_discarded();
        return PrivateDeliveryResult::Skipped;
    }

    // Late STEP after inject #DB already completed the stop and cleared the
    // pending VT step receiver. Soft-continue and discard the duplicate so
    // external debuggers do not see a second free-run stop.
    if (is_step &&
        !LookupPendingVtStep(
            private_event.ProcessId, private_event.ThreadId, nullptr)) {
        Trace(L"[VT-STEP] discarded late STEP route=%s pid=%lu tid=%lu "
              L"rip=0x%llX seq=%llu\n",
              route ? route : L"unknown",
              private_event.ProcessId,
              private_event.ThreadId,
              static_cast<unsigned long long>(private_event.Rip),
              static_cast<unsigned long long>(private_event.Sequence));
        acknowledge_discarded();
        return PrivateDeliveryResult::Skipped;
    }

    // Secondary safety only: if a gate SWBP still arrives while a VT step is
    // armed at the same RIP, continue it without delivering a user BP.  The
    // real stop must come from HV_BRIDGE_PRIVATE_EVENT_STEP.
    if (is_swbp) {
        PendingVtStep pending_step = {};
        if (LookupPendingVtStep(
                private_event.ProcessId,
                private_event.ThreadId,
                &pending_step) &&
            pending_step.Address == private_event.Rip) {
            Trace(L"[VT-STEP] suppressed gate SWBP route=%s pid=%lu tid=%lu "
                  L"rip=0x%llX seq=%llu owns_gate=%d\n",
                  route ? route : L"unknown",
                  private_event.ProcessId,
                  private_event.ThreadId,
                  static_cast<unsigned long long>(private_event.Rip),
                  static_cast<unsigned long long>(private_event.Sequence),
                  pending_step.OwnsSwBpGate ? 1 : 0);
            if (!ContinuePrivateEvent(private_event, DBG_CONTINUE)) {
                const DWORD cont_error = GetLastError();
                Trace(L"[VT-STEP] gate SWBP continue failed route=%s "
                      L"pid=%lu tid=%lu seq=%llu win32=%lu\n",
                      route ? route : L"unknown",
                      private_event.ProcessId,
                      private_event.ThreadId,
                      static_cast<unsigned long long>(private_event.Sequence),
                      cont_error);
                SetLastError(cont_error);
                return PrivateDeliveryResult::Error;
            }
            return PrivateDeliveryResult::Skipped;
        }
    }

    const std::uint64_t key = PrivateEventKey(
        private_event.ProcessId, private_event.ThreadId);
    AcquireSRWLockShared(&g_target_lock);
    if (g_stop.load() ||
        g_targets.find(private_event.ProcessId) == g_targets.end()) {
        ReleaseSRWLockShared(&g_target_lock);
        Trace(L"[PRIVATE] discarded unbound pid=%lu tid=%lu seq=%llu\n",
              private_event.ProcessId, private_event.ThreadId,
              static_cast<unsigned long long>(private_event.Sequence));
        acknowledge_discarded();
        return PrivateDeliveryResult::Skipped;
    }

    AcquireSRWLockExclusive(&g_private_event_lock);
    if (g_pending_private_events.find(key) != g_pending_private_events.end()) {
        ReleaseSRWLockExclusive(&g_private_event_lock);
        ReleaseSRWLockShared(&g_target_lock);
        Trace(L"[PRIVATE] duplicate pending event pid=%lu tid=%lu seq=%llu\n",
              private_event.ProcessId, private_event.ThreadId,
              static_cast<unsigned long long>(private_event.Sequence));
        acknowledge_discarded();
        return PrivateDeliveryResult::Skipped;
    }

    HANDLE thread = OpenThread(thread_access, FALSE, private_event.ThreadId);
    if (!thread || GetProcessIdOfThread(thread) != private_event.ProcessId) {
        const DWORD error = thread ? ERROR_INVALID_OWNER : GetLastError();
        if (thread) CloseHandle(thread);
        ReleaseSRWLockExclusive(&g_private_event_lock);
        ReleaseSRWLockShared(&g_target_lock);
        Trace(L"[PRIVATE] OpenThread failed pid=%lu tid=%lu seq=%llu win32=%lu\n",
              private_event.ProcessId, private_event.ThreadId,
              static_cast<unsigned long long>(private_event.Sequence), error);
        acknowledge_discarded();
        SetLastError(error);
        return PrivateDeliveryResult::Skipped;
    }

    DWORD pending_error = ERROR_SUCCESS;
    try {
        PendingPrivateEvent pending = {};
        pending.Sequence = private_event.Sequence;
        pending.BreakpointAddress = private_event.Rip;
        pending.Thread = thread;
        pending.Kind = private_event.Kind;
        if (!g_pending_private_events.emplace(key, pending).second) {
            pending_error = ERROR_BUSY;
        }
    } catch (...) {
        pending_error = ERROR_NOT_ENOUGH_MEMORY;
    }
    if (pending_error != ERROR_SUCCESS) {
        ReleaseSRWLockExclusive(&g_private_event_lock);
        ReleaseSRWLockShared(&g_target_lock);
        CloseHandle(thread);
        Trace(L"[PRIVATE] pending reservation failed pid=%lu tid=%lu seq=%llu win32=%lu\n",
              private_event.ProcessId, private_event.ThreadId,
              static_cast<unsigned long long>(private_event.Sequence),
              pending_error);
        acknowledge_discarded();
        SetLastError(pending_error);
        return PrivateDeliveryResult::Skipped;
    }

    const DWORD previous_suspend_count = SuspendThread(thread);
    if (previous_suspend_count == static_cast<DWORD>(-1)) {
        const DWORD error = GetLastError();
        g_pending_private_events.erase(key);
        ReleaseSRWLockExclusive(&g_private_event_lock);
        ReleaseSRWLockShared(&g_target_lock);
        CloseHandle(thread);
        Trace(L"[PRIVATE] SuspendThread failed pid=%lu tid=%lu seq=%llu win32=%lu\n",
              private_event.ProcessId, private_event.ThreadId,
              static_cast<unsigned long long>(private_event.Sequence), error);
        acknowledge_discarded();
        SetLastError(error);
        return PrivateDeliveryResult::Skipped;
    }
    auto pending_context = g_pending_private_events.find(key);
    // STEP is reported after the instruction already executed.  Never apply
    // the INT3 RIP+1 emulator used for private SWBP delivery.
    const PreparePrivateEventContextFn context_fn =
        is_step ? nullptr : prepare_context;
    if (pending_context == g_pending_private_events.end() ||
        (context_fn && !context_fn(
            private_event.ProcessId,
            private_event.ThreadId,
            &pending_context->second))) {
        const DWORD context_error = GetLastError();
        g_pending_private_events.erase(key);
        ReleaseSRWLockExclusive(&g_private_event_lock);
        ReleaseSRWLockShared(&g_target_lock);
        acknowledge_discarded();
        const DWORD previous = ResumeThread(thread);
        if (previous == static_cast<DWORD>(-1)) {
            Trace(L"[PRIVATE] context failure resume failed pid=%lu tid=%lu seq=%llu win32=%lu\n",
                  private_event.ProcessId, private_event.ThreadId,
                  static_cast<unsigned long long>(private_event.Sequence),
                  GetLastError());
        }
        CloseHandle(thread);
        Trace(L"[PRIVATE] INT3 context preparation failed pid=%lu tid=%lu rip=0x%llX seq=%llu win32=%lu\n",
              private_event.ProcessId, private_event.ThreadId,
              static_cast<unsigned long long>(private_event.Rip),
              static_cast<unsigned long long>(private_event.Sequence),
              context_error);
        SetLastError(context_error);
        return PrivateDeliveryResult::Skipped;
    }
    ReleaseSRWLockExclusive(&g_private_event_lock);
    ReleaseSRWLockShared(&g_target_lock);

    ZeroMemory(debug_event, sizeof(*debug_event));
    debug_event->dwDebugEventCode = EXCEPTION_DEBUG_EVENT;
    debug_event->dwProcessId = private_event.ProcessId;
    debug_event->dwThreadId = private_event.ThreadId;
    debug_event->u.Exception.ExceptionRecord.ExceptionCode =
        is_step ? EXCEPTION_SINGLE_STEP : EXCEPTION_BREAKPOINT;
    debug_event->u.Exception.ExceptionRecord.ExceptionAddress =
        reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(private_event.Rip));
    debug_event->u.Exception.ExceptionRecord.NumberParameters =
        is_step ? 0 : 1;
    debug_event->u.Exception.ExceptionRecord.ExceptionInformation[0] = 0;
    debug_event->u.Exception.dwFirstChance = TRUE;

    Trace(L"[PRIVATE] delivered %s route=%s pid=%lu tid=%lu rip=0x%llX seq=%llu previous_suspend=%lu\n",
          is_step ? L"STEP" : L"SWBP",
          route ? route : L"unknown",
          private_event.ProcessId, private_event.ThreadId,
          static_cast<unsigned long long>(private_event.Rip),
          static_cast<unsigned long long>(private_event.Sequence),
          previous_suspend_count);
    ObserveDebugEvent(debug_event);
    if (is_step) {
        // Dual-notify inject #DB may still surface a native SINGLE_STEP.
        // Suppress that second stop so x64dbg / external waiters do not free-run.
        ArmNativeSingleStepSuppress(
            private_event.ProcessId, private_event.ThreadId);
    }
    return PrivateDeliveryResult::Delivered;
}

PrivateDeliveryResult TryDeliverPrivateDbgkSwBpEvent(
    LPDEBUG_EVENT debug_event)
{
    return TryDeliverPrivateEventCore(
        debug_event,
        THREAD_SUSPEND_RESUME | THREAD_QUERY_LIMITED_INFORMATION,
        nullptr,
        L"private-dbgk");
}

PrivateDeliveryResult TryDeliverNativePrivateSwBpEvent(
    LPDEBUG_EVENT debug_event)
{
    return TryDeliverPrivateEventCore(
        debug_event,
        THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
            THREAD_QUERY_LIMITED_INFORMATION,
        &PreparePrivateBreakpointContext,
        L"native-debug-object");
}

bool IsWaitTimeoutError(DWORD error)
{
    return error == ERROR_SUCCESS || error == ERROR_SEM_TIMEOUT ||
           error == ERROR_TIMEOUT || error == WAIT_TIMEOUT;
}

BOOL WaitForMergedDebugEvent(
    WaitForDebugEventFn native_wait,
    LPDEBUG_EVENT event,
    DWORD timeout)
{
    if (g_private_dbgk_mode.load()) {
        if (!native_wait) {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return FALSE;
        }
        if (!event) {
            return native_wait(event, timeout);
        }

        // Keep the sequence-bearing private Dbgk transport authoritative for
        // external debuggers.  NtWaitForDebugEvent/NtDebugContinue cannot
        // preserve the driver's exact event sequence and previously made VT
        // single-step completion timing-dependent.  A bounded blocking IOCTL
        // avoids the old 1 ms hot poll while still draining the separate
        // no-signal VT software-breakpoint ring.
        constexpr DWORD private_wait_slice_ms = 50;
        const ULONGLONG started = GetTickCount64();
        for (;;) {
            if (TryDeliverPrivateDbgkSwBpEvent(event) ==
                    PrivateDeliveryResult::Delivered) {
                return TRUE;
            }

            DWORD slice = timeout == 0 ? 0 : private_wait_slice_ms;
            if (timeout != INFINITE && timeout != 0) {
                const ULONGLONG elapsed = GetTickCount64() - started;
                if (elapsed >= timeout) {
                    SetLastError(ERROR_SEM_TIMEOUT);
                    return FALSE;
                }
                slice = std::min<DWORD>(slice,
                    static_cast<DWORD>(timeout - elapsed));
            }

            const PrivateDbgkPollResult dbgk_result =
                DeliverPrivateDbgkEvent(event, slice);
            if (dbgk_result == PrivateDbgkPollResult::Event) {
                return TRUE;
            }
            const DWORD dbgk_error = GetLastError();

            if (dbgk_result == PrivateDbgkPollResult::Terminal) {
                // Private Dbgk session / target is gone. Do not fall back to
                // native WaitForDebugEvent (no Windows DebugObject in this
                // mode) and do not keep re-polling: that is the x64dbg hang.
                SetLastError(dbgk_error != ERROR_SUCCESS
                    ? dbgk_error : ERROR_INVALID_HANDLE);
                return FALSE;
            }

            if (TryDeliverPrivateDbgkSwBpEvent(event) ==
                    PrivateDeliveryResult::Delivered) {
                return TRUE;
            }
            if (dbgk_result == PrivateDbgkPollResult::Error) {
                // Compatibility fallback for a package whose direct Dbgk
                // IOCTL is unavailable but whose syscall hook is installed.
                // Never used for terminal session statuses (handled above).
                const BOOL native_ok = native_wait(event, 0);
                if (native_ok) {
                    if (ConsumeNativeDebugEvent(event)) {
                        return TRUE;
                    }
                    continue;
                }
                SetLastError(dbgk_error);
                return FALSE;
            }
            if (timeout == 0) {
                SetLastError(ERROR_SEM_TIMEOUT);
                return FALSE;
            }
        }
    }
    if (!native_wait) {
        SetLastError(ERROR_PROC_NOT_FOUND);
        return FALSE;
    }
    if (!event) return native_wait(event, timeout);

    AcquireSRWLockShared(&g_private_event_lock);
    const bool private_event_pending = !g_pending_private_events.empty();
    ReleaseSRWLockShared(&g_private_event_lock);
    if (private_event_pending) {
        SetLastError(ERROR_BUSY);
        return FALSE;
    }

    constexpr DWORD private_poll_slice_ms = 1;
    const ULONGLONG started = GetTickCount64();
    DWORD native_error = ERROR_SEM_TIMEOUT;

    for (;;) {
        const BOOL native_ok = native_wait(event, 0);
        native_error = native_ok ? ERROR_SUCCESS : GetLastError();
        if (native_ok) {
            if (ConsumeNativeDebugEvent(event)) {
                return TRUE;
            }
            continue;
        }

        const PrivateDeliveryResult private_result =
            TryDeliverNativePrivateSwBpEvent(event);
        if (private_result == PrivateDeliveryResult::Delivered) return TRUE;
        if (!IsWaitTimeoutError(native_error)) {
            SetLastError(native_error);
            return FALSE;
        }
        if (timeout == 0) {
            SetLastError(native_error == ERROR_SUCCESS
                ? ERROR_SEM_TIMEOUT : native_error);
            return FALSE;
        }

        DWORD slice = private_poll_slice_ms;
        if (timeout != INFINITE) {
            const ULONGLONG elapsed = GetTickCount64() - started;
            if (elapsed >= timeout) {
                SetLastError(ERROR_SEM_TIMEOUT);
                return FALSE;
            }
            slice = std::min<DWORD>(
                slice, static_cast<DWORD>(timeout - elapsed));
        }

        const BOOL waited_ok = native_wait(event, slice);
        native_error = waited_ok ? ERROR_SUCCESS : GetLastError();
        if (waited_ok) {
            if (ConsumeNativeDebugEvent(event)) {
                return TRUE;
            }
            continue;
        }

        const PrivateDeliveryResult waited_private_result =
            TryDeliverNativePrivateSwBpEvent(event);
        if (waited_private_result == PrivateDeliveryResult::Delivered) {
            return TRUE;
        }
        if (!IsWaitTimeoutError(native_error)) {
            SetLastError(native_error);
            return FALSE;
        }
    }
}

bool DriverReadMemory(
    DWORD pid,
    LPCVOID address,
    LPVOID buffer,
    SIZE_T size,
    SIZE_T* transferred)
{
    if ((g_granted_capabilities.load() & HV_BRIDGE_CAP_MEMORY_IO) == 0) {
        if (transferred) *transferred = 0;
        SetLastError(ERROR_NOT_SUPPORTED);
        return false;
    }

    const auto sequence = g_read_sequence.fetch_add(1) + 1;
    SIZE_T total = 0;
    if (transferred) *transferred = 0;
    if (size == 0) return true;
    if (!buffer || !address) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return false;
    }

    while (total < size) {
        const ULONG chunk = static_cast<ULONG>(std::min<SIZE_T>(
            size - total, HV_BRIDGE_MEMORY_MAX_PAYLOAD));
        HV_BRIDGE_MEMORY_REQUEST request = {};
        request.ProcessId = pid;
        request.Address = reinterpret_cast<ULONG_PTR>(address) + total;
        request.Size = chunk;

        std::vector<unsigned char> output(sizeof(HV_BRIDGE_MEMORY_RESULT) + chunk);
        DWORD returned = 0;
        const BOOL ioctl_ok = DeviceIoControl(
                g_device, IOCTL_HV_BRIDGE_MEMORY_READ,
                &request, sizeof(request), output.data(),
                static_cast<DWORD>(output.size()), &returned, nullptr);
        const DWORD ioctl_error = ioctl_ok ? ERROR_SUCCESS : GetLastError();
        if (!ioctl_ok || returned < sizeof(HV_BRIDGE_MEMORY_RESULT)) {
            Trace(L"[READ #%llu] IOCTL failed pid=%lu addr=%p chunk=%lu total=%llu ok=%d returned=%lu win32=%lu\n",
                  sequence, pid,
                  static_cast<const unsigned char*>(address) + total,
                  chunk, static_cast<unsigned long long>(total),
                  ioctl_ok, returned, ioctl_error);
            if (transferred) *transferred = total;
            SetLastError(ioctl_error != ERROR_SUCCESS
                ? ioctl_error : ERROR_INVALID_DATA);
            return false;
        }

        const auto* result = reinterpret_cast<const HV_BRIDGE_MEMORY_RESULT*>(
            output.data());
        const ULONG copied = std::min(result->BytesTransferred, chunk);
        if (sequence <= 256 || !IsNtSuccess(result->Status) || copied != chunk) {
            Trace(L"[READ #%llu] result pid=%lu addr=%p chunk=%lu total=%llu status=0x%08X copied=%lu stage=%lu(%s) detail=0x%08X returned=%lu\n",
                  sequence, pid,
                  static_cast<const unsigned char*>(address) + total,
                  chunk, static_cast<unsigned long long>(total),
                  static_cast<unsigned long>(result->Status), copied,
                  result->Reserved0, CopyStageName(result->Reserved0),
                  result->Reserved1, returned);
        }
        if (copied != 0) {
            std::memcpy(static_cast<unsigned char*>(buffer) + total,
                        output.data() + sizeof(HV_BRIDGE_MEMORY_RESULT), copied);
            total += copied;
        }

        if (!IsNtSuccess(result->Status) || copied != chunk) {
            if (transferred) *transferred = total;
            if (!IsNtSuccess(result->Status)) {
                SetLastErrorFromNtStatus(result->Status);
            } else {
                SetLastError(ERROR_PARTIAL_COPY);
            }
            return false;
        }
    }

    if (transferred) *transferred = total;
    if (sequence <= 256) {
        Trace(L"[READ #%llu] complete pid=%lu addr=%p size=%llu transferred=%llu\n",
              sequence, pid, address,
              static_cast<unsigned long long>(size),
              static_cast<unsigned long long>(total));
    }
    return true;
}

bool DriverWriteMemory(
    DWORD pid,
    LPVOID address,
    LPCVOID buffer,
    SIZE_T size,
    SIZE_T* transferred)
{
    SIZE_T total = 0;
    const ULONG capabilities = g_granted_capabilities.load();
    const bool allow_cow =
        (capabilities & HV_BRIDGE_CAP_OS_COW_WRITE) != 0;
    const bool allow_vt_write =
        (capabilities & HV_BRIDGE_CAP_MEMORY_IO) != 0;
    if (transferred) *transferred = 0;
    if (size == 0) return true;
    if (!allow_cow && !allow_vt_write) {
        SetLastError(ERROR_NOT_SUPPORTED);
        return false;
    }
    if (!buffer || !address) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return false;
    }

    while (total < size) {
        const ULONG chunk = static_cast<ULONG>(std::min<SIZE_T>(
            size - total, HV_BRIDGE_MEMORY_MAX_PAYLOAD));
        std::vector<unsigned char> input(sizeof(HV_BRIDGE_MEMORY_REQUEST) + chunk);
        auto* request = reinterpret_cast<HV_BRIDGE_MEMORY_REQUEST*>(input.data());
        request->ProcessId = pid;
        request->Address = reinterpret_cast<ULONG_PTR>(address) + total;
        request->Size = chunk;
        std::memcpy(input.data() + sizeof(*request),
                    static_cast<const unsigned char*>(buffer) + total, chunk);

        HV_BRIDGE_MEMORY_RESULT result = {};
        DWORD returned = 0;
        const auto send_write = [&](DWORD code) {
            result = {};
            returned = 0;
            return DeviceIoControl(
                       g_device, code,
                       input.data(), static_cast<DWORD>(input.size()),
                       &result, sizeof(result), &returned, nullptr) &&
                   returned >= sizeof(result);
        };

        bool request_ok = allow_cow &&
            send_write(IOCTL_HV_BRIDGE_MEMORY_WRITE_COW);
        ULONG copied = request_ok
            ? std::min(result.BytesTransferred, chunk)
            : 0;
        if ((!request_ok || !IsNtSuccess(result.Status) || copied != chunk) &&
            allow_vt_write) {
            if (!send_write(IOCTL_HV_BRIDGE_MEMORY_WRITE)) {
                if (transferred) *transferred = total;
                return false;
            }
            copied = std::min(result.BytesTransferred, chunk);
        }

        total += copied;
        if (!IsNtSuccess(result.Status) || copied != chunk) {
            if (transferred) *transferred = total;
            if (!IsNtSuccess(result.Status)) {
                SetLastErrorFromNtStatus(result.Status);
            } else {
                SetLastError(ERROR_PARTIAL_COPY);
            }
            return false;
        }
    }

    if (transferred) *transferred = total;
    return true;
}

bool CaptureBytes(LPCVOID buffer, unsigned char* value, SIZE_T size)
{
    if (!buffer || !value || size == 0) return false;
    __try {
        std::memcpy(value, buffer, size);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool DetachPrivateBreakpointsInRange(
    DWORD pid,
    LPCVOID address,
    SIZE_T size)
{
    if (size <= 1) return true;
    if (!address) {
        SetLastError(ERROR_INVALID_ADDRESS);
        return false;
    }

    const std::uint64_t start = static_cast<std::uint64_t>(
        reinterpret_cast<ULONG_PTR>(address));
    if (size > static_cast<SIZE_T>(UINT64_MAX - start)) {
        SetLastError(ERROR_INVALID_ADDRESS);
        return false;
    }
    const std::uint64_t end = start + size;

    std::vector<std::uint64_t> overlapping;
    AcquireSRWLockExclusive(&g_swbp_lock);
    auto process = g_sw_breakpoints.find(pid);
    if (process != g_sw_breakpoints.end()) {
        overlapping.reserve(process->second.size());
        for (const auto& breakpoint : process->second) {
            if (breakpoint.first >= start && breakpoint.first < end) {
                overlapping.push_back(breakpoint.first);
            }
        }
    }

    for (const std::uint64_t breakpoint_address : overlapping) {
        if (!SendSoftwareBreakpoint(
                IOCTL_HV_BRIDGE_SWBP_DEL, pid, breakpoint_address)) {
            const DWORD error = GetLastError();
            ReleaseSRWLockExclusive(&g_swbp_lock);
            Trace(L"[SWBP] range detach failed pid=%lu address=0x%llX write=[0x%llX,+0x%llX) win32=%lu\n",
                  pid,
                  static_cast<unsigned long long>(breakpoint_address),
                  static_cast<unsigned long long>(start),
                  static_cast<unsigned long long>(size), error);
            SetLastError(error);
            return false;
        }
        if (process != g_sw_breakpoints.end()) {
            process->second.erase(breakpoint_address);
        }
    }
    if (process != g_sw_breakpoints.end() && process->second.empty()) {
        g_sw_breakpoints.erase(process);
    }
    ReleaseSRWLockExclusive(&g_swbp_lock);

    if (!overlapping.empty()) {
        Trace(L"[SWBP] detached %llu breakpoint(s) before range write pid=%lu address=%p size=%llu\n",
              static_cast<unsigned long long>(overlapping.size()),
              pid, address, static_cast<unsigned long long>(size));
    }
    return true;
}

bool HandleSoftwareBreakpointWrite(
    DWORD pid,
    LPVOID address,
    LPCVOID buffer,
    SIZE_T size,
    bool allow_new_private,
    bool force_native_route,
    SIZE_T* transferred,
    BOOL* operation_result)
{
    if (!operation_result) return false;
    if (size != 1) return false;

    unsigned char requested_byte = 0;
    if (!CaptureBytes(buffer, &requested_byte, sizeof(requested_byte))) {
        if (transferred) *transferred = 0;
        SetLastError(ERROR_NOACCESS);
        *operation_result = FALSE;
        return true;
    }

    const std::uint64_t breakpoint_address =
        static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(address));
    AcquireSRWLockExclusive(&g_swbp_lock);
    auto process = g_sw_breakpoints.find(pid);
    auto breakpoint = process == g_sw_breakpoints.end()
        ? std::unordered_map<std::uint64_t, SoftwareBreakpointState>::iterator{}
        : process->second.find(breakpoint_address);
    const bool registered = process != g_sw_breakpoints.end() &&
                            breakpoint != process->second.end();

    // A private breakpoint keeps its original route for its entire lifetime.
    // Consult this registry before reclassifying the address so a loader
    // change cannot turn a VT restore into a native write and orphan the EPT
    // shadow in the driver.
    if (registered) {
        const unsigned char original_byte = breakpoint->second.OriginalByte;
        if (force_native_route) {
            if (!SendSoftwareBreakpoint(
                    IOCTL_HV_BRIDGE_SWBP_DEL, pid, breakpoint_address)) {
                const DWORD error = GetLastError();
                ReleaseSRWLockExclusive(&g_swbp_lock);
                if (transferred) *transferred = 0;
                SetLastError(error);
                *operation_result = FALSE;
                return true;
            }
            process->second.erase(breakpoint);
            if (process->second.empty()) g_sw_breakpoints.erase(process);
            ReleaseSRWLockExclusive(&g_swbp_lock);
            Trace(L"[SWBP] detached stale route pid=%lu address=%p original=0x%02X\n",
                  pid, address, original_byte);
            return false;
        }

        if (requested_byte == 0xCC) {
            ReleaseSRWLockExclusive(&g_swbp_lock);
            if (transferred) *transferred = 1;
            *operation_result = TRUE;
            return true;
        }

        if (!SendSoftwareBreakpoint(
                IOCTL_HV_BRIDGE_SWBP_DEL, pid, breakpoint_address)) {
            const DWORD error = GetLastError();
            ReleaseSRWLockExclusive(&g_swbp_lock);
            if (transferred) *transferred = 0;
            SetLastError(error);
            *operation_result = FALSE;
            return true;
        }

        process->second.erase(breakpoint);
        if (process->second.empty()) g_sw_breakpoints.erase(process);
        ReleaseSRWLockExclusive(&g_swbp_lock);

        if (requested_byte == original_byte) {
            if (transferred) *transferred = 1;
            Trace(L"[SWBP] del pid=%lu address=%p original=0x%02X (restore write suppressed)\n",
                  pid, address, original_byte);
            *operation_result = TRUE;
            return true;
        }

        // This is a real one-byte code/data modification, not x64dbg's
        // breakpoint restore.  Remove the overlay first, then let the caller
        // perform the requested write instead of silently discarding it.
        Trace(L"[SWBP] detached before real write pid=%lu address=%p requested=0x%02X original=0x%02X\n",
              pid, address, requested_byte, original_byte);
        return false;
    }

    if (requested_byte != 0xCC) {
        ReleaseSRWLockExclusive(&g_swbp_lock);
        return false;
    }

    if (!allow_new_private ||
        (g_granted_capabilities.load() &
         HV_BRIDGE_CAP_PRIVATE_SWBP) == 0) {
        ReleaseSRWLockExclusive(&g_swbp_lock);
        // The caller will use native WriteProcessMemory for a breakpoint that
        // cannot safely be represented by the private execute overlay.
        return false;
    }

    unsigned char original_byte = 0;
    SIZE_T bytes_read = 0;
    if (!DriverReadMemory(
            pid, address, &original_byte, 1, &bytes_read) ||
        bytes_read != 1) {
        const DWORD error = GetLastError();
        ReleaseSRWLockExclusive(&g_swbp_lock);
        if (transferred) *transferred = 0;
        SetLastError(error);
        *operation_result = FALSE;
        return true;
    }
    bool original_is_int3 = original_byte == 0xCC;
    if (original_byte == 0xCD) {
        unsigned char trailing_byte = 0;
        if (breakpoint_address == static_cast<std::uint64_t>(UINTPTR_MAX) ||
            !DriverReadMemory(
                pid,
                reinterpret_cast<LPCVOID>(
                    static_cast<ULONG_PTR>(breakpoint_address + 1)),
                &trailing_byte, 1, &bytes_read) ||
            bytes_read != 1) {
            const DWORD error = breakpoint_address ==
                static_cast<std::uint64_t>(UINTPTR_MAX)
                ? ERROR_INVALID_ADDRESS : GetLastError();
            ReleaseSRWLockExclusive(&g_swbp_lock);
            if (transferred) *transferred = 0;
            SetLastError(error);
            *operation_result = FALSE;
            return true;
        }
        original_is_int3 = trailing_byte == 0x03;
    }
    if (original_is_int3) {
        ReleaseSRWLockExclusive(&g_swbp_lock);
        if (transferred) *transferred = 0;
        SetLastError(ERROR_NOT_SUPPORTED);
        *operation_result = FALSE;
        Trace(L"[SWBP] rejected existing INT3 pid=%lu address=%p original=0x%02X\n",
              pid, address, original_byte);
        return true;
    }
    if (!SendSoftwareBreakpoint(
            IOCTL_HV_BRIDGE_SWBP_ADD, pid, breakpoint_address)) {
        const DWORD error = GetLastError();
        ReleaseSRWLockExclusive(&g_swbp_lock);
        if (transferred) *transferred = 0;
        SetLastError(error);
        *operation_result = FALSE;
        return true;
    }

    SoftwareBreakpointState state = {};
    state.OriginalByte = original_byte;
    g_sw_breakpoints[pid][breakpoint_address] = state;
    ReleaseSRWLockExclusive(&g_swbp_lock);
    if (transferred) *transferred = 1;
    Trace(L"[SWBP] add pid=%lu address=%p original=0x%02X (physical write suppressed)\n",
          pid, address, original_byte);
    *operation_result = TRUE;
    return true;
}

bool LookupDebugState(DWORD pid, VirtualDebugState* state)
{
    AcquireSRWLockShared(&g_debug_state_lock);
    const auto found = g_debug_states.find(pid);
    const bool exists = found != g_debug_states.end();
    if (exists && state) *state = found->second;
    ReleaseSRWLockShared(&g_debug_state_lock);
    return exists;
}

bool CommitDebugState(DWORD pid, const VirtualDebugState& state)
{
    VirtualDebugState previous = {};
    const bool had_previous = LookupDebugState(pid, &previous);
    if (!ApplyHardwareState(pid, state)) {
        const DWORD error = GetLastError();
        if (had_previous) {
            (void)ApplyHardwareState(pid, previous);
        } else {
            VirtualDebugState empty = {};
            (void)ApplyHardwareState(pid, empty);
        }
        SetLastError(error);
        return false;
    }

    AcquireSRWLockExclusive(&g_debug_state_lock);
    g_debug_states[pid] = state;
    ReleaseSRWLockExclusive(&g_debug_state_lock);
    return true;
}

void* ReplacementForName(const char* name)
{
    if (!name || IS_INTRESOURCE(name)) return nullptr;
    if (strcmp(name, "NtDebugActiveProcess") == 0) return reinterpret_cast<void*>(&BridgeNtDebugActiveProcess);
    if (strcmp(name, "WaitForDebugEvent") == 0) return reinterpret_cast<void*>(&BridgeWaitForDebugEvent);
    if (strcmp(name, "WaitForDebugEventEx") == 0) return reinterpret_cast<void*>(&BridgeWaitForDebugEventEx);
    if (strcmp(name, "ContinueDebugEvent") == 0) return reinterpret_cast<void*>(&BridgeContinueDebugEvent);
    if (strcmp(name, "DebugActiveProcess") == 0) return reinterpret_cast<void*>(&BridgeDebugActiveProcess);
    if (strcmp(name, "DebugActiveProcessStop") == 0) return reinterpret_cast<void*>(&BridgeDebugActiveProcessStop);
    if (strcmp(name, "ReadProcessMemory") == 0) return reinterpret_cast<void*>(&BridgeReadProcessMemory);
    if (strcmp(name, "WriteProcessMemory") == 0) return reinterpret_cast<void*>(&BridgeWriteProcessMemory);
    if (strcmp(name, "VirtualProtectEx") == 0) return reinterpret_cast<void*>(&BridgeVirtualProtectEx);
    if (strcmp(name, "GetThreadContext") == 0) return reinterpret_cast<void*>(&BridgeGetThreadContext);
    if (strcmp(name, "SetThreadContext") == 0) return reinterpret_cast<void*>(&BridgeSetThreadContext);
#ifdef _WIN64
    if (strcmp(name, "Wow64GetThreadContext") == 0) return reinterpret_cast<void*>(&BridgeWow64GetThreadContext);
    if (strcmp(name, "Wow64SetThreadContext") == 0) return reinterpret_cast<void*>(&BridgeWow64SetThreadContext);
#endif
    if (strcmp(name, "CreateProcessW") == 0) return reinterpret_cast<void*>(&BridgeCreateProcessW);
    if (strcmp(name, "CreateProcessA") == 0) return reinterpret_cast<void*>(&BridgeCreateProcessA);
    return nullptr;
}

void* ReplacementForAddress(void* address)
{
    if (address == reinterpret_cast<void*>(g_nt_debug_active_process)) return reinterpret_cast<void*>(&BridgeNtDebugActiveProcess);
    if (address == reinterpret_cast<void*>(g_wait_for_debug_event)) return reinterpret_cast<void*>(&BridgeWaitForDebugEvent);
    if (address == reinterpret_cast<void*>(g_wait_for_debug_event_ex)) return reinterpret_cast<void*>(&BridgeWaitForDebugEventEx);
    if (address == reinterpret_cast<void*>(g_continue_debug_event)) return reinterpret_cast<void*>(&BridgeContinueDebugEvent);
    if (address == reinterpret_cast<void*>(g_debug_active_process)) return reinterpret_cast<void*>(&BridgeDebugActiveProcess);
    if (address == reinterpret_cast<void*>(g_debug_active_process_stop)) return reinterpret_cast<void*>(&BridgeDebugActiveProcessStop);
    if (address == reinterpret_cast<void*>(g_read_process_memory)) return reinterpret_cast<void*>(&BridgeReadProcessMemory);
    if (address == reinterpret_cast<void*>(g_write_process_memory)) return reinterpret_cast<void*>(&BridgeWriteProcessMemory);
    if (address == reinterpret_cast<void*>(g_virtual_protect_ex)) return reinterpret_cast<void*>(&BridgeVirtualProtectEx);
    if (address == reinterpret_cast<void*>(g_get_thread_context)) return reinterpret_cast<void*>(&BridgeGetThreadContext);
    if (address == reinterpret_cast<void*>(g_set_thread_context)) return reinterpret_cast<void*>(&BridgeSetThreadContext);
#ifdef _WIN64
    if (address == reinterpret_cast<void*>(g_wow64_get_thread_context)) return reinterpret_cast<void*>(&BridgeWow64GetThreadContext);
    if (address == reinterpret_cast<void*>(g_wow64_set_thread_context)) return reinterpret_cast<void*>(&BridgeWow64SetThreadContext);
#endif
    if (address == reinterpret_cast<void*>(g_create_process_w)) return reinterpret_cast<void*>(&BridgeCreateProcessW);
    if (address == reinterpret_cast<void*>(g_create_process_a)) return reinterpret_cast<void*>(&BridgeCreateProcessA);
    return nullptr;
}

bool IsWindowsApiProvider(const char* name)
{
    if (!name) return false;
    return _stricmp(name, "kernel32.dll") == 0 ||
           _stricmp(name, "kernelbase.dll") == 0 ||
           _stricmp(name, "ntdll.dll") == 0 ||
           _strnicmp(name, "api-ms-win-", 11) == 0 ||
           _strnicmp(name, "ext-ms-win-", 11) == 0;
}

bool IsPathInWindowsDirectory(const wchar_t* path)
{
    if (!path || !*path) return false;

    wchar_t windows_path[MAX_PATH] = {};
    UINT windows_length = GetWindowsDirectoryW(
        windows_path, static_cast<UINT>(_countof(windows_path)));
    if (windows_length == 0 || windows_length >= _countof(windows_path)) {
        return false;
    }

    while (windows_length > 0 &&
           (windows_path[windows_length - 1] == L'\\' ||
            windows_path[windows_length - 1] == L'/')) {
        windows_path[windows_length - 1] = L'\0';
        --windows_length;
    }

    const wchar_t* comparable_path = path;
    if (_wcsnicmp(comparable_path, L"\\\\?\\", 4) == 0) {
        comparable_path += 4;
    }

    return _wcsnicmp(comparable_path, windows_path, windows_length) == 0 &&
           (comparable_path[windows_length] == L'\\' ||
            comparable_path[windows_length] == L'/' ||
            comparable_path[windows_length] == L'\0');
}

bool IsWindowsSystemModule(HMODULE module)
{
    wchar_t module_path[MAX_PATH] = {};
    const DWORD module_length = GetModuleFileNameW(
        module, module_path, static_cast<DWORD>(_countof(module_path)));
    if (module_length == 0 || module_length >= _countof(module_path)) {
        // This helper is also used to decide whether a debugger-host module
        // may be IAT-patched.  Fail closed when its identity is unavailable.
        return true;
    }
    return IsPathInWindowsDirectory(module_path);
}

bool IsAddressInLocalWindowsModule(LPCVOID address)
{
    if (!address) return false;

    // Windows images use a boot-wide ASLR base.  If the target address maps
    // into a Windows module in the debugger too, this remains a conservative
    // fallback when a target-module snapshot is temporarily unavailable.
    HMODULE module = nullptr;
    if (!GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(address), &module)) {
        return false;
    }
    return IsWindowsSystemModule(module);
}

TargetAddressClass ClassifyTargetAddress(
    HANDLE process,
    DWORD pid,
    LPCVOID address,
    SIZE_T size)
{
    if (!process || !pid || !address || size == 0) {
        return TargetAddressClass::Unknown;
    }

    const ULONG_PTR start = reinterpret_cast<ULONG_PTR>(address);
    if (size > static_cast<SIZE_T>(
                   static_cast<ULONG_PTR>(UINTPTR_MAX) - start)) {
        return TargetAddressClass::Unknown;
    }
    const ULONG_PTR end = start + size;

    HANDLE snapshot = INVALID_HANDLE_VALUE;
    for (unsigned attempt = 0; attempt < 3; ++attempt) {
        snapshot = CreateToolhelp32Snapshot(
            TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (snapshot != INVALID_HANDLE_VALUE ||
            GetLastError() != ERROR_BAD_LENGTH) {
            break;
        }
        SwitchToThread();
    }

    if (snapshot != INVALID_HANDLE_VALUE) {
        MODULEENTRY32W entry = {};
        entry.dwSize = sizeof(entry);
        if (Module32FirstW(snapshot, &entry)) {
            do {
                const ULONG_PTR module_start =
                    reinterpret_cast<ULONG_PTR>(entry.modBaseAddr);
                ULONG_PTR module_end = module_start;
                if (entry.modBaseSize <=
                    static_cast<ULONG_PTR>(UINTPTR_MAX) - module_start) {
                    module_end += entry.modBaseSize;
                } else {
                    module_end = static_cast<ULONG_PTR>(UINTPTR_MAX);
                }
                if (start >= module_start && end <= module_end) {
                    const bool system_module =
                        IsPathInWindowsDirectory(entry.szExePath);
                    CloseHandle(snapshot);
                    return system_module
                        ? TargetAddressClass::WindowsSystemModule
                        : TargetAddressClass::UserModule;
                }
            } while (Module32NextW(snapshot, &entry));
        }
        CloseHandle(snapshot);
    }

    MEMORY_BASIC_INFORMATION memory = {};
    if (VirtualQueryEx(process, address, &memory, sizeof(memory)) ==
        sizeof(memory)) {
        const ULONG_PTR region_start =
            reinterpret_cast<ULONG_PTR>(memory.BaseAddress);
        ULONG_PTR region_end = region_start;
        if (memory.RegionSize <=
            static_cast<ULONG_PTR>(UINTPTR_MAX) - region_start) {
            region_end += memory.RegionSize;
        } else {
            region_end = static_cast<ULONG_PTR>(UINTPTR_MAX);
        }
        if (start >= region_start && end <= region_end &&
            memory.State == MEM_COMMIT && memory.Type == MEM_PRIVATE) {
            return TargetAddressClass::UserPrivateMemory;
        }
    }

    if (IsAddressInLocalWindowsModule(address)) {
        return TargetAddressClass::WindowsSystemModule;
    }
    return TargetAddressClass::Unknown;
}

bool IsClrProvider(const char* name)
{
    if (!name) return false;
    static constexpr const char* providers[] = {
        "mscoree.dll",
        "mscoreei.dll",
        "clr.dll",
        "coreclr.dll",
        "fusion.dll",
        "hostfxr.dll",
        "hostpolicy.dll",
    };
    for (const char* provider : providers) {
        if (_stricmp(name, provider) == 0) return true;
    }
    return false;
}

bool IsClrRuntimeName(const wchar_t* path)
{
    if (!path) return true;
    const wchar_t* slash = wcsrchr(path, L'\\');
    const wchar_t* alternate_slash = wcsrchr(path, L'/');
    if (!slash || (alternate_slash && alternate_slash > slash)) {
        slash = alternate_slash;
    }
    const wchar_t* name = slash ? slash + 1 : path;
    static constexpr const wchar_t* runtime_modules[] = {
        L"mscoree.dll",
        L"mscoreei.dll",
        L"clr.dll",
        L"coreclr.dll",
        L"clrjit.dll",
        L"fusion.dll",
        L"hostfxr.dll",
        L"hostpolicy.dll",
    };
    for (const wchar_t* runtime : runtime_modules) {
        if (_wcsicmp(name, runtime) == 0) return true;
    }
    return false;
}

bool IsThirdPartyPluginPath(const wchar_t* path)
{
    if (!path) return true;
    for (const wchar_t* cursor = path; *cursor; ++cursor) {
        const bool component_start = cursor == path ||
            cursor[-1] == L'\\' || cursor[-1] == L'/';
        if (component_start && _wcsnicmp(cursor, L"plugins", 7) == 0 &&
            (cursor[7] == L'\\' || cursor[7] == L'/' || cursor[7] == L'\0')) {
            return true;
        }
    }

    const wchar_t* extension = wcsrchr(path, L'.');
    return extension &&
        (_wcsicmp(extension, L".dp32") == 0 ||
         _wcsicmp(extension, L".dp64") == 0);
}

bool IsSupportedDebuggerCoreModule(
    HMODULE module,
    HMODULE main_module,
    const wchar_t* path)
{
    if (module == main_module) return true;
    if (!path) return false;

    const wchar_t* slash = wcsrchr(path, L'\\');
    const wchar_t* alternate_slash = wcsrchr(path, L'/');
    if (!slash || (alternate_slash && alternate_slash > slash)) {
        slash = alternate_slash;
    }
    const wchar_t* name = slash ? slash + 1 : path;
    static constexpr const wchar_t* core_modules[] = {
        L"x32dbg.dll",
        L"x64dbg.dll",
        L"TitanEngine.dll",
    };
    for (const wchar_t* core : core_modules) {
        if (_wcsicmp(name, core) == 0) return true;
    }
    return false;
}

bool IsManagedOrClrHostingModule(HMODULE module)
{
    wchar_t module_path[MAX_PATH] = {};
    const DWORD path_length = GetModuleFileNameW(
        module, module_path, static_cast<DWORD>(_countof(module_path)));
    if (path_length == 0 || path_length >= _countof(module_path) ||
        IsClrRuntimeName(module_path)) {
        return true;
    }

    __try {
        auto* base = reinterpret_cast<BYTE*>(module);
        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0) return true;
        auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return true;

        const DWORD image_size = nt->OptionalHeader.SizeOfImage;
        if (image_size < sizeof(IMAGE_DOS_HEADER)) return true;

        if (nt->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR) {
            const auto& clr = nt->OptionalHeader.DataDirectory[
                IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];
            if (clr.VirtualAddress != 0 && clr.Size != 0) return true;
        }

        if (nt->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_IMPORT) {
            return false;
        }
        const auto& imports = nt->OptionalHeader.DataDirectory[
            IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (imports.VirtualAddress == 0 ||
            imports.VirtualAddress >= image_size ||
            imports.Size < sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
            return false;
        }

        const size_t available =
            (image_size - imports.VirtualAddress) / sizeof(IMAGE_IMPORT_DESCRIPTOR);
        const size_t declared = imports.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
        const size_t descriptor_count = (std::min)(available, declared);
        auto* descriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
            base + imports.VirtualAddress);
        for (size_t index = 0; index < descriptor_count; ++index) {
            if (descriptor[index].Name == 0) break;
            if (descriptor[index].Name >= image_size) return true;
            const auto* provider = reinterpret_cast<const char*>(
                base + descriptor[index].Name);
            const size_t remaining = image_size - descriptor[index].Name;
            if (strnlen_s(provider, remaining) == remaining) return true;
            if (IsClrProvider(provider)) return true;
        }
        return false;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // A module whose PE metadata cannot be read safely must not be
        // rewritten while its loader state is uncertain.
        return true;
    }
}

bool AppendPatchRecord(
    PatchJournal* journal,
    PVOID volatile* slot,
    PVOID original,
    PVOID replacement)
{
    if (!journal || !slot || !original || !replacement) return false;
    if (journal->Count == journal->Capacity) {
        const size_t capacity = journal->Capacity == 0
            ? 32 : journal->Capacity * 2;
        if (capacity < journal->Capacity ||
            capacity > SIZE_MAX / sizeof(IatPatchRecord)) {
            return false;
        }
        void* resized = journal->Records
            ? HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                          journal->Records,
                          capacity * sizeof(IatPatchRecord))
            : HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                        capacity * sizeof(IatPatchRecord));
        if (!resized) return false;
        journal->Records = static_cast<IatPatchRecord*>(resized);
        journal->Capacity = capacity;
    }
    IatPatchRecord& record = journal->Records[journal->Count++];
    record.Slot = slot;
    record.Original = original;
    record.Replacement = replacement;
    return true;
}

void ReleasePatchJournal(PatchJournal* journal)
{
    if (!journal) return;
    if (journal->Records) HeapFree(GetProcessHeap(), 0, journal->Records);
    *journal = {};
}

bool RollbackPatchJournal(PatchJournal* journal)
{
    if (!journal) return false;
    bool restored = true;
    for (size_t index = journal->Count; index != 0; --index) {
        IatPatchRecord& record = journal->Records[index - 1];
        if (!record.Applied) continue;
        __try {
            DWORD temporary = 0;
            if (!VirtualProtect(const_cast<PVOID*>(record.Slot), sizeof(PVOID), PAGE_READWRITE,
                                &temporary)) {
                restored = false;
                continue;
            }
            InterlockedExchangePointer(record.Slot, record.Original);
            DWORD ignored = 0;
            if (!VirtualProtect(const_cast<PVOID*>(record.Slot), sizeof(PVOID),
                                record.OriginalProtection, &ignored)) {
                restored = false;
            }
            record.Applied = false;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            restored = false;
        }
    }
    return restored;
}

bool ApplyPatchJournal(
    PatchJournal* journal,
    size_t* patched_entries,
    size_t* failed_entries,
    bool* rollback_succeeded)
{
    if (!journal || !patched_entries || !failed_entries ||
        !rollback_succeeded) {
        return false;
    }
    *patched_entries = 0;
    *failed_entries = 0;
    *rollback_succeeded = true;

    bool success = true;
    size_t active_index = SIZE_MAX;
    __try {
        for (size_t index = 0; index < journal->Count; ++index) {
            active_index = index;
            IatPatchRecord& record = journal->Records[index];
            // The debugger IAT normally lives in read-only .rdata.  An
            // InterlockedCompareExchangePointer(ptr, NULL, NULL) is still an
            // RMW operation and faults before VirtualProtect.  Use the aligned
            // pointer load for preflight, then perform the actual CAS only
            // after the page is writable.
            PVOID current = *record.Slot;
            if (current != record.Original) {
                Trace(L"[NetrBridge] patch conflict index=%zu slot=%p expected=%p current=%p replacement=%p\n",
                      index, record.Slot, record.Original, current,
                      record.Replacement);
                ++*failed_entries;
                success = false;
                break;
            }
            DWORD old_protect = 0;
            if (!VirtualProtect(const_cast<PVOID*>(record.Slot), sizeof(PVOID), PAGE_READWRITE,
                                &old_protect)) {
                Trace(L"[NetrBridge] patch protect failed index=%zu slot=%p win32=%lu\n",
                      index, record.Slot, GetLastError());
                ++*failed_entries;
                success = false;
                break;
            }
            record.OriginalProtection = old_protect;
            current = InterlockedCompareExchangePointer(
                record.Slot, record.Replacement, record.Original);
            if (current != record.Original) {
                DWORD ignored = 0;
                const BOOL restored = VirtualProtect(
                    const_cast<PVOID*>(record.Slot), sizeof(PVOID),
                    old_protect, &ignored);
                if (!restored) *rollback_succeeded = false;
                Trace(L"[NetrBridge] patch CAS lost index=%zu slot=%p expected=%p current=%p replacement=%p protect_restored=%d win32=%lu\n",
                      index, record.Slot, record.Original, current,
                      record.Replacement, restored, restored ? ERROR_SUCCESS : GetLastError());
                ++*failed_entries;
                success = false;
                break;
            }
            record.Applied = true;
            ++*patched_entries;
            DWORD ignored = 0;
            if (!VirtualProtect(const_cast<PVOID*>(record.Slot), sizeof(PVOID), old_protect,
                                &ignored)) {
                Trace(L"[NetrBridge] patch protection restore failed index=%zu slot=%p win32=%lu\n",
                      index, record.Slot, GetLastError());
                ++*failed_entries;
                success = false;
                break;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Trace(L"[NetrBridge] patch exception index=%zu code=0x%08lX\n",
              active_index, GetExceptionCode());
        ++*failed_entries;
        success = false;
    }

    if (!success) {
        *rollback_succeeded =
            RollbackPatchJournal(journal) && *rollback_succeeded;
        *patched_entries = 0;
    }
    return success;
}

ModulePatchResult CollectModulePatchesUnlocked(
    HMODULE module,
    PatchJournal* journal)
{
    ModulePatchResult result = {};
    if (!module || module == g_module || IsWindowsSystemModule(module)) {
        return result;
    }

    __try {
        auto* base = reinterpret_cast<BYTE*>(module);
        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0) {
            return result;
        }
        auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return result;

        const DWORD image_size = nt->OptionalHeader.SizeOfImage;
        if (image_size < sizeof(IMAGE_DOS_HEADER) ||
            nt->OptionalHeader.NumberOfRvaAndSizes <=
                IMAGE_DIRECTORY_ENTRY_IMPORT) {
            return result;
        }

        const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (dir.VirtualAddress == 0 || dir.Size == 0) {
            result.ScanSucceeded = true;
            return result;
        }
        if (dir.VirtualAddress >= image_size ||
            dir.Size < sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
            return result;
        }

        auto* descriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + dir.VirtualAddress);
        const size_t descriptor_capacity = (std::min)(
            static_cast<size_t>(dir.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR)),
            static_cast<size_t>((image_size - dir.VirtualAddress) /
                                sizeof(IMAGE_IMPORT_DESCRIPTOR)));
        bool descriptor_terminated = false;
        for (size_t descriptor_index = 0;
             descriptor_index < descriptor_capacity;
             ++descriptor_index) {
            const auto& current_descriptor = descriptor[descriptor_index];
            if (current_descriptor.Name == 0) {
                descriptor_terminated = true;
                break;
            }
            if (current_descriptor.Name >= image_size ||
                current_descriptor.FirstThunk >= image_size) {
                return result;
            }

            const auto* provider = reinterpret_cast<const char*>(
                base + current_descriptor.Name);
            const size_t provider_remaining = image_size - current_descriptor.Name;
            if (strnlen_s(provider, provider_remaining) == provider_remaining) {
                return result;
            }
            const bool windows_provider = IsWindowsApiProvider(provider);
            auto* iat = reinterpret_cast<IMAGE_THUNK_DATA*>(
                base + current_descriptor.FirstThunk);
            auto* names = current_descriptor.OriginalFirstThunk
                ? reinterpret_cast<IMAGE_THUNK_DATA*>(
                    base + current_descriptor.OriginalFirstThunk)
                : nullptr;
            if (current_descriptor.OriginalFirstThunk >= image_size) {
                return result;
            }

            const size_t iat_capacity =
                (image_size - current_descriptor.FirstThunk) /
                sizeof(IMAGE_THUNK_DATA);
            const size_t names_capacity = current_descriptor.OriginalFirstThunk
                ? (image_size - current_descriptor.OriginalFirstThunk) /
                    sizeof(IMAGE_THUNK_DATA)
                : 0;
            bool iat_terminated = false;
            for (size_t index = 0; index < iat_capacity; ++index) {
                if (iat[index].u1.Function == 0) {
                    iat_terminated = true;
                    break;
                }
                void* replacement = ReplacementForAddress(reinterpret_cast<void*>(
                    static_cast<ULONG_PTR>(iat[index].u1.Function)));
                if (!replacement && windows_provider && names &&
                    index < names_capacity &&
                    !IMAGE_SNAP_BY_ORDINAL(names[index].u1.Ordinal)) {
                    if (names[index].u1.AddressOfData >= image_size) {
                        return result;
                    }
                    auto* import = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(
                        base + names[index].u1.AddressOfData);
                    const size_t import_name_offset =
                        names[index].u1.AddressOfData +
                        offsetof(IMAGE_IMPORT_BY_NAME, Name);
                    if (import_name_offset >= image_size ||
                        strnlen_s(reinterpret_cast<const char*>(import->Name),
                                  image_size - import_name_offset) ==
                            image_size - import_name_offset) {
                        return result;
                    }
                    replacement = ReplacementForName(
                        reinterpret_cast<const char*>(import->Name));
                }
                if (!replacement) {
                    continue;
                }
                ++result.CandidateEntries;
                if (reinterpret_cast<void*>(
                        static_cast<ULONG_PTR>(iat[index].u1.Function)) ==
                    replacement) {
                    ++result.AlreadyPatchedEntries;
                    continue;
                }

                if (!AppendPatchRecord(
                        journal,
                        reinterpret_cast<PVOID volatile*>(
                            &iat[index].u1.Function),
                        reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(
                            iat[index].u1.Function)),
                        replacement)) {
                    ++result.FailedEntries;
                    return result;
                }
            }
            if (!iat_terminated) return result;
        }
        if (!descriptor_terminated) return result;
        result.ScanSucceeded = true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        result.ScanSucceeded = false;
    }
    return result;
}

bool SameModuleIdentity(
    const ModulePatchState& state,
    const MODULEENTRY32W& entry)
{
    return state.ImageSize == entry.modBaseSize &&
           _wcsicmp(state.Path, entry.szExePath) == 0;
}

void ResetModulePatchState(
    ModulePatchState* state,
    const MODULEENTRY32W& entry,
    ULONGLONG first_seen)
{
    if (!state) return;
    *state = {};
    state->FirstSeen = first_seen;
    state->ImageSize = entry.modBaseSize;
    wcsncpy_s(state->Path, entry.szExePath, _TRUNCATE);
}

PatchPassResult PatchAllModules(bool baseline_modules)
{
    PatchPassResult result = {};
    PatchJournal journal = {};
    std::vector<HMODULE> eligible_modules;
    // The initial set has already received the launcher's host-init grace.
    // Modules discovered later get their own settle window to reduce the
    // loader-race risk. CLR/managed and third-party plug-in modules are never
    // eligible for IAT rewriting.
    static constexpr ULONGLONG module_settle_ms = 1'500;
    const HANDLE snapshot = CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
    if (snapshot == INVALID_HANDLE_VALUE) return result;

    AcquireSRWLockExclusive(&g_patch_lock);
    const ULONGLONG now = GetTickCount64();
    const HMODULE main_module = GetModuleHandleW(nullptr);
    std::unordered_set<HMODULE> seen_modules;
    MODULEENTRY32W entry = {};
    entry.dwSize = sizeof(entry);
    if (Module32FirstW(snapshot, &entry)) {
        result.SnapshotSucceeded = true;
        do {
            seen_modules.insert(entry.hModule);
            auto [position, inserted] = g_module_patch_states.try_emplace(
                entry.hModule);
            ModulePatchState& state = position->second;
            if (inserted || !SameModuleIdentity(state, entry)) {
                const ULONGLONG first_seen = baseline_modules &&
                    now >= module_settle_ms
                    ? now - module_settle_ms
                    : now;
                ResetModulePatchState(&state, entry, first_seen);
            }
            if (state.Complete) continue;

            if (!entry.hModule || entry.hModule == g_module ||
                IsWindowsSystemModule(entry.hModule) ||
                IsThirdPartyPluginPath(entry.szExePath) ||
                !IsSupportedDebuggerCoreModule(
                    entry.hModule, main_module, entry.szExePath) ||
                IsManagedOrClrHostingModule(entry.hModule)) {
                state.Complete = true;
                continue;
            }

            if (entry.hModule != main_module &&
                now - state.FirstSeen < module_settle_ms) {
                continue;
            }

            ++result.EligibleModules;
            eligible_modules.push_back(entry.hModule);
            const ModulePatchResult module_result =
                CollectModulePatchesUnlocked(entry.hModule, &journal);
            result.CandidateEntries += module_result.CandidateEntries;
            result.AlreadyPatchedEntries += module_result.AlreadyPatchedEntries;
            result.FailedEntries += module_result.FailedEntries;
            if (module_result.ScanSucceeded) {
                ++result.ScannedModules;
            } else {
                ++result.FailedModules;
            }
        } while (Module32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);

    const bool preflight_succeeded = result.SnapshotSucceeded &&
        result.EligibleModules != 0 && result.FailedModules == 0 &&
        result.FailedEntries == 0 && !g_patch_integrity_lost &&
        (journal.Count + result.AlreadyPatchedEntries) != 0;
    if (preflight_succeeded) {
        if (!g_module_pinned) {
            HMODULE pinned = nullptr;
            if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                   GET_MODULE_HANDLE_EX_FLAG_PIN,
                                   reinterpret_cast<LPCWSTR>(&PatchAllModules),
                                   &pinned)) {
                g_module_pinned = true;
            }
        }
        result.ModulePinned = g_module_pinned;
        if (g_module_pinned) {
            size_t patched = 0;
            size_t failed = 0;
            bool rollback_succeeded = true;
            result.ApplySucceeded = ApplyPatchJournal(
                &journal, &patched, &failed, &rollback_succeeded);
            result.PatchedEntries = patched;
            result.FailedEntries += failed;
            result.RollbackSucceeded = rollback_succeeded;
            if (!rollback_succeeded) g_patch_integrity_lost = true;
            if (result.ApplySucceeded) {
                for (HMODULE module : eligible_modules) {
                    const auto state = g_module_patch_states.find(module);
                    if (state != g_module_patch_states.end()) {
                        state->second.Complete = true;
                    }
                }
            }
        }
    } else {
        result.ModulePinned = g_module_pinned;
    }

    for (auto state = g_module_patch_states.begin();
         state != g_module_patch_states.end();) {
        if (seen_modules.find(state->first) == seen_modules.end()) {
            state = g_module_patch_states.erase(state);
        } else {
            ++state;
        }
    }
    ReleasePatchJournal(&journal);
    ReleaseSRWLockExclusive(&g_patch_lock);
    return result;
}

bool ResolveOriginals()
{
    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!kernel32 || !ntdll) return false;

    g_nt_debug_active_process = reinterpret_cast<NtDebugActiveProcessFn>(::GetProcAddress(ntdll, "NtDebugActiveProcess"));
    g_nt_query_information_thread = reinterpret_cast<NtQueryInformationThreadFn>(::GetProcAddress(ntdll, "NtQueryInformationThread"));
    g_rtl_nt_status_to_dos_error = reinterpret_cast<RtlNtStatusToDosErrorFn>(::GetProcAddress(ntdll, "RtlNtStatusToDosError"));
    g_wait_for_debug_event = reinterpret_cast<WaitForDebugEventFn>(::GetProcAddress(kernel32, "WaitForDebugEvent"));
    g_wait_for_debug_event_ex = reinterpret_cast<WaitForDebugEventExFn>(::GetProcAddress(kernel32, "WaitForDebugEventEx"));
    g_continue_debug_event = reinterpret_cast<ContinueDebugEventFn>(::GetProcAddress(kernel32, "ContinueDebugEvent"));
    g_debug_active_process = reinterpret_cast<DebugActiveProcessFn>(::GetProcAddress(kernel32, "DebugActiveProcess"));
    g_debug_active_process_stop = reinterpret_cast<DebugActiveProcessStopFn>(::GetProcAddress(kernel32, "DebugActiveProcessStop"));
    g_read_process_memory = reinterpret_cast<ReadProcessMemoryFn>(::GetProcAddress(kernel32, "ReadProcessMemory"));
    g_write_process_memory = reinterpret_cast<WriteProcessMemoryFn>(::GetProcAddress(kernel32, "WriteProcessMemory"));
    g_virtual_protect_ex = reinterpret_cast<VirtualProtectExFn>(::GetProcAddress(kernel32, "VirtualProtectEx"));
    g_get_thread_context = reinterpret_cast<GetThreadContextFn>(::GetProcAddress(kernel32, "GetThreadContext"));
    g_set_thread_context = reinterpret_cast<SetThreadContextFn>(::GetProcAddress(kernel32, "SetThreadContext"));
    g_create_process_w = reinterpret_cast<CreateProcessWFn>(::GetProcAddress(kernel32, "CreateProcessW"));
    g_create_process_a = reinterpret_cast<CreateProcessAFn>(::GetProcAddress(kernel32, "CreateProcessA"));
#ifdef _WIN64
    g_wow64_get_thread_context = reinterpret_cast<Wow64GetThreadContextFn>(::GetProcAddress(kernel32, "Wow64GetThreadContext"));
    g_wow64_set_thread_context = reinterpret_cast<Wow64SetThreadContextFn>(::GetProcAddress(kernel32, "Wow64SetThreadContext"));
#endif

    return g_nt_debug_active_process && g_nt_query_information_thread &&
           g_rtl_nt_status_to_dos_error &&
           g_wait_for_debug_event && g_continue_debug_event &&
           g_debug_active_process && g_read_process_memory &&
           g_write_process_memory && g_virtual_protect_ex &&
           g_get_thread_context && g_set_thread_context &&
           g_create_process_w;
}

HANDLE CreateBridgeControlEvent(const wchar_t* phase)
{
    if (!phase || !*phase) return nullptr;
    wchar_t event_name[80] = {};
    _snwprintf_s(event_name, _countof(event_name), _TRUNCATE,
                 L"Local\\NetrBridge%s-%lu", phase, GetCurrentProcessId());
    return CreateEventW(nullptr, TRUE, FALSE, event_name);
}

bool CreateBridgeControlEvents()
{
    g_ready_event = CreateBridgeControlEvent(L"Ready");
    g_commit_event = CreateBridgeControlEvent(L"Commit");
    g_committed_event = CreateBridgeControlEvent(L"Committed");
    g_abort_event = CreateBridgeControlEvent(L"Abort");
    return g_ready_event && g_commit_event && g_committed_event && g_abort_event;
}

bool WaitForBridgeCommit()
{
    static constexpr DWORD commit_timeout_ms = 30'000;
    HANDLE events[] = {g_commit_event, g_abort_event};
    const DWORD wait = WaitForMultipleObjects(
        static_cast<DWORD>(_countof(events)), events, FALSE,
        commit_timeout_ms);
    if (wait == WAIT_OBJECT_0) return true;
    if (wait == WAIT_OBJECT_0 + 1) {
        SetLastError(ERROR_OPERATION_ABORTED);
    } else if (wait == WAIT_TIMEOUT) {
        SetLastError(ERROR_TIMEOUT);
    }
    return false;
}

DWORD WINAPI BridgeWorker(void*)
{
    if (!ResolveOriginals()) {
        Trace(L"[NetrBridge] failed to resolve debugger APIs\n");
        FreeLibraryAndExitThread(g_module, 1);
    }

    bool registered = false;
    for (unsigned attempt = 0; attempt < 50 && !g_stop.load(); ++attempt) {
        if (g_device == INVALID_HANDLE_VALUE && !OpenDriver()) {
            Sleep(100);
            continue;
        }
        if (RegisterBridge()) {
            registered = true;
            break;
        }
        const DWORD register_error = GetLastError();
        Trace(L"[NetrBridge] registration failed permanently, win32=%lu\n",
              register_error);
        CloseHandle(g_device);
        g_device = INVALID_HANDLE_VALUE;
        break;
    }
    if (!registered) {
        Trace(L"[NetrBridge] driver handshake failed\n");
        if (g_device != INVALID_HANDLE_VALUE) {
            CloseHandle(g_device);
            g_device = INVALID_HANDLE_VALUE;
        }
        FreeLibraryAndExitThread(g_module, 2);
    }

    if (!CreateBridgeControlEvents()) {
        Trace(L"[NetrBridge] failed to create commit control events, win32=%lu\n",
              GetLastError());
        CleanupBridgeState();
        FreeLibraryAndExitThread(g_module, 3);
    }

    // Transport readiness is deliberately separate from publishing the IAT
    // hooks.  The launcher first commits the debugger identity in the driver,
    // then signals Commit.  Until then no debugger module has been rewritten
    // and no wrapper can race an uncommitted debugger registration.
    SetEvent(g_ready_event);
    Trace(L"[NetrBridge] transport ready in debugger PID=%lu\n",
          GetCurrentProcessId());
    for (;;) {
        if (!WaitForBridgeCommit()) {
            Trace(L"[NetrBridge] commit aborted or timed out, win32=%lu pinned=%d\n",
                  GetLastError(), g_module_pinned);
            if (!g_module_pinned) {
                CleanupBridgeState();
                FreeLibraryAndExitThread(g_module, 4);
            }
            ResetEvent(g_commit_event);
            ResetEvent(g_committed_event);
            ResetEvent(g_abort_event);
            continue;
        }

        // REGISTER only negotiates the transport.  The launcher records this
        // debugger PID in the driver before signaling Commit, so private Dbgk
        // symbol publication belongs here, after the driver's ACL can accept
        // it and before any debugger module is patched.
        if (!ConfigurePrivateDbgkSymbols()) {
            DWORD symbol_error = GetLastError();
            if (symbol_error == ERROR_SUCCESS) {
                symbol_error = ERROR_INVALID_FUNCTION;
            }
            Trace(L"[NetrBridge] private Dbgk symbol commit failed, win32=%lu pinned=%d\n",
                  symbol_error, g_module_pinned);
            SetEvent(g_abort_event);
            if (!g_module_pinned) {
                CleanupBridgeState();
                FreeLibraryAndExitThread(g_module, 5);
            }
            SetLastError(symbol_error);
            ResetEvent(g_commit_event);
            ResetEvent(g_committed_event);
            ResetEvent(g_abort_event);
            continue;
        }

        if (WaitForSingleObject(g_abort_event, 0) == WAIT_OBJECT_0) {
            Trace(L"[NetrBridge] commit cancelled after private Dbgk symbol configuration\n");
            if (!g_module_pinned) {
                CleanupBridgeState();
                FreeLibraryAndExitThread(g_module, 5);
            }
            ResetEvent(g_commit_event);
            ResetEvent(g_committed_event);
            ResetEvent(g_abort_event);
            continue;
        }

        static constexpr ULONGLONG patch_retry_window_ms = 5'000;
        static constexpr DWORD patch_retry_delay_ms = 250;
        const ULONGLONG retry_started = GetTickCount64();
        PatchPassResult initial_patch = {};
        size_t attempt = 0;
        bool commit_ready = false;

        for (;;) {
            ++attempt;
            initial_patch = PatchAllModules(true);
            Trace(L"[NetrBridge] initial patch attempt=%zu scan=%d pinned=%d apply=%d rollback=%d eligible=%zu scanned=%zu failed_modules=%zu candidates=%zu patched=%zu already=%zu failed_entries=%zu\n",
                  attempt,
                  initial_patch.SnapshotSucceeded,
                  initial_patch.ModulePinned,
                  initial_patch.ApplySucceeded,
                  initial_patch.RollbackSucceeded,
                  initial_patch.EligibleModules,
                  initial_patch.ScannedModules,
                  initial_patch.FailedModules,
                  initial_patch.CandidateEntries,
                  initial_patch.PatchedEntries,
                  initial_patch.AlreadyPatchedEntries,
                  initial_patch.FailedEntries);
            if (initial_patch.CommitReady()) {
                commit_ready = true;
                break;
            }

            if (!initial_patch.RollbackSucceeded || g_patch_integrity_lost) {
                Trace(L"[NetrBridge] rollback integrity lost; rejecting commit and keeping the pinned module alive\n");
                SetEvent(g_abort_event);
                while (!g_stop.load()) Sleep(1000);
                return 7;
            }
            if (WaitForSingleObject(g_abort_event, 0) == WAIT_OBJECT_0) {
                Trace(L"[NetrBridge] patch commit cancelled during retry\n");
                break;
            }
            if (GetTickCount64() - retry_started >= patch_retry_window_ms) {
                Trace(L"[NetrBridge] patch retry window exhausted after %zu attempts\n",
                      attempt);
                break;
            }
            Trace(L"[NetrBridge] transient patch conflict rolled back; retrying internally\n");
            Sleep(patch_retry_delay_ms);
        }

        if (commit_ready) break;

        Trace(L"[NetrBridge] refusing hook commit after bounded internal retries\n");
        SetEvent(g_abort_event);
        if (!initial_patch.ModulePinned) {
            CleanupBridgeState();
            FreeLibraryAndExitThread(g_module, 6);
        }
        Sleep(250);
        ResetEvent(g_commit_event);
        ResetEvent(g_committed_event);
        ResetEvent(g_abort_event);
        Trace(L"[NetrBridge] rolled-back patch transaction ready for a new external commit\n");
    }
    SetEvent(g_committed_event);
    Trace(L"[NetrBridge] hooks committed in debugger PID=%lu\n",
          GetCurrentProcessId());
    Trace(L"[NetrBridge] runtime log=%s\n", g_log_path);

    ULONGLONG last_patch_scan = GetTickCount64();
    while (!g_stop.load()) {
        Sleep(200);
        PollKernelEvents();
        const ULONGLONG now = GetTickCount64();
        if (now - last_patch_scan >= 1'000) {
            (void)PatchAllModules(false);
            last_patch_scan = now;
        }
    }
    return 0;
}

LONG NTAPI BridgeNtDebugActiveProcess(HANDLE process, HANDLE debug_object)
{
    if (!g_nt_debug_active_process) return static_cast<LONG>(0xC0000002L);
    const DWORD pid = GetProcessId(process);
    const bool private_mode = g_private_dbgk_mode.load();
    const bool was_bound = pid != 0 && IsBoundTarget(pid);
    if (private_mode && pid != 0 && !was_bound && !BindTarget(pid)) {
        return static_cast<LONG>(0xC0000022L);
    }
    const LONG status = g_nt_debug_active_process(process, debug_object);
    if (IsNtSuccess(status)) {
        if (pid && !was_bound) BindTarget(pid);
    } else if (private_mode && pid != 0 && !was_bound) {
        (void)UnbindTarget(pid);
    }
    return status;
}

BOOL WINAPI BridgeWaitForDebugEvent(LPDEBUG_EVENT event, DWORD timeout)
{
    return WaitForMergedDebugEvent(g_wait_for_debug_event, event, timeout);
}

BOOL WINAPI BridgeWaitForDebugEventEx(LPDEBUG_EVENT event, DWORD timeout)
{
    if (!g_wait_for_debug_event_ex) {
        SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }
    return WaitForMergedDebugEvent(g_wait_for_debug_event_ex, event, timeout);
}

BOOL WINAPI BridgeContinueDebugEvent(DWORD pid, DWORD tid, DWORD status)
{
    const std::uint64_t private_key = PrivateEventKey(pid, tid);
    AcquireSRWLockExclusive(&g_private_event_lock);
    const auto private_dbgk = g_pending_private_dbgk_events.find(private_key);
    if (private_dbgk != g_pending_private_dbgk_events.end()) {
        const PendingPrivateDbgkEvent pending = private_dbgk->second;
        const HV_BRIDGE_DBGK_EVENT event = [&]() {
            HV_BRIDGE_DBGK_EVENT value = {};
            value.Sequence = pending.Sequence;
            value.ProcessId = pid;
            value.ThreadId = tid;
            value.State = pending.State;
            return value;
        }();
        const bool ok = ContinuePrivateDbgkEvent(event, status);
        const DWORD dbgk_error = ok ? ERROR_SUCCESS : GetLastError();
        if (ok) {
            if (g_private_launches.find(pid) != g_private_launches.end() &&
                pending.Thread && pending.State == HV_BRIDGE_DBGK_CREATE_PROCESS) {
                (void)ResumeThread(pending.Thread);
                g_private_launches.erase(pid);
            }
            g_pending_private_dbgk_events.erase(private_dbgk);
        }
        ReleaseSRWLockExclusive(&g_private_event_lock);
        Trace(L"[DBGK-CONTINUE] seq=%llu state=%lu pid=%lu tid=%lu status=0x%08lX ok=%d win32=%lu\n",
              static_cast<unsigned long long>(pending.Sequence), pending.State,
              pid, tid, status, ok, dbgk_error);
        if (!ok) SetLastError(dbgk_error);
        return ok ? TRUE : FALSE;
    }
    ReleaseSRWLockExclusive(&g_private_event_lock);

    AcquireSRWLockShared(&g_target_lock);
    AcquireSRWLockExclusive(&g_private_event_lock);
    auto pending = g_pending_private_events.find(private_key);
    if (pending != g_pending_private_events.end()) {
        bool continued = pending->second.DriverContinued;
        DWORD error = ERROR_SUCCESS;
        NormalizePrivateBreakpointContext(
            pid, tid, pending->second, L"continue");
        if (!continued) {
            HV_BRIDGE_PRIVATE_EVENT private_event = {};
            private_event.Sequence = pending->second.Sequence;
            private_event.ProcessId = pid;
            private_event.ThreadId = tid;
            private_event.Kind = pending->second.Kind;
            continued = ContinuePrivateEvent(private_event, status);
            error = continued ? ERROR_SUCCESS : GetLastError();
            // STEP completion has no HitPending SWBP entry.  Driver continue
            // returns NOT_FOUND by design; still resume the suspended thread.
            if (!continued &&
                pending->second.Kind == HV_BRIDGE_PRIVATE_EVENT_STEP &&
                error == ERROR_NOT_FOUND) {
                continued = true;
                error = ERROR_SUCCESS;
            }
            if (continued) pending->second.DriverContinued = true;
        }

        BOOL ok = FALSE;
        if (continued) {
            const DWORD previous = ResumeThread(pending->second.Thread);
            if (previous != static_cast<DWORD>(-1)) {
                CloseHandle(pending->second.Thread);
                g_pending_private_events.erase(pending);
                ok = TRUE;
            } else {
                error = GetLastError();
            }
        }
        ReleaseSRWLockExclusive(&g_private_event_lock);
        ReleaseSRWLockShared(&g_target_lock);

        const auto sequence = g_continue_sequence.fetch_add(1) + 1;
        Trace(L"[CONTINUE #%llu] private pid=%lu tid=%lu status=0x%08lX ok=%d win32=%lu\n",
              sequence, pid, tid, status, ok, error);
        if (!ok) SetLastError(error);
        return ok;
    }
    ReleaseSRWLockExclusive(&g_private_event_lock);
    ReleaseSRWLockShared(&g_target_lock);

    if (!g_continue_debug_event) {
        SetLastError(ERROR_PROC_NOT_FOUND);
        return FALSE;
    }

    const BOOL ok = g_continue_debug_event(pid, tid, status);
    const DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    const auto sequence = g_continue_sequence.fetch_add(1) + 1;
    if (sequence <= 512 || !ok) {
        Trace(L"[CONTINUE #%llu] pid=%lu tid=%lu status=0x%08lX ok=%d win32=%lu\n",
              sequence, pid, tid, status, ok, error);
    }
    if (!ok) SetLastError(error);
    return ok;
}

BOOL WINAPI BridgeDebugActiveProcess(DWORD pid)
{
    const bool private_mode = g_private_dbgk_mode.load();
    const bool was_bound = pid != 0 && IsBoundTarget(pid);
    if (private_mode && pid != 0 && !was_bound && !BindTarget(pid)) {
        return FALSE;
    }
    const BOOL ok = g_debug_active_process && g_debug_active_process(pid);
    if (ok) {
        if (!was_bound) BindTarget(pid);
    } else if (private_mode && pid != 0 && !was_bound) {
        (void)UnbindTarget(pid);
    }
    return ok;
}

BOOL WINAPI BridgeDebugActiveProcessStop(DWORD pid)
{
    const BOOL ok = g_debug_active_process_stop && g_debug_active_process_stop(pid);
    if (ok) UnbindTarget(pid);
    return ok;
}

BOOL WINAPI BridgeReadProcessMemory(
    HANDLE process, LPCVOID address, LPVOID buffer,
    SIZE_T size, SIZE_T* transferred)
{
    const DWORD pid = GetProcessId(process);
    if (pid && IsBoundTarget(pid) &&
        (g_granted_capabilities.load() & HV_BRIDGE_CAP_MEMORY_IO) != 0) {
        return DriverReadMemory(pid, address, buffer, size, transferred) ? TRUE : FALSE;
    }
    return g_read_process_memory &&
           g_read_process_memory(process, address, buffer, size, transferred);
}

BOOL WINAPI BridgeWriteProcessMemory(
    HANDLE process, LPVOID address, LPCVOID buffer,
    SIZE_T size, SIZE_T* transferred)
{
    const DWORD pid = GetProcessId(process);
    AcquireSRWLockShared(&g_target_lock);
    const bool bound = pid && !g_stop.load() &&
        g_targets.find(pid) != g_targets.end();
    if (bound) {
        if (!DetachPrivateBreakpointsInRange(pid, address, size)) {
            const DWORD error = GetLastError();
            if (transferred) *transferred = 0;
            ReleaseSRWLockShared(&g_target_lock);
            SetLastError(error);
            return FALSE;
        }

        unsigned char breakpoint_bytes[2] = {};
        const bool captured_breakpoint_bytes = size <= sizeof(breakpoint_bytes) &&
            CaptureBytes(buffer, breakpoint_bytes, size);
        const bool one_byte_int3 = captured_breakpoint_bytes && size == 1 &&
            breakpoint_bytes[0] == 0xCC;
        const bool two_byte_int3 = captured_breakpoint_bytes && size == 2 &&
            breakpoint_bytes[0] == 0xCD && breakpoint_bytes[1] == 0x03;
        const bool breakpoint_write = one_byte_int3 || two_byte_int3;

        const TargetAddressClass address_class = size <= 2
            ? ClassifyTargetAddress(process, pid, address, size)
            : TargetAddressClass::Unknown;
        const bool system_module =
            address_class == TargetAddressClass::WindowsSystemModule;
        const bool private_target =
            address_class == TargetAddressClass::UserModule ||
            address_class == TargetAddressClass::UserPrivateMemory;

        // Registered VT breakpoints are consulted before the current module
        // classification.  This fixes their route for the full lifetime and
        // guarantees that a restore removes the driver shadow first.
        BOOL swbp_result = FALSE;
        if (HandleSoftwareBreakpointWrite(
                pid, address, buffer, size, private_target,
                !private_target,
                transferred, &swbp_result)) {
            ReleaseSRWLockShared(&g_target_lock);
            return swbp_result;
        }

        const bool private_swbp_available =
            (g_granted_capabilities.load() &
             HV_BRIDGE_CAP_PRIVATE_SWBP) != 0;
        if (system_module ||
            (breakpoint_write &&
             (!one_byte_int3 || !private_target ||
              !private_swbp_available))) {
            // Match the intended Unreal boundary: Windows images and any
            // breakpoint form the VT byte-overlay cannot represent stay on
            // the native debug-port/COW path.  Target EXE/user DLL 0xCC
            // writes continue through HandleSoftwareBreakpointWrite above.
            const BOOL result = g_write_process_memory &&
                g_write_process_memory(
                    process, address, buffer, size, transferred);
            const DWORD error = result ? ERROR_SUCCESS : GetLastError();
            Trace(L"[SWBP] native write pid=%lu address=%p size=%llu system=%d form=%s private_cap=%d ok=%d win32=%lu\n",
                  pid, address, static_cast<unsigned long long>(size),
                  system_module,
                  two_byte_int3 ? L"CD03" :
                      (one_byte_int3 ? L"CC" : L"ordinary"),
                  private_swbp_available, result, error);
            ReleaseSRWLockShared(&g_target_lock);
            if (!result) SetLastError(error);
            return result;
        }
        const ULONG capabilities = g_granted_capabilities.load();
        if ((capabilities & (HV_BRIDGE_CAP_MEMORY_IO |
                             HV_BRIDGE_CAP_OS_COW_WRITE)) != 0) {
            const BOOL result = DriverWriteMemory(
                pid, address, buffer, size, transferred) ? TRUE : FALSE;
            ReleaseSRWLockShared(&g_target_lock);
            return result;
        }
    }
    ReleaseSRWLockShared(&g_target_lock);
    return g_write_process_memory &&
           g_write_process_memory(process, address, buffer, size, transferred);
}

BOOL WINAPI BridgeVirtualProtectEx(
    HANDLE process, LPVOID address, SIZE_T size,
    DWORD protection, PDWORD old_protection)
{
    const DWORD pid = GetProcessId(process);
    const bool bound = pid && IsBoundTarget(pid);
    if (!g_virtual_protect_ex) {
        SetLastError(ERROR_PROC_NOT_FOUND);
        return FALSE;
    }

    BOOL ok = g_virtual_protect_ex(
        process, address, size, protection, old_protection);
    DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    bool used_driver_fallback = false;
    if (bound) {
        if (!ok) {
            DWORD driver_old_protection = 0;
            const BOOL driver_ok = DriverProtectMemory(
                pid, address, size, protection, &driver_old_protection);
            const DWORD driver_error = driver_ok ? ERROR_SUCCESS : GetLastError();
            if (driver_ok) {
                if (old_protection) *old_protection = driver_old_protection;
                ok = TRUE;
                error = ERROR_SUCCESS;
                used_driver_fallback = true;
                Trace(L"[PROTECT-DRIVER-FALLBACK] pid=%lu address=%p size=%llu new=0x%08lX old=0x%08lX\n",
                      pid, address, static_cast<unsigned long long>(size),
                      protection, driver_old_protection);
            } else if (driver_error != ERROR_SUCCESS) {
                error = driver_error;
            }
        }
        const auto sequence = g_protect_sequence.fetch_add(1) + 1;
        if (sequence <= 256 || !ok) {
            Trace(used_driver_fallback
                      ? L"[PROTECT-DRIVER-RESULT #%llu] pid=%lu address=%p size=%llu new=0x%08lX ok=%d win32=%lu old=0x%08lX\n"
                      : L"[PROTECT-NATIVE #%llu] pid=%lu address=%p size=%llu new=0x%08lX ok=%d win32=%lu old=0x%08lX\n",
                  sequence, pid, address,
                  static_cast<unsigned long long>(size), protection,
                  ok, error, ok && old_protection ? *old_protection : 0);
        }
    }
    if (!ok) SetLastError(error);
    return ok;
}

BOOL WINAPI BridgeGetThreadContext(HANDLE thread, LPCONTEXT context)
{
    if (!g_get_thread_context || !context) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    const DWORD requested = context->ContextFlags;
    const BOOL ok = g_get_thread_context(thread, context);
    const DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    const auto sequence = g_context_sequence.fetch_add(1) + 1;
    if (sequence <= 256) {
#ifdef _WIN64
        Trace(L"[CONTEXT #%llu] get thread=%p pid=%lu flags=0x%08lX ok=%d win32=%lu ip=0x%llX sp=0x%llX dr7=0x%llX\n",
              sequence, thread, GetProcessIdOfThread(thread), requested,
              ok, error, static_cast<unsigned long long>(context->Rip),
              static_cast<unsigned long long>(context->Rsp),
              static_cast<unsigned long long>(context->Dr7));
#else
        Trace(L"[CONTEXT #%llu] get thread=%p pid=%lu flags=0x%08lX ok=%d win32=%lu ip=0x%08lX sp=0x%08lX dr7=0x%08lX\n",
              sequence, thread, GetProcessIdOfThread(thread), requested,
              ok, error, context->Eip, context->Esp, context->Dr7);
#endif
    }
    const DWORD pid = GetProcessIdOfThread(thread);
    const DWORD tid = GetThreadId(thread);
    if (ok &&
        (requested & CONTEXT_CONTROL) == CONTEXT_CONTROL &&
        pid && tid && LookupPendingVtStep(pid, tid, nullptr)) {
        context->EFlags |= 0x100u;
    }
    if (!ok || (requested & CONTEXT_DEBUG_REGISTERS) != CONTEXT_DEBUG_REGISTERS) {
        if (!ok) SetLastError(error);
        return ok;
    }

    VirtualDebugState state = {};
    if (pid && IsBoundTarget(pid) && LookupDebugState(pid, &state)) {
        context->Dr0 = static_cast<DWORD_PTR>(state.Dr[0]);
        context->Dr1 = static_cast<DWORD_PTR>(state.Dr[1]);
        context->Dr2 = static_cast<DWORD_PTR>(state.Dr[2]);
        context->Dr3 = static_cast<DWORD_PTR>(state.Dr[3]);
        context->Dr7 = static_cast<DWORD_PTR>(state.Dr7);
    }
    return TRUE;
}

BOOL WINAPI BridgeSetThreadContext(HANDLE thread, const CONTEXT* context)
{
    if (!g_set_thread_context || !context) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    const DWORD pid = GetProcessIdOfThread(thread);
    const DWORD tid = GetThreadId(thread);
    AcquireSRWLockShared(&g_target_lock);
    const bool bound = pid && !g_stop.load() &&
        g_targets.find(pid) != g_targets.end();
    const auto sequence = g_context_sequence.fetch_add(1) + 1;
    if (sequence <= 256) {
#ifdef _WIN64
        Trace(L"[CONTEXT #%llu] set-enter thread=%p pid=%lu flags=0x%08lX ip=0x%llX sp=0x%llX dr7=0x%llX bound=%d\n",
              sequence, thread, pid, context->ContextFlags,
              static_cast<unsigned long long>(context->Rip),
              static_cast<unsigned long long>(context->Rsp),
              static_cast<unsigned long long>(context->Dr7),
              bound);
#else
        Trace(L"[CONTEXT #%llu] set-enter thread=%p pid=%lu flags=0x%08lX ip=0x%08lX sp=0x%08lX dr7=0x%08lX bound=%d\n",
              sequence, thread, pid, context->ContextFlags,
              context->Eip, context->Esp, context->Dr7,
              bound);
#endif
    }

    CONTEXT sanitized = *context;
    const bool has_control =
        (context->ContextFlags & CONTEXT_CONTROL) == CONTEXT_CONTROL;
    const bool has_debug_registers =
        (context->ContextFlags & CONTEXT_DEBUG_REGISTERS) ==
            CONTEXT_DEBUG_REGISTERS;
    bool vt_step_virtualized = false;
    bool vt_step_armed_here = false;
    std::uint64_t step_address = 0;
    if (bound && has_control && tid) {
#ifdef _WIN64
        step_address = context->Rip;
#else
        step_address = context->Eip;
#endif
        PendingVtStep pending_step = {};
        const bool had_pending_step =
            LookupPendingVtStep(pid, tid, &pending_step);
        const bool requested_single_step = (context->EFlags & 0x100u) != 0;
        if (requested_single_step && had_pending_step &&
            pending_step.Address == step_address) {
            sanitized.EFlags &= ~0x100u;
            vt_step_virtualized = true;
            Trace(L"[VT-STEP-CONTEXT] preserve duplicate-arm pid=%lu tid=%lu rip=0x%llX\n",
                  pid, tid, static_cast<unsigned long long>(step_address));
        } else if (requested_single_step &&
            (g_granted_capabilities.load() & HV_BRIDGE_CAP_VT_STEP) != 0) {
            const TargetAddressClass address_class =
                ClassifyStepAddress(pid, step_address);
            if (address_class == TargetAddressClass::UserModule ||
                address_class == TargetAddressClass::UserPrivateMemory) {
                if (!ArmVtStep(pid, tid, step_address)) {
                    const DWORD error = GetLastError();
                    ReleaseSRWLockShared(&g_target_lock);
                    Trace(L"[VT-STEP] arm failed pid=%lu tid=%lu rip=0x%llX win32=%lu\n",
                          pid, tid,
                          static_cast<unsigned long long>(step_address), error);
                    SetLastError(error);
                    return FALSE;
                }
                sanitized.EFlags &= ~0x100u;
                vt_step_virtualized = true;
                vt_step_armed_here = true;
            }
        }
        if (!vt_step_virtualized && had_pending_step) {
            if (pending_step.Address == step_address) {
                Trace(L"[VT-STEP-CONTEXT] preserve same-ip sync pid=%lu tid=%lu rip=0x%llX tf=%d\n",
                      pid, tid, static_cast<unsigned long long>(step_address),
                      requested_single_step);
            } else {
                Trace(L"[VT-STEP-CONTEXT] cancel changed-ip pid=%lu tid=%lu old=0x%llX new=0x%llX tf=%d\n",
                      pid, tid,
                      static_cast<unsigned long long>(pending_step.Address),
                      static_cast<unsigned long long>(step_address),
                      requested_single_step);
                if (!ClearPendingVtStep(pid, tid)) {
                    const DWORD error = GetLastError();
                    ReleaseSRWLockShared(&g_target_lock);
                    SetLastError(error);
                    return FALSE;
                }
            }
        }
    }

    if (!bound || !has_debug_registers) {
        const BOOL ok = g_set_thread_context(
            thread, vt_step_virtualized ? &sanitized : context);
        const DWORD error = ok ? ERROR_SUCCESS : GetLastError();
        if (!ok && vt_step_armed_here) (void)ClearPendingVtStep(pid, tid);
        ReleaseSRWLockShared(&g_target_lock);
        if (sequence <= 256 || !ok) {
            Trace(L"[CONTEXT #%llu] set-%s pid=%lu tid=%lu ok=%d win32=%lu\n",
                  sequence, vt_step_virtualized ? L"vt-step" : L"native",
                  pid, tid, ok, error);
        }
        if (!ok) SetLastError(error);
        return ok;
    }

    sanitized.Dr0 = sanitized.Dr1 = sanitized.Dr2 = sanitized.Dr3 = 0;
    sanitized.Dr6 = sanitized.Dr7 = 0;
    if (!g_set_thread_context(thread, &sanitized)) {
        const DWORD error = GetLastError();
        if (vt_step_armed_here) (void)ClearPendingVtStep(pid, tid);
        ReleaseSRWLockShared(&g_target_lock);
        Trace(L"[CONTEXT #%llu] set-sanitized failed pid=%lu win32=%lu\n",
              sequence, pid, error);
        SetLastError(error);
        return FALSE;
    }

    VirtualDebugState state = {};
    state.Dr[0] = context->Dr0;
    state.Dr[1] = context->Dr1;
    state.Dr[2] = context->Dr2;
    state.Dr[3] = context->Dr3;
    state.Dr7 = context->Dr7;
    const BOOL committed = CommitDebugState(pid, state) ? TRUE : FALSE;
    const DWORD commit_error = committed ? ERROR_SUCCESS : GetLastError();
    if (!committed && vt_step_armed_here) (void)ClearPendingVtStep(pid, tid);
    ReleaseSRWLockShared(&g_target_lock);
    Trace(L"[CONTEXT #%llu] set-virtual pid=%lu committed=%d\n",
          sequence, pid, committed);
    if (!committed) SetLastError(commit_error);
    return committed;
}

#ifdef _WIN64
BOOL WINAPI BridgeWow64GetThreadContext(HANDLE thread, PWOW64_CONTEXT context)
{
    if (!g_wow64_get_thread_context || !context) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    const DWORD requested = context->ContextFlags;
    const BOOL ok = g_wow64_get_thread_context(thread, context);
    const DWORD pid = GetProcessIdOfThread(thread);
    const DWORD tid = GetThreadId(thread);
    if (ok &&
        (requested & WOW64_CONTEXT_CONTROL) == WOW64_CONTEXT_CONTROL &&
        pid && tid && LookupPendingVtStep(pid, tid, nullptr)) {
        context->EFlags |= 0x100u;
    }
    if (!ok ||
        (requested & WOW64_CONTEXT_DEBUG_REGISTERS) != WOW64_CONTEXT_DEBUG_REGISTERS) {
        return ok;
    }

    VirtualDebugState state = {};
    if (pid && IsBoundTarget(pid) && LookupDebugState(pid, &state)) {
        context->Dr0 = static_cast<DWORD>(state.Dr[0]);
        context->Dr1 = static_cast<DWORD>(state.Dr[1]);
        context->Dr2 = static_cast<DWORD>(state.Dr[2]);
        context->Dr3 = static_cast<DWORD>(state.Dr[3]);
        context->Dr7 = static_cast<DWORD>(state.Dr7);
    }
    return TRUE;
}

BOOL WINAPI BridgeWow64SetThreadContext(HANDLE thread, const WOW64_CONTEXT* context)
{
    if (!g_wow64_set_thread_context || !context) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    const DWORD pid = GetProcessIdOfThread(thread);
    const DWORD tid = GetThreadId(thread);
    AcquireSRWLockShared(&g_target_lock);
    const bool bound = pid && !g_stop.load() &&
        g_targets.find(pid) != g_targets.end();
    WOW64_CONTEXT sanitized = *context;
    const bool has_control =
        (context->ContextFlags & WOW64_CONTEXT_CONTROL) ==
            WOW64_CONTEXT_CONTROL;
    const bool has_debug_registers =
        (context->ContextFlags & WOW64_CONTEXT_DEBUG_REGISTERS) ==
            WOW64_CONTEXT_DEBUG_REGISTERS;
    bool vt_step_virtualized = false;
    bool vt_step_armed_here = false;
    if (bound && has_control && tid) {
        const std::uint64_t step_address = context->Eip;
        PendingVtStep pending_step = {};
        const bool had_pending_step =
            LookupPendingVtStep(pid, tid, &pending_step);
        const bool requested_single_step = (context->EFlags & 0x100u) != 0;
        if (requested_single_step && had_pending_step &&
            pending_step.Address == step_address) {
            sanitized.EFlags &= ~0x100u;
            vt_step_virtualized = true;
            Trace(L"[VT-STEP-CONTEXT] wow64 preserve duplicate-arm pid=%lu tid=%lu eip=0x%llX\n",
                  pid, tid, static_cast<unsigned long long>(step_address));
        } else if (requested_single_step &&
            (g_granted_capabilities.load() & HV_BRIDGE_CAP_VT_STEP) != 0) {
            const TargetAddressClass address_class =
                ClassifyStepAddress(pid, step_address);
            if (address_class == TargetAddressClass::UserModule ||
                address_class == TargetAddressClass::UserPrivateMemory) {
                if (!ArmVtStep(pid, tid, step_address)) {
                    const DWORD error = GetLastError();
                    ReleaseSRWLockShared(&g_target_lock);
                    SetLastError(error);
                    return FALSE;
                }
                sanitized.EFlags &= ~0x100u;
                vt_step_virtualized = true;
                vt_step_armed_here = true;
            }
        }
        if (!vt_step_virtualized && had_pending_step) {
            if (pending_step.Address == step_address) {
                Trace(L"[VT-STEP-CONTEXT] wow64 preserve same-ip sync pid=%lu tid=%lu eip=0x%llX tf=%d\n",
                      pid, tid, static_cast<unsigned long long>(step_address),
                      requested_single_step);
            } else {
                Trace(L"[VT-STEP-CONTEXT] wow64 cancel changed-ip pid=%lu tid=%lu old=0x%llX new=0x%llX tf=%d\n",
                      pid, tid,
                      static_cast<unsigned long long>(pending_step.Address),
                      static_cast<unsigned long long>(step_address),
                      requested_single_step);
                if (!ClearPendingVtStep(pid, tid)) {
                    const DWORD error = GetLastError();
                    ReleaseSRWLockShared(&g_target_lock);
                    SetLastError(error);
                    return FALSE;
                }
            }
        }
    }

    if (!bound || !has_debug_registers) {
        const BOOL ok = g_wow64_set_thread_context(
            thread, vt_step_virtualized ? &sanitized : context);
        const DWORD error = ok ? ERROR_SUCCESS : GetLastError();
        if (!ok && vt_step_armed_here) (void)ClearPendingVtStep(pid, tid);
        ReleaseSRWLockShared(&g_target_lock);
        if (!ok) SetLastError(error);
        return ok;
    }

    sanitized.Dr0 = sanitized.Dr1 = sanitized.Dr2 = sanitized.Dr3 = 0;
    sanitized.Dr6 = sanitized.Dr7 = 0;
    if (!g_wow64_set_thread_context(thread, &sanitized)) {
        const DWORD error = GetLastError();
        if (vt_step_armed_here) (void)ClearPendingVtStep(pid, tid);
        ReleaseSRWLockShared(&g_target_lock);
        SetLastError(error);
        return FALSE;
    }

    VirtualDebugState state = {};
    state.Dr[0] = context->Dr0;
    state.Dr[1] = context->Dr1;
    state.Dr[2] = context->Dr2;
    state.Dr[3] = context->Dr3;
    state.Dr7 = context->Dr7;
    const BOOL committed = CommitDebugState(pid, state) ? TRUE : FALSE;
    const DWORD error = committed ? ERROR_SUCCESS : GetLastError();
    if (!committed && vt_step_armed_here) (void)ClearPendingVtStep(pid, tid);
    ReleaseSRWLockShared(&g_target_lock);
    if (!committed) SetLastError(error);
    return committed;
}
#endif

bool TransferPrivateLaunchSuspend(
    DWORD requested_creation_flags,
    LPPROCESS_INFORMATION process_info)
{
    if (!process_info || !process_info->hThread) {
        SetLastError(ERROR_INVALID_HANDLE);
        return false;
    }
    if ((requested_creation_flags & CREATE_SUSPENDED) != 0) {
        return true;
    }

    // The private attach has already queued CREATE_PROCESS and placed its own
    // process-wide hold.  Drop the temporary CreateProcess hold now so either
    // the Bridge IOCTL path or the direct NtDebugContinue path can release the
    // sole remaining owner and start the target.
    const DWORD previous = ResumeThread(process_info->hThread);
    const DWORD error = previous == static_cast<DWORD>(-1)
        ? GetLastError() : ERROR_SUCCESS;
    Trace(L"[PRIVATE-LAUNCH] transfer suspend pid=%lu tid=%lu previous=%lu ok=%d win32=%lu\n",
          process_info->dwProcessId, process_info->dwThreadId,
          previous, previous != static_cast<DWORD>(-1), error);
    if (previous == static_cast<DWORD>(-1)) {
        SetLastError(error);
        return false;
    }
    return true;
}

BOOL WINAPI BridgeCreateProcessW(
    LPCWSTR application_name, LPWSTR command_line,
    LPSECURITY_ATTRIBUTES process_attributes, LPSECURITY_ATTRIBUTES thread_attributes,
    BOOL inherit_handles, DWORD creation_flags, LPVOID environment,
    LPCWSTR current_directory, LPSTARTUPINFOW startup_info,
    LPPROCESS_INFORMATION process_info)
{
    const bool private_launch = g_private_dbgk_mode.load() &&
        (creation_flags & (DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS)) != 0;
    DWORD effective_flags = creation_flags;
    if (private_launch) {
        effective_flags &= ~(DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS);
        effective_flags |= CREATE_SUSPENDED;
    }
    const BOOL ok = g_create_process_w && g_create_process_w(
        application_name, command_line, process_attributes, thread_attributes,
        inherit_handles, effective_flags, environment, current_directory,
        startup_info, process_info);
    const DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    Trace(L"[CREATE-W] app=%s flags=0x%08lX ok=%d win32=%lu pid=%lu process=%p thread=%p\n",
          application_name ? application_name : L"<null>", creation_flags,
          ok, error, ok && process_info ? process_info->dwProcessId : 0,
          ok && process_info ? process_info->hProcess : nullptr,
          ok && process_info ? process_info->hThread : nullptr);
    if (ok && process_info && private_launch) {
        const DWORD pid = process_info->dwProcessId;
        if (!BindTarget(pid, HV_BRIDGE_BIND_DEFER_PEB_CLOAK) ||
            !g_debug_active_process ||
            !g_debug_active_process(pid) ||
            !TransferPrivateLaunchSuspend(creation_flags, process_info)) {
            const DWORD attach_error = GetLastError() != ERROR_SUCCESS
                ? GetLastError() : ERROR_DEBUG_ATTACH_FAILED;
            (void)UnbindTarget(pid);
            (void)TerminateProcess(process_info->hProcess, attach_error);
            (void)WaitForSingleObject(process_info->hProcess, 5'000);
            CloseHandle(process_info->hThread);
            CloseHandle(process_info->hProcess);
            ZeroMemory(process_info, sizeof(*process_info));
            SetLastError(attach_error);
            return FALSE;
        }
    } else if (ok && process_info &&
               (creation_flags & (DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS)) != 0) {
        (void)BindTarget(
            process_info->dwProcessId,
            HV_BRIDGE_BIND_DEFER_PEB_CLOAK);
    }
    if (!ok) SetLastError(error);
    return ok;
}

BOOL WINAPI BridgeCreateProcessA(
    LPCSTR application_name, LPSTR command_line,
    LPSECURITY_ATTRIBUTES process_attributes, LPSECURITY_ATTRIBUTES thread_attributes,
    BOOL inherit_handles, DWORD creation_flags, LPVOID environment,
    LPCSTR current_directory, LPSTARTUPINFOA startup_info,
    LPPROCESS_INFORMATION process_info)
{
    const bool private_launch = g_private_dbgk_mode.load() &&
        (creation_flags & (DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS)) != 0;
    DWORD effective_flags = creation_flags;
    if (private_launch) {
        effective_flags &= ~(DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS);
        effective_flags |= CREATE_SUSPENDED;
    }
    const BOOL ok = g_create_process_a && g_create_process_a(
        application_name, command_line, process_attributes, thread_attributes,
        inherit_handles, effective_flags, environment, current_directory,
        startup_info, process_info);
    const DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    Trace(L"[CREATE-A] flags=0x%08lX ok=%d win32=%lu pid=%lu process=%p thread=%p\n",
          creation_flags, ok, error,
          ok && process_info ? process_info->dwProcessId : 0,
          ok && process_info ? process_info->hProcess : nullptr,
          ok && process_info ? process_info->hThread : nullptr);
    if (ok && process_info && private_launch) {
        const DWORD pid = process_info->dwProcessId;
        if (!BindTarget(pid, HV_BRIDGE_BIND_DEFER_PEB_CLOAK) ||
            !g_debug_active_process ||
            !g_debug_active_process(pid) ||
            !TransferPrivateLaunchSuspend(creation_flags, process_info)) {
            const DWORD attach_error = GetLastError() != ERROR_SUCCESS
                ? GetLastError() : ERROR_DEBUG_ATTACH_FAILED;
            (void)UnbindTarget(pid);
            (void)TerminateProcess(process_info->hProcess, attach_error);
            (void)WaitForSingleObject(process_info->hProcess, 5'000);
            CloseHandle(process_info->hThread);
            CloseHandle(process_info->hProcess);
            ZeroMemory(process_info, sizeof(*process_info));
            SetLastError(attach_error);
            return FALSE;
        }
    } else if (ok && process_info &&
               (creation_flags & (DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS)) != 0) {
        (void)BindTarget(
            process_info->dwProcessId,
            HV_BRIDGE_BIND_DEFER_PEB_CLOAK);
    }
    if (!ok) SetLastError(error);
    return ok;
}

} // namespace

extern "C" __declspec(dllexport) BOOL NetrBridgeBindTarget(DWORD pid)
{
    return BindTarget(pid) ? TRUE : FALSE;
}

extern "C" __declspec(dllexport) BOOL NetrBridgeUnbindTarget(DWORD pid)
{
    return UnbindTarget(pid) ? TRUE : FALSE;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH) {
        g_module = instance;
        DisableThreadLibraryCalls(instance);
        HANDLE thread = CreateThread(nullptr, 0, BridgeWorker, nullptr, 0, nullptr);
        if (thread) CloseHandle(thread);
    } else if (reason == DLL_PROCESS_DETACH) {
        CleanupBridgeState();
    }
    return TRUE;
}
