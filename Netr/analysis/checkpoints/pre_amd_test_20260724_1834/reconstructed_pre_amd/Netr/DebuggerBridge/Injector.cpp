#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <tlhelp32.h>

#include <cstdio>
#include <cwchar>
#include <string>

namespace {

bool ParsePid(const wchar_t* text, DWORD* pid)
{
    if (!text || !pid) return false;
    wchar_t* end = nullptr;
    const unsigned long parsed = wcstoul(text, &end, 10);
    if (!end || *end != L'\0' || parsed == 0 || parsed > 0xFFFFFFFFul) {
        return false;
    }
    *pid = static_cast<DWORD>(parsed);
    return true;
}

HANDLE OpenBridgeEvent(DWORD pid, const wchar_t* phase, DWORD access)
{
    wchar_t event_name[80] = {};
    _snwprintf_s(event_name, _countof(event_name), _TRUNCATE,
                 L"Local\\NetrBridge%s-%lu", phase, pid);
    return OpenEventW(access, FALSE, event_name);
}

int Commit(DWORD pid)
{
    HANDLE commit = OpenBridgeEvent(pid, L"Commit", EVENT_MODIFY_STATE);
    HANDLE committed = OpenBridgeEvent(pid, L"Committed", SYNCHRONIZE);
    HANDLE aborted = OpenBridgeEvent(pid, L"Abort", SYNCHRONIZE);
    if (!commit || !committed || !aborted) {
        const DWORD error = GetLastError();
        if (commit) CloseHandle(commit);
        if (committed) CloseHandle(committed);
        if (aborted) CloseHandle(aborted);
        fwprintf(stderr, L"Open bridge commit events failed: %lu\n", error);
        return 18;
    }

    if (!SetEvent(commit)) {
        const DWORD error = GetLastError();
        CloseHandle(commit);
        CloseHandle(committed);
        CloseHandle(aborted);
        fwprintf(stderr, L"Signal bridge commit failed: %lu\n", error);
        return 19;
    }

    // A private-DebugObject commit may resolve/download kernel symbols before
    // the Bridge can publish its hooks.  Keep this wait above that first-use
    // path without changing any steady-state debugger timeout.
    static constexpr DWORD commit_timeout_ms = 120'000;
    HANDLE completion[] = {committed, aborted};
    const DWORD wait = WaitForMultipleObjects(
        static_cast<DWORD>(_countof(completion)), completion, FALSE,
        commit_timeout_ms);
    CloseHandle(commit);
    CloseHandle(committed);
    CloseHandle(aborted);
    if (wait == WAIT_OBJECT_0) return 0;
    if (wait == WAIT_OBJECT_0 + 1) {
        fwprintf(stderr, L"Bridge rejected commit\n");
        return 20;
    }
    if (wait == WAIT_FAILED) {
        fwprintf(stderr, L"Wait for bridge commit failed: %lu\n", GetLastError());
    } else {
        fwprintf(stderr, L"Bridge commit timed out (wait=%lu)\n", wait);
    }
    return 21;
}

int Abort(DWORD pid)
{
    HANDLE abort = OpenBridgeEvent(pid, L"Abort", EVENT_MODIFY_STATE);
    if (!abort) {
        fwprintf(stderr, L"Open bridge abort event failed: %lu\n", GetLastError());
        return 22;
    }
    const BOOL signaled = SetEvent(abort);
    const DWORD error = signaled ? ERROR_SUCCESS : GetLastError();
    CloseHandle(abort);
    if (!signaled) {
        fwprintf(stderr, L"Signal bridge abort failed: %lu\n", error);
        return 23;
    }
    return 0;
}

std::wstring BaseName(const wchar_t* path)
{
    const wchar_t* slash = wcsrchr(path, L'\\');
    return slash ? slash + 1 : path;
}

uintptr_t FindRemoteModule(DWORD pid, const std::wstring& module_name)
{
    HANDLE snapshot = CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    MODULEENTRY32W entry = {};
    entry.dwSize = sizeof(entry);
    uintptr_t result = 0;
    if (Module32FirstW(snapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szModule, module_name.c_str()) == 0) {
                result = reinterpret_cast<uintptr_t>(entry.modBaseAddr);
                break;
            }
        } while (Module32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return result;
}

LPTHREAD_START_ROUTINE ResolveRemoteLoadLibraryW(DWORD pid)
{
    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    FARPROC load_library = kernel32 ? GetProcAddress(kernel32, "LoadLibraryW") : nullptr;
    if (!load_library) return nullptr;

    HMODULE owner = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            reinterpret_cast<LPCWSTR>(load_library), &owner)) {
        return nullptr;
    }

    wchar_t owner_path[MAX_PATH] = {};
    if (!GetModuleFileNameW(owner, owner_path, _countof(owner_path))) {
        return nullptr;
    }
    const uintptr_t remote_owner = FindRemoteModule(pid, BaseName(owner_path));
    if (!remote_owner) return nullptr;

    const uintptr_t rva = reinterpret_cast<uintptr_t>(load_library) -
                          reinterpret_cast<uintptr_t>(owner);
    return reinterpret_cast<LPTHREAD_START_ROUTINE>(remote_owner + rva);
}

int Inject(DWORD pid, const wchar_t* dll_path)
{
    const std::wstring dll_name = BaseName(dll_path);
    wchar_t event_name[80] = {};
    _snwprintf_s(event_name, _countof(event_name), _TRUNCATE,
                 L"Local\\NetrBridgeReady-%lu", pid);
    HANDLE ready = CreateEventW(nullptr, TRUE, FALSE, event_name);
    if (!ready) {
        fwprintf(stderr, L"CreateEvent failed: %lu\n", GetLastError());
        return 10;
    }

    // A successful Bridge keeps this manual-reset event alive and signaled.
    // Therefore repeated injection requests still verify the driver handshake
    // instead of treating a merely loaded (possibly inert) DLL as success.
    if (FindRemoteModule(pid, dll_name) != 0) {
        const DWORD ready_wait = WaitForSingleObject(ready, 10000);
        CloseHandle(ready);
        if (ready_wait != WAIT_OBJECT_0) {
            fwprintf(stderr, L"Loaded bridge is not ready (wait=%lu)\n", ready_wait);
            return 17;
        }
        return 0;
    }

    HANDLE process = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                                 PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
                                 PROCESS_VM_READ | SYNCHRONIZE,
                                 FALSE, pid);
    if (!process) {
        fwprintf(stderr, L"OpenProcess(%lu) failed: %lu\n", pid, GetLastError());
        CloseHandle(ready);
        return 11;
    }

    const size_t bytes = (wcslen(dll_path) + 1) * sizeof(wchar_t);
    void* remote_path = VirtualAllocEx(process, nullptr, bytes,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote_path) {
        fwprintf(stderr, L"VirtualAllocEx failed: %lu\n", GetLastError());
        CloseHandle(process);
        CloseHandle(ready);
        return 12;
    }

    SIZE_T written = 0;
    if (!WriteProcessMemory(process, remote_path, dll_path, bytes, &written) ||
        written != bytes) {
        fwprintf(stderr, L"WriteProcessMemory failed: %lu\n", GetLastError());
        VirtualFreeEx(process, remote_path, 0, MEM_RELEASE);
        CloseHandle(process);
        CloseHandle(ready);
        return 13;
    }

    LPTHREAD_START_ROUTINE load_library = ResolveRemoteLoadLibraryW(pid);
    if (!load_library) {
        fwprintf(stderr, L"Cannot resolve remote LoadLibraryW\n");
        VirtualFreeEx(process, remote_path, 0, MEM_RELEASE);
        CloseHandle(process);
        CloseHandle(ready);
        return 14;
    }

    HANDLE thread = CreateRemoteThread(process, nullptr, 0, load_library,
                                       remote_path, 0, nullptr);
    if (!thread) {
        fwprintf(stderr, L"CreateRemoteThread failed: %lu\n", GetLastError());
        VirtualFreeEx(process, remote_path, 0, MEM_RELEASE);
        CloseHandle(process);
        CloseHandle(ready);
        return 15;
    }

    const DWORD load_wait = WaitForSingleObject(thread, 10000);
    DWORD load_result = 0;
    if (load_wait == WAIT_OBJECT_0) {
        GetExitCodeThread(thread, &load_result);
    }
    CloseHandle(thread);

    if (load_wait != WAIT_OBJECT_0) {
        // The remote thread may still be reading the path. Leaking one small
        // allocation is safer than freeing memory out from under it; launch
        // failures are followed by terminating the newly-created debugger.
        if (load_wait == WAIT_FAILED) {
            fwprintf(stderr, L"LoadLibraryW wait failed: %lu\n", GetLastError());
        } else {
            fwprintf(stderr, L"LoadLibraryW timed out (wait=%lu)\n", load_wait);
        }
        CloseHandle(process);
        CloseHandle(ready);
        return 16;
    }

    VirtualFreeEx(process, remote_path, 0, MEM_RELEASE);

    // GetExitCodeThread exposes only DWORD, so an x64 HMODULE whose low
    // 32 bits are zero is indistinguishable from failure. Module enumeration
    // and the ready handshake are the architecture-neutral authorities.
    if (FindRemoteModule(pid, dll_name) == 0) {
        fwprintf(stderr, L"LoadLibraryW failed or timed out (wait=%lu, exit=%lu)\n",
                 load_wait, load_result);
        CloseHandle(process);
        CloseHandle(ready);
        return 16;
    }

    const DWORD ready_wait = WaitForSingleObject(ready, 10000);
    CloseHandle(process);
    CloseHandle(ready);
    if (ready_wait != WAIT_OBJECT_0) {
        fwprintf(stderr, L"Bridge transport handshake timed out (wait=%lu)\n",
                 ready_wait);
        return 17;
    }
    return 0;
}

} // namespace

int wmain(int argc, wchar_t** argv)
{
    if (argc == 3 && _wcsicmp(argv[1], L"--commit") == 0) {
        DWORD pid = 0;
        if (!ParsePid(argv[2], &pid)) {
            fwprintf(stderr, L"invalid pid: %ls\n", argv[2]);
            return 3;
        }
        return Commit(pid);
    }
    if (argc == 3 && _wcsicmp(argv[1], L"--abort") == 0) {
        DWORD pid = 0;
        if (!ParsePid(argv[2], &pid)) {
            fwprintf(stderr, L"invalid pid: %ls\n", argv[2]);
            return 3;
        }
        return Abort(pid);
    }

    const bool deferred_commit = argc == 4 &&
        _wcsicmp(argv[1], L"--deferred") == 0;
    if (!deferred_commit) {
        fwprintf(stderr,
                 L"usage: NetrBridgeInjector --deferred <pid> <bridge.dll>\n"
                 L"       NetrBridgeInjector --commit <pid>\n"
                 L"       NetrBridgeInjector --abort <pid>\n");
        return 2;
    }

    const int pid_index = 2;
    const int dll_index = 3;
    DWORD pid = 0;
    if (!ParsePid(argv[pid_index], &pid)) {
        fwprintf(stderr, L"invalid pid: %ls\n", argv[pid_index]);
        return 3;
    }

    const DWORD attrs = GetFileAttributesW(argv[dll_index]);
    if (attrs == INVALID_FILE_ATTRIBUTES || (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0) {
        fwprintf(stderr, L"bridge DLL not found: %ls\n", argv[dll_index]);
        return 4;
    }
    return Inject(pid, argv[dll_index]);
}
