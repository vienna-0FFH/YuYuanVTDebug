#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <tlhelp32.h>

#include <cstddef>
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

std::wstring NormalizeModulePath(const wchar_t* path)
{
    if (!path || *path == L'\0') return {};
    std::wstring normalized(path);
    for (wchar_t& character : normalized) {
        if (character == L'/') character = L'\\';
    }
    if (normalized.rfind(L"\\\\?\\UNC\\", 0) == 0) {
        normalized = L"\\\\" + normalized.substr(8);
    } else if (normalized.rfind(L"\\\\?\\", 0) == 0) {
        normalized.erase(0, 4);
    }

    std::wstring full(32768, L'\0');
    const DWORD length = GetFullPathNameW(
        normalized.c_str(), static_cast<DWORD>(full.size()), full.data(), nullptr);
    if (length != 0 && length < full.size()) {
        full.resize(length);
        return full;
    }
    return normalized;
}

bool QueryFileIdentity(const wchar_t* path, BY_HANDLE_FILE_INFORMATION* identity)
{
    if (!path || !identity) return false;
    HANDLE file = CreateFileW(
        path,
        FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    const BOOL ok = GetFileInformationByHandle(file, identity);
    CloseHandle(file);
    return ok != FALSE;
}

bool SameFile(const wchar_t* first, const wchar_t* second)
{
    BY_HANDLE_FILE_INFORMATION first_identity = {};
    BY_HANDLE_FILE_INFORMATION second_identity = {};
    if (!QueryFileIdentity(first, &first_identity) ||
        !QueryFileIdentity(second, &second_identity)) {
        return false;
    }
    return first_identity.dwVolumeSerialNumber == second_identity.dwVolumeSerialNumber &&
           first_identity.nFileIndexHigh == second_identity.nFileIndexHigh &&
           first_identity.nFileIndexLow == second_identity.nFileIndexLow;
}

HANDLE CreateModuleSnapshot(DWORD pid)
{
    for (unsigned int attempt = 0; attempt < 8; ++attempt) {
        HANDLE snapshot = CreateToolhelp32Snapshot(
            TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (snapshot != INVALID_HANDLE_VALUE) return snapshot;
        if (GetLastError() != ERROR_BAD_LENGTH) break;
        Sleep(1);
    }
    return INVALID_HANDLE_VALUE;
}

uintptr_t FindRemoteModule(DWORD pid, const std::wstring& module_name)
{
    HANDLE snapshot = CreateModuleSnapshot(pid);
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

uintptr_t FindRemoteModuleByPath(DWORD pid, const wchar_t* module_path)
{
    const std::wstring expected = NormalizeModulePath(module_path);
    if (expected.empty()) return 0;

    HANDLE snapshot = CreateModuleSnapshot(pid);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    MODULEENTRY32W entry = {};
    entry.dwSize = sizeof(entry);
    uintptr_t result = 0;
    if (Module32FirstW(snapshot, &entry)) {
        do {
            const std::wstring candidate = NormalizeModulePath(entry.szExePath);
            if (_wcsicmp(candidate.c_str(), expected.c_str()) == 0 ||
                SameFile(entry.szExePath, module_path)) {
                result = reinterpret_cast<uintptr_t>(entry.modBaseAddr);
                break;
            }
        } while (Module32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return result;
}

uintptr_t ResolveRemoteKernel32Procedure(DWORD pid, const char* name)
{
    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    FARPROC procedure = kernel32 ? GetProcAddress(kernel32, name) : nullptr;
    if (!procedure) return 0;

    HMODULE owner = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            reinterpret_cast<LPCWSTR>(procedure), &owner)) {
        return 0;
    }

    wchar_t owner_path[MAX_PATH] = {};
    if (!GetModuleFileNameW(owner, owner_path, _countof(owner_path))) {
        return 0;
    }
    const uintptr_t remote_owner = FindRemoteModule(pid, BaseName(owner_path));
    if (!remote_owner) return 0;

    const uintptr_t rva = reinterpret_cast<uintptr_t>(procedure) -
                          reinterpret_cast<uintptr_t>(owner);
    return remote_owner + rva;
}

LPTHREAD_START_ROUTINE ResolveRemoteLoadLibraryW(DWORD pid)
{
    return reinterpret_cast<LPTHREAD_START_ROUTINE>(
        ResolveRemoteKernel32Procedure(pid, "LoadLibraryW"));
}

WORD ReadImageMachine(const wchar_t* path)
{
    HANDLE file = CreateFileW(
        path,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (file == INVALID_HANDLE_VALUE) return IMAGE_FILE_MACHINE_UNKNOWN;

    IMAGE_DOS_HEADER dos = {};
    DWORD read = 0;
    bool ok = ReadFile(file, &dos, sizeof(dos), &read, nullptr) != FALSE &&
              read == sizeof(dos) && dos.e_magic == IMAGE_DOS_SIGNATURE &&
              dos.e_lfanew > 0;
    DWORD signature = 0;
    IMAGE_FILE_HEADER header = {};
    if (ok) {
        LARGE_INTEGER offset = {};
        offset.QuadPart = dos.e_lfanew;
        ok = SetFilePointerEx(file, offset, nullptr, FILE_BEGIN) != FALSE &&
             ReadFile(file, &signature, sizeof(signature), &read, nullptr) != FALSE &&
             read == sizeof(signature) && signature == IMAGE_NT_SIGNATURE &&
             ReadFile(file, &header, sizeof(header), &read, nullptr) != FALSE &&
             read == sizeof(header);
    }
    CloseHandle(file);
    return ok ? header.Machine : IMAGE_FILE_MACHINE_UNKNOWN;
}

struct RemoteLoadContext {
    uintptr_t LoadLibraryExW;
    uintptr_t GetLastError;
    uintptr_t Path;
    uintptr_t Module;
    DWORD Error;
};

#ifdef _WIN64
static_assert(offsetof(RemoteLoadContext, Path) == 16);
static_assert(offsetof(RemoteLoadContext, Module) == 24);
static_assert(offsetof(RemoteLoadContext, Error) == 32);

const unsigned char kRemoteLoadCode[] = {
    0x53,
    0x48, 0x83, 0xEC, 0x20,
    0x48, 0x8B, 0xD9,
    0x48, 0x8B, 0x4B, 0x10,
    0x33, 0xD2,
    0x41, 0xB8, 0x00, 0x11, 0x00, 0x00,
    0xFF, 0x13,
    0x48, 0x89, 0x43, 0x18,
    0x48, 0x85, 0xC0,
    0x75, 0x0A,
    0xFF, 0x53, 0x08,
    0x89, 0x43, 0x20,
    0x33, 0xC0,
    0xEB, 0x0C,
    0xC7, 0x43, 0x20, 0x00, 0x00, 0x00, 0x00,
    0xB8, 0x01, 0x00, 0x00, 0x00,
    0x48, 0x83, 0xC4, 0x20,
    0x5B,
    0xC3,
};
#else
static_assert(offsetof(RemoteLoadContext, Path) == 8);
static_assert(offsetof(RemoteLoadContext, Module) == 12);
static_assert(offsetof(RemoteLoadContext, Error) == 16);

const unsigned char kRemoteLoadCode[] = {
    0x53,
    0x8B, 0x5C, 0x24, 0x08,
    0x68, 0x00, 0x11, 0x00, 0x00,
    0x6A, 0x00,
    0xFF, 0x73, 0x08,
    0xFF, 0x13,
    0x89, 0x43, 0x0C,
    0x85, 0xC0,
    0x75, 0x0A,
    0xFF, 0x53, 0x04,
    0x89, 0x43, 0x10,
    0x33, 0xC0,
    0xEB, 0x0C,
    0xC7, 0x43, 0x10, 0x00, 0x00, 0x00, 0x00,
    0xB8, 0x01, 0x00, 0x00, 0x00,
    0x5B,
    0xC2, 0x04, 0x00,
};
#endif

bool TryRemoteLoadLibraryEx(
    HANDLE process,
    DWORD pid,
    void* remote_path,
    uintptr_t* module,
    DWORD* loader_error,
    bool* remote_thread_pending)
{
    if (module) *module = 0;
    if (loader_error) *loader_error = ERROR_SUCCESS;
    if (remote_thread_pending) *remote_thread_pending = false;

    const uintptr_t load_library_ex =
        ResolveRemoteKernel32Procedure(pid, "LoadLibraryExW");
    const uintptr_t get_last_error =
        ResolveRemoteKernel32Procedure(pid, "GetLastError");
    if (!load_library_ex || !get_last_error) {
        SetLastError(ERROR_PROC_NOT_FOUND);
        return false;
    }

    RemoteLoadContext context = {};
    context.LoadLibraryExW = load_library_ex;
    context.GetLastError = get_last_error;
    context.Path = reinterpret_cast<uintptr_t>(remote_path);

    void* remote_context = VirtualAllocEx(
        process, nullptr, sizeof(context), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    void* remote_code = VirtualAllocEx(
        process, nullptr, sizeof(kRemoteLoadCode), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote_context || !remote_code) {
        const DWORD error = GetLastError();
        if (remote_context) VirtualFreeEx(process, remote_context, 0, MEM_RELEASE);
        if (remote_code) VirtualFreeEx(process, remote_code, 0, MEM_RELEASE);
        SetLastError(error);
        return false;
    }

    SIZE_T written = 0;
    if (!WriteProcessMemory(
            process, remote_context, &context, sizeof(context), &written) ||
        written != sizeof(context) ||
        !WriteProcessMemory(
            process, remote_code, kRemoteLoadCode, sizeof(kRemoteLoadCode), &written) ||
        written != sizeof(kRemoteLoadCode)) {
        const DWORD error = GetLastError();
        VirtualFreeEx(process, remote_code, 0, MEM_RELEASE);
        VirtualFreeEx(process, remote_context, 0, MEM_RELEASE);
        SetLastError(error);
        return false;
    }

    DWORD old_protection = 0;
    if (!VirtualProtectEx(
            process, remote_code, sizeof(kRemoteLoadCode), PAGE_EXECUTE_READ,
            &old_protection) ||
        !FlushInstructionCache(process, remote_code, sizeof(kRemoteLoadCode))) {
        const DWORD error = GetLastError();
        VirtualFreeEx(process, remote_code, 0, MEM_RELEASE);
        VirtualFreeEx(process, remote_context, 0, MEM_RELEASE);
        SetLastError(error);
        return false;
    }

    HANDLE thread = CreateRemoteThread(
        process,
        nullptr,
        0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(remote_code),
        remote_context,
        0,
        nullptr);
    if (!thread) {
        const DWORD error = GetLastError();
        VirtualFreeEx(process, remote_code, 0, MEM_RELEASE);
        VirtualFreeEx(process, remote_context, 0, MEM_RELEASE);
        SetLastError(error);
        return false;
    }

    const DWORD wait = WaitForSingleObject(thread, 10000);
    CloseHandle(thread);
    if (wait != WAIT_OBJECT_0) {
        if (remote_thread_pending) *remote_thread_pending = true;
        SetLastError(wait == WAIT_FAILED ? GetLastError() : ERROR_TIMEOUT);
        return false;
    }

    SIZE_T read = 0;
    const BOOL read_ok = ReadProcessMemory(
        process, remote_context, &context, sizeof(context), &read);
    const DWORD read_error = read_ok ? ERROR_SUCCESS : GetLastError();
    VirtualFreeEx(process, remote_code, 0, MEM_RELEASE);
    VirtualFreeEx(process, remote_context, 0, MEM_RELEASE);
    if (!read_ok || read != sizeof(context)) {
        SetLastError(read_error != ERROR_SUCCESS ? read_error : ERROR_PARTIAL_COPY);
        return false;
    }

    if (module) *module = context.Module;
    if (loader_error) *loader_error = context.Error;
    return true;
}

int Inject(DWORD pid, const wchar_t* dll_path, bool require_bridge_ready)
{
    const WORD image_machine = ReadImageMachine(dll_path);
#ifdef _WIN64
    static constexpr WORD expected_machine = IMAGE_FILE_MACHINE_AMD64;
    static constexpr const wchar_t* helper_architecture = L"x64";
#else
    static constexpr WORD expected_machine = IMAGE_FILE_MACHINE_I386;
    static constexpr const wchar_t* helper_architecture = L"x86";
#endif
    if (image_machine == IMAGE_FILE_MACHINE_UNKNOWN) {
        fwprintf(stderr, L"Invalid PE image or unreadable DLL: %ls\n", dll_path);
        return 5;
    }
    if (image_machine != expected_machine) {
        fwprintf(
            stderr,
            L"DLL machine mismatch: helper=%ls expected=0x%04X image=0x%04X path=%ls\n",
            helper_architecture,
            expected_machine,
            image_machine,
            dll_path);
        return 5;
    }

    const std::wstring dll_name = BaseName(dll_path);
    HANDLE ready = nullptr;
    if (require_bridge_ready) {
        wchar_t event_name[80] = {};
        _snwprintf_s(event_name, _countof(event_name), _TRUNCATE,
                     L"Local\\NetrBridgeReady-%lu", pid);
        ready = CreateEventW(nullptr, TRUE, FALSE, event_name);
        if (!ready) {
            fwprintf(stderr, L"CreateEvent failed: %lu\n", GetLastError());
            return 10;
        }
    }

    // A successful Bridge keeps this manual-reset event alive and signaled.
    // Therefore repeated injection requests still verify the driver handshake
    // instead of treating a merely loaded (possibly inert) DLL as success.
    const uintptr_t loaded_module = require_bridge_ready
        ? FindRemoteModule(pid, dll_name)
        : FindRemoteModuleByPath(pid, dll_path);
    if (loaded_module != 0) {
        if (!require_bridge_ready) {
            fwprintf(stdout, L"loader_success existing=1 module=%p\n",
                     reinterpret_cast<void*>(loaded_module));
            return 0;
        }
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
        if (ready) CloseHandle(ready);
        return 11;
    }

    const size_t bytes = (wcslen(dll_path) + 1) * sizeof(wchar_t);
    void* remote_path = VirtualAllocEx(process, nullptr, bytes,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote_path) {
        fwprintf(stderr, L"VirtualAllocEx failed: %lu\n", GetLastError());
        CloseHandle(process);
        if (ready) CloseHandle(ready);
        return 12;
    }

    SIZE_T written = 0;
    if (!WriteProcessMemory(process, remote_path, dll_path, bytes, &written) ||
        written != bytes) {
        fwprintf(stderr, L"WriteProcessMemory failed: %lu\n", GetLastError());
        VirtualFreeEx(process, remote_path, 0, MEM_RELEASE);
        CloseHandle(process);
        if (ready) CloseHandle(ready);
        return 13;
    }

    LPTHREAD_START_ROUTINE load_library = ResolveRemoteLoadLibraryW(pid);
    if (!load_library) {
        fwprintf(stderr, L"Cannot resolve remote LoadLibraryW\n");
        VirtualFreeEx(process, remote_path, 0, MEM_RELEASE);
        CloseHandle(process);
        if (ready) CloseHandle(ready);
        return 14;
    }

    HANDLE thread = CreateRemoteThread(process, nullptr, 0, load_library,
                                       remote_path, 0, nullptr);
    if (!thread) {
        fwprintf(stderr, L"CreateRemoteThread failed: %lu\n", GetLastError());
        VirtualFreeEx(process, remote_path, 0, MEM_RELEASE);
        CloseHandle(process);
        if (ready) CloseHandle(ready);
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
        if (ready) CloseHandle(ready);
        return 16;
    }

    // GetExitCodeThread exposes only DWORD, so an x64 HMODULE whose low
    // 32 bits are zero is indistinguishable from failure. Module enumeration
    // and the ready handshake are the architecture-neutral authorities.
    uintptr_t verified_module = require_bridge_ready
        ? FindRemoteModule(pid, dll_name)
        : FindRemoteModuleByPath(pid, dll_path);
    if (load_result == 0 && verified_module == 0) {
        uintptr_t extended_module = 0;
        DWORD loader_error = ERROR_SUCCESS;
        bool remote_thread_pending = false;
        if (TryRemoteLoadLibraryEx(
                process,
                pid,
                remote_path,
                &extended_module,
                &loader_error,
                &remote_thread_pending)) {
            verified_module = require_bridge_ready
                ? FindRemoteModule(pid, dll_name)
                : FindRemoteModuleByPath(pid, dll_path);
            if (extended_module != 0 || verified_module != 0) {
                fwprintf(
                    stdout,
                    L"loader_retry_success load_library_ex=%p verified=%p\n",
                    reinterpret_cast<void*>(extended_module),
                    reinterpret_cast<void*>(verified_module));
                load_result = static_cast<DWORD>(extended_module);
            } else {
                fwprintf(
                    stderr,
                    L"LoadLibraryW and LoadLibraryExW failed (wait=%lu, remote_win32=%lu)\n",
                    load_wait,
                    loader_error);
            }
        } else {
            fwprintf(
                stderr,
                L"LoadLibraryW failed and LoadLibraryExW retry infrastructure failed (wait=%lu, win32=%lu)\n",
                load_wait,
                GetLastError());
        }
        if (load_result == 0 && verified_module == 0) {
            if (!remote_thread_pending) {
                VirtualFreeEx(process, remote_path, 0, MEM_RELEASE);
            }
            CloseHandle(process);
            if (ready) CloseHandle(ready);
            return 16;
        }
    }

    VirtualFreeEx(process, remote_path, 0, MEM_RELEASE);

    if (!require_bridge_ready) {
        fwprintf(stdout,
                 L"loader_success existing=0 thread_exit=0x%08lX verified=%p\n",
                 load_result, reinterpret_cast<void*>(verified_module));
        CloseHandle(process);
        return 0;
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
    const bool plain_load = argc == 4 &&
        _wcsicmp(argv[1], L"--load") == 0;
    if (!deferred_commit && !plain_load) {
        fwprintf(stderr,
                 L"usage: NetrBridgeInjector --deferred <pid> <bridge.dll>\n"
                 L"       NetrBridgeInjector --load <pid> <dll>\n"
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
        fwprintf(stderr, L"DLL not found: %ls\n", argv[dll_index]);
        return 4;
    }
    return Inject(pid, argv[dll_index], deferred_commit);
}
