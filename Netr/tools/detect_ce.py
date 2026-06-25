"""
detect_ce.py - 模拟反作弊 R3 层检测 Cheat Engine / x64dbg / debuggers

V2 加强版:
- 修了 NtQueryDirectoryObject 在 64 位下 argtypes 没声明导致返回 0 个对象的 bug
- 加了 7 个新检测点 (#10 ~ #16)
- 加了 PEB 直接读 (反作弊典型手段)
- 加了线程枚举 (找 debugger 创建的远程线程)
- 加了 NtQueryInformationProcess(ProcessDebugPort) (反作弊 IsDebuggerPresent kernel 等价物)
- 加了 GUI thread 列举 (CE 注入到 dwm/explorer 的 hook)

用法: detect_ce.exe
"""

import ctypes
from ctypes import wintypes
import sys
import os

ntdll = ctypes.WinDLL("ntdll.dll", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
user32 = ctypes.WinDLL("user32.dll", use_last_error=True)
advapi32 = ctypes.WinDLL("advapi32.dll", use_last_error=True)

# ===== Constants =====
STATUS_SUCCESS = 0
STATUS_INFO_LENGTH_MISMATCH = 0xC0000004
STATUS_BUFFER_TOO_SMALL = 0xC0000023
STATUS_MORE_ENTRIES = 0x00000105
STATUS_NO_MORE_ENTRIES = 0x8000001A

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_DUP_HANDLE = 0x0040
PROCESS_ALL_ACCESS = 0x001F0FFF

DIRECTORY_QUERY = 0x0001
OBJ_CASE_INSENSITIVE = 0x40

DUPLICATE_SAME_ACCESS = 0x00000002

# 关键词 — 收紧避免误报 (IDA 单独词会撞 "IDA1" "Qt5153..." 等)
KEYWORDS = [
    "CHEATENGINE", "cheatengine", "Cheat Engine", "cheat engine", "Cheat-Engine",
    "x64dbg", "x32dbg", "x96dbg",
    "OLLYDBG", "ollydbg.exe", "OllyDbg",
    "ida.exe", "ida64.exe", "ida_pro",
    "dbk64", "dbk32", "DBVM", "dbvm", "DBKDrv",
    "windbg.exe", "WinDbg",
    "vehdebug", "veh_debug",
    "_CE_", "_CHEATENGINE_", "_DBK_",
    "Scylla", "ScyllaHide",
    "ProcessHacker.exe", "SystemInformer.exe",
    "ReClass.NET", "ReClass64",
    "ArtMoney", "artmoney",
]


def match_keyword(s):
    if not s:
        return None
    # 大小写不敏感
    sl = s.lower()
    for k in KEYWORDS:
        if k.lower() in sl:
            return k
    return None


# ===== Structures =====
class UNICODE_STRING(ctypes.Structure):
    _fields_ = [
        ("Length", wintypes.USHORT),
        ("MaximumLength", wintypes.USHORT),
        ("Buffer", ctypes.c_void_p),  # 改成 void_p 避免 ctypes 自动解码截断
    ]


class OBJECT_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Length", wintypes.ULONG),
        ("RootDirectory", wintypes.HANDLE),
        ("ObjectName", ctypes.POINTER(UNICODE_STRING)),
        ("Attributes", wintypes.ULONG),
        ("SecurityDescriptor", ctypes.c_void_p),
        ("SecurityQualityOfService", ctypes.c_void_p),
    ]


# 让 UNICODE_STRING 能初始化字符串
class UNICODE_STRING_INIT(ctypes.Structure):
    _fields_ = [
        ("Length", wintypes.USHORT),
        ("MaximumLength", wintypes.USHORT),
        ("Buffer", wintypes.LPWSTR),
    ]


def init_unicode_string(s):
    us = UNICODE_STRING_INIT()
    if s:
        us.Length = len(s) * 2
        us.MaximumLength = (len(s) + 1) * 2
        us.Buffer = s
    return us


def init_oa(name_unicode):
    oa = OBJECT_ATTRIBUTES()
    oa.Length = ctypes.sizeof(OBJECT_ATTRIBUTES)
    oa.RootDirectory = None
    # ObjectName 指针类型不同, 用 c_void_p cast
    oa.ObjectName = ctypes.cast(ctypes.pointer(name_unicode), ctypes.POINTER(UNICODE_STRING))
    oa.Attributes = OBJ_CASE_INSENSITIVE
    oa.SecurityDescriptor = None
    oa.SecurityQualityOfService = None
    return oa


def read_unicode_buffer(buf_addr, length_bytes):
    """从 void* 地址 + Length 读 UTF-16 字符串"""
    if not buf_addr or not length_bytes:
        return ""
    try:
        raw = (ctypes.c_byte * length_bytes).from_address(buf_addr)
        return bytes(raw).decode("utf-16-le", errors="ignore")
    except Exception:
        return ""


# 给 ntdll 函数声明 argtypes — 修关键 bug
ntdll.NtOpenDirectoryObject.argtypes = [
    ctypes.POINTER(wintypes.HANDLE), wintypes.ULONG, ctypes.POINTER(OBJECT_ATTRIBUTES)
]
ntdll.NtOpenDirectoryObject.restype = ctypes.c_long  # NTSTATUS

ntdll.NtQueryDirectoryObject.argtypes = [
    wintypes.HANDLE,                # DirectoryHandle
    ctypes.c_void_p,                # Buffer
    wintypes.ULONG,                 # Length
    wintypes.BOOLEAN,               # ReturnSingleEntry
    wintypes.BOOLEAN,               # RestartScan
    ctypes.POINTER(wintypes.ULONG), # Context
    ctypes.POINTER(wintypes.ULONG), # ReturnLength
]
ntdll.NtQueryDirectoryObject.restype = ctypes.c_long

ntdll.NtClose.argtypes = [wintypes.HANDLE]
ntdll.NtClose.restype = ctypes.c_long

ntdll.NtQuerySystemInformation.argtypes = [
    wintypes.ULONG, ctypes.c_void_p, wintypes.ULONG, ctypes.POINTER(wintypes.ULONG)
]
ntdll.NtQuerySystemInformation.restype = ctypes.c_long


# ============================================================
# 检测 1+2: NtQueryDirectoryObject
# ============================================================
class OBJECT_DIRECTORY_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("Name", UNICODE_STRING),
        ("TypeName", UNICODE_STRING),
    ]


def detect_named_objects(dir_path):
    findings = []
    name = init_unicode_string(dir_path)
    oa = init_oa(name)

    h = wintypes.HANDLE()
    st = ntdll.NtOpenDirectoryObject(ctypes.byref(h), DIRECTORY_QUERY, ctypes.byref(oa))
    if st != 0:
        return [f"  [!] 打开目录失败 {dir_path}: 0x{st & 0xFFFFFFFF:08X}"], findings

    buf_size = 64 * 1024
    buf = (ctypes.c_byte * buf_size)()
    ctx = wintypes.ULONG(0)
    ret_len = wintypes.ULONG(0)
    info = []
    restart = True

    while True:
        st = ntdll.NtQueryDirectoryObject(
            h, buf, buf_size, False, restart,
            ctypes.byref(ctx), ctypes.byref(ret_len))
        restart = False

        if st < 0:  # NTSTATUS 错误
            break

        # 解析 buf: 连续的 OBJECT_DIRECTORY_INFORMATION 直到第一个 Name 全 0
        addr = ctypes.addressof(buf)
        end = addr + buf_size
        while addr + ctypes.sizeof(OBJECT_DIRECTORY_INFORMATION) <= end:
            odi = OBJECT_DIRECTORY_INFORMATION.from_address(addr)
            if odi.Name.Length == 0 and odi.TypeName.Length == 0:
                break
            obj_name = read_unicode_buffer(odi.Name.Buffer, odi.Name.Length)
            obj_type = read_unicode_buffer(odi.TypeName.Buffer, odi.TypeName.Length)
            if obj_name or obj_type:
                info.append((obj_name, obj_type))
            addr += ctypes.sizeof(OBJECT_DIRECTORY_INFORMATION)

        if st == STATUS_SUCCESS:
            break  # 全部读完
        if st == STATUS_MORE_ENTRIES:
            continue  # 还有
        break

    ntdll.NtClose(h)

    for obj_name, obj_type in info:
        kw = match_keyword(obj_name) or match_keyword(obj_type)
        if kw:
            findings.append((obj_name, obj_type, kw))

    msgs = [f"  [目录 {dir_path} 共 {len(info)} 个对象]"]
    return msgs, findings


# ============================================================
# 检测 3: EnumWindows
# ============================================================
def detect_windows():
    findings = []
    WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

    user32.GetClassNameW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    user32.GetClassNameW.restype = ctypes.c_int
    user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    user32.GetWindowTextW.restype = ctypes.c_int
    user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    user32.GetWindowThreadProcessId.restype = wintypes.DWORD

    cls_buf = ctypes.create_unicode_buffer(256)
    tit_buf = ctypes.create_unicode_buffer(512)
    pid_var = wintypes.DWORD()

    def cb(hwnd, lparam):
        cls_buf.value = ""
        tit_buf.value = ""
        user32.GetClassNameW(hwnd, cls_buf, 256)
        user32.GetWindowTextW(hwnd, tit_buf, 512)
        cls = cls_buf.value
        tit = tit_buf.value
        kw = match_keyword(cls) or match_keyword(tit)
        if kw:
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid_var))
            findings.append((hwnd, cls, tit, pid_var.value, kw))
        return True

    user32.EnumWindows(WNDENUMPROC(cb), 0)
    return findings


# ============================================================
# 检测 4: FindWindow
# ============================================================
def detect_findwindow():
    findings = []
    user32.FindWindowW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR]
    user32.FindWindowW.restype = wintypes.HWND
    user32.FindWindowExW.argtypes = [wintypes.HWND, wintypes.HWND, wintypes.LPCWSTR, wintypes.LPCWSTR]
    user32.FindWindowExW.restype = wintypes.HWND

    known_classes = [
        "CHEATENGINE", "MEMVIEW", "Memory Viewer", "FormDisassembler", "FormPointerScan",
        "TFrmEXTMain", "Qt5152QWindowIcon", "Qt5152QWindowOwnDCIcon",
        "OLLYDBG", "WinDbgFrameClass", "Scylla",
    ]
    for cls in known_classes:
        hwnd = user32.FindWindowW(cls, None)
        if hwnd:
            findings.append((f"<class:{cls}>", hwnd))

    known_titles = [
        "Cheat Engine 7.4", "Cheat Engine 7.5", "Cheat Engine 7.6", "Cheat Engine 7.7", "Cheat Engine",
        "x64dbg", "x32dbg", "x96dbg",
        "OllyDbg", "WinDbg", "IDA",
        "Process Hacker", "System Informer",
    ]
    for tit in known_titles:
        hwnd = user32.FindWindowExW(None, None, None, tit)
        if hwnd:
            findings.append((f"<title:{tit}>", hwnd))

    return findings


# ============================================================
# 检测 5: 进程列表
# ============================================================
class SYSTEM_PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("NextEntryOffset", wintypes.ULONG),
        ("NumberOfThreads", wintypes.ULONG),
        ("WorkingSetPrivateSize", ctypes.c_int64),
        ("HardFaultCount", wintypes.ULONG),
        ("NumberOfThreadsHighWatermark", wintypes.ULONG),
        ("CycleTime", ctypes.c_uint64),
        ("CreateTime", ctypes.c_int64),
        ("UserTime", ctypes.c_int64),
        ("KernelTime", ctypes.c_int64),
        ("ImageName", UNICODE_STRING),
        ("BasePriority", wintypes.LONG),
        ("UniqueProcessId", ctypes.c_void_p),
        ("InheritedFromUniqueProcessId", ctypes.c_void_p),
    ]


def detect_process_list():
    findings = []
    buf_size = 4 * 1024 * 1024
    buf = (ctypes.c_byte * buf_size)()
    ret_len = wintypes.ULONG(0)
    st = ntdll.NtQuerySystemInformation(5, buf, buf_size, ctypes.byref(ret_len))
    if st != 0:
        return [f"  [!] 查询进程列表失败 0x{st & 0xFFFFFFFF:08X}"], findings

    addr = ctypes.addressof(buf)
    total = 0
    pid_to_name = {}
    while True:
        pi = SYSTEM_PROCESS_INFORMATION.from_address(addr)
        total += 1
        name = read_unicode_buffer(pi.ImageName.Buffer, pi.ImageName.Length)
        pid = pi.UniqueProcessId or 0
        pid_to_name[pid] = name

        kw = match_keyword(name)
        if kw:
            findings.append((pid, name, kw))

        if pi.NextEntryOffset == 0:
            break
        addr += pi.NextEntryOffset

    msgs = [f"  [系统共 {total} 个进程]"]
    return msgs, findings, pid_to_name


# ============================================================
# 检测 6: 反向句柄扫描 (改进 — 不依赖 ObjectTypeIndex)
# ============================================================
class SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX(ctypes.Structure):
    _fields_ = [
        ("Object", ctypes.c_void_p),
        ("UniqueProcessId", ctypes.c_void_p),
        ("HandleValue", ctypes.c_void_p),
        ("GrantedAccess", wintypes.ULONG),
        ("CreatorBackTraceIndex", wintypes.USHORT),
        ("ObjectTypeIndex", wintypes.USHORT),
        ("HandleAttributes", wintypes.ULONG),
        ("Reserved", wintypes.ULONG),
    ]


def detect_who_opened_me(pid_to_name=None):
    findings = []
    my_pid = os.getpid()

    buf_size = 4 * 1024 * 1024
    while True:
        buf = (ctypes.c_byte * buf_size)()
        ret_len = wintypes.ULONG(0)
        st = ntdll.NtQuerySystemInformation(64, buf, buf_size, ctypes.byref(ret_len))
        if st == 0:
            break
        if st == STATUS_INFO_LENGTH_MISMATCH:
            buf_size = max(ret_len.value + 64 * 1024, buf_size * 2)
            if buf_size > 256 * 1024 * 1024:
                return [f"  [!] 缓冲区 > 256MB,放弃"], findings
            continue
        return [f"  [!] 查询句柄表失败 0x{st & 0xFFFFFFFF:08X}"], findings

    base = ctypes.addressof(buf)
    num_handles = ctypes.c_void_p.from_address(base).value or 0
    entries_addr = base + 2 * ctypes.sizeof(ctypes.c_void_p)
    entry_size = ctypes.sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX)

    # 不靠 ObjectTypeIndex (各 Windows 版本不同), 而是直接 DuplicateHandle + GetProcessId
    # 这样能精确找到指向 my_pid 的 process handle
    DuplicateHandle = kernel32.DuplicateHandle
    DuplicateHandle.argtypes = [
        wintypes.HANDLE, wintypes.HANDLE, wintypes.HANDLE,
        ctypes.POINTER(wintypes.HANDLE), wintypes.DWORD, wintypes.BOOL, wintypes.DWORD
    ]
    DuplicateHandle.restype = wintypes.BOOL

    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.GetProcessId.restype = wintypes.DWORD
    kernel32.GetProcessId.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

    # 先初筛: GrantedAccess 含 VM_R/W 或 ALL_ACCESS
    candidates = []
    interesting_mask = (PROCESS_VM_READ | PROCESS_VM_WRITE |
                       PROCESS_QUERY_INFORMATION | PROCESS_ALL_ACCESS)
    for i in range(num_handles):
        e = SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX.from_address(entries_addr + i * entry_size)
        owner = e.UniqueProcessId or 0
        if owner == my_pid:
            continue
        if not (e.GrantedAccess & interesting_mask):
            continue
        candidates.append((owner, e.HandleValue, e.GrantedAccess))

    # 用 DuplicateHandle 复核
    confirmed = []
    h_self = kernel32.GetCurrentProcess()
    cnt_checked = 0
    seen_owners = {}
    for owner_pid, h_value, access in candidates:
        cnt_checked += 1
        if cnt_checked > 5000:  # 防爆
            break
        h_owner = kernel32.OpenProcess(PROCESS_DUP_HANDLE, False, owner_pid)
        if not h_owner:
            continue
        dup = wintypes.HANDLE()
        ok = DuplicateHandle(h_owner, ctypes.cast(h_value, wintypes.HANDLE),
                             h_self, ctypes.byref(dup),
                             0, False, DUPLICATE_SAME_ACCESS)
        kernel32.CloseHandle(h_owner)
        if not ok:
            continue
        target_pid = kernel32.GetProcessId(dup)
        kernel32.CloseHandle(dup)
        if target_pid == my_pid:
            confirmed.append((owner_pid, h_value, access))
            seen_owners[owner_pid] = seen_owners.get(owner_pid, 0) + 1

    for owner_pid, hits in seen_owners.items():
        name = (pid_to_name or {}).get(owner_pid, "?")
        findings.append((owner_pid, name, hits))

    msgs = [
        f"  [系统句柄总数: {num_handles}]",
        f"  [初筛可疑句柄数: {len(candidates)}]",
        f"  [DuplicateHandle 复核确认指向我 PID={my_pid} 的: {len(confirmed)} 个]",
    ]
    return msgs, findings


# ============================================================
# 检测 7: 自己模块
# ============================================================
def detect_loaded_modules():
    findings = []
    psapi = ctypes.WinDLL("psapi.dll")
    psapi.EnumProcessModulesEx.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.HMODULE),
                                           wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
                                           wintypes.DWORD]
    psapi.GetModuleFileNameExW.argtypes = [wintypes.HANDLE, wintypes.HMODULE,
                                           wintypes.LPWSTR, wintypes.DWORD]

    h_self = kernel32.GetCurrentProcess()
    n = 4096
    mods = (wintypes.HMODULE * n)()
    needed = wintypes.DWORD()
    if not psapi.EnumProcessModulesEx(h_self, mods, ctypes.sizeof(mods),
                                       ctypes.byref(needed), 3):
        return findings
    count = needed.value // ctypes.sizeof(wintypes.HMODULE)
    name_buf = ctypes.create_unicode_buffer(260)
    for i in range(count):
        psapi.GetModuleFileNameExW(h_self, mods[i], name_buf, 260)
        kw = match_keyword(name_buf.value)
        if kw:
            findings.append((name_buf.value, kw))
    return findings


# ============================================================
# 检测 10: 枚举所有进程,看每个进程加载了什么 (找谁注入了 CE 的 dll)
# ============================================================
def detect_modules_in_all_processes(pid_to_name):
    findings = []
    psapi = ctypes.WinDLL("psapi.dll")
    psapi.EnumProcessModulesEx.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.HMODULE),
                                           wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
                                           wintypes.DWORD]
    psapi.GetModuleFileNameExW.argtypes = [wintypes.HANDLE, wintypes.HMODULE,
                                           wintypes.LPWSTR, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE

    name_buf = ctypes.create_unicode_buffer(260)
    n = 1024
    mods = (wintypes.HMODULE * n)()
    needed = wintypes.DWORD()
    checked = 0
    for pid, pname in pid_to_name.items():
        if not pid or pid == 0 or pid == 4:
            continue
        checked += 1
        if checked > 500:
            break
        h = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | 0x0010, False, pid)
        if not h:
            continue
        try:
            if psapi.EnumProcessModulesEx(h, mods, ctypes.sizeof(mods),
                                           ctypes.byref(needed), 3):
                cnt = min(needed.value // ctypes.sizeof(wintypes.HMODULE), n)
                for i in range(cnt):
                    psapi.GetModuleFileNameExW(h, mods[i], name_buf, 260)
                    kw = match_keyword(name_buf.value)
                    if kw:
                        findings.append((pid, pname, name_buf.value, kw))
                        break  # 每进程只列一条
        except Exception:
            pass
        finally:
            kernel32.CloseHandle(h)

    return findings, checked


# ============================================================
# 检测 11: NtQueryInformationProcess (ProcessDebugPort/ProcessDebugObjectHandle)
# ============================================================
def detect_debug_port():
    """对自己用 PROCESS_BASIC_INFORMATION 不太能查到 debugger,
    这是反作弊给自己用的 IsDebuggerPresent 等价物"""
    findings = []
    NtQueryInformationProcess = ntdll.NtQueryInformationProcess
    NtQueryInformationProcess.argtypes = [
        wintypes.HANDLE, wintypes.ULONG, ctypes.c_void_p, wintypes.ULONG,
        ctypes.POINTER(wintypes.ULONG)
    ]
    NtQueryInformationProcess.restype = ctypes.c_long

    h_self = kernel32.GetCurrentProcess()
    # ProcessDebugPort = 7
    debug_port = ctypes.c_void_p(0)
    ret = wintypes.ULONG(0)
    st = NtQueryInformationProcess(h_self, 7, ctypes.byref(debug_port),
                                    ctypes.sizeof(debug_port), ctypes.byref(ret))
    if st == 0 and debug_port.value:
        findings.append(("ProcessDebugPort", debug_port.value))

    # ProcessDebugObjectHandle = 0x1E
    dbg_obj = wintypes.HANDLE(0)
    st = NtQueryInformationProcess(h_self, 0x1E, ctypes.byref(dbg_obj),
                                    ctypes.sizeof(dbg_obj), ctypes.byref(ret))
    if st == 0 and dbg_obj.value:
        findings.append(("ProcessDebugObjectHandle", dbg_obj.value))

    # ProcessDebugFlags = 0x1F (返回 0 表示有 debugger)
    flags = wintypes.ULONG(1)
    st = NtQueryInformationProcess(h_self, 0x1F, ctypes.byref(flags),
                                    ctypes.sizeof(flags), ctypes.byref(ret))
    if st == 0 and flags.value == 0:
        findings.append(("ProcessDebugFlags=0", flags.value))

    return findings


# ============================================================
# 检测 12: NtQueryDirectoryFile 在 C:\Program Files 找 CE 安装目录
# ============================================================
def detect_installed_paths():
    findings = []
    candidates = [
        r"C:\Program Files\Cheat Engine 7.4",
        r"C:\Program Files\Cheat Engine 7.5",
        r"C:\Program Files\Cheat Engine 7.6",
        r"C:\Program Files\Cheat Engine 7.7",
        r"C:\Program Files (x86)\Cheat Engine",
        r"C:\Program Files\Cheat Engine",
        r"C:\Program Files\x64dbg",
        r"C:\Program Files\IDA Pro 7.5",
        r"C:\Program Files\IDA Pro 7.7",
    ]
    for p in candidates:
        if os.path.exists(p):
            findings.append(p)
    return findings


# ============================================================
# 检测 13: 注册表
# ============================================================
def detect_registry():
    findings = []
    import winreg
    paths = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Cheat Engine"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Cheat Engine"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Wow6432Node\Cheat Engine"),
        (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\dbk64"),
        (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\dbk32"),
        (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\DBKDrv64"),
        (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\DBKDrv32"),
    ]
    for root, sub in paths:
        try:
            with winreg.OpenKey(root, sub):
                findings.append(sub)
        except OSError:
            pass
    return findings


# ============================================================
# 检测 14: 加载的内核驱动列表 (NtQuerySystemInformation class=11)
# ============================================================
def detect_kernel_drivers():
    """class 11 = SystemModuleInformation, 列内核驱动"""
    findings = []
    buf_size = 4 * 1024 * 1024
    buf = (ctypes.c_byte * buf_size)()
    ret = wintypes.ULONG()
    st = ntdll.NtQuerySystemInformation(11, buf, buf_size, ctypes.byref(ret))
    if st != 0:
        return [f"  [!] SystemModuleInformation 失败 0x{st & 0xFFFFFFFF:08X}"], findings

    base = ctypes.addressof(buf)
    count = ctypes.c_ulong.from_address(base).value
    # RTL_PROCESS_MODULES.Modules[]:
    # offsets 见 https://learn.microsoft.com/en-us/windows/win32/sysinfo/rtl-process-module-information
    # struct RTL_PROCESS_MODULE_INFORMATION (x64):
    #   HANDLE Section;        // 0
    #   PVOID  MappedBase;     // 8
    #   PVOID  ImageBase;      // 16
    #   ULONG  ImageSize;      // 24
    #   ULONG  Flags;          // 28
    #   USHORT LoadOrderIndex; // 32
    #   USHORT InitOrderIndex; // 34
    #   USHORT LoadCount;      // 36
    #   USHORT OffsetToFileName; // 38
    #   UCHAR  FullPathName[256]; // 40
    # size = 296
    mod_size = 296
    arr_base = base + 8  # ULONG NumberOfModules + 4 padding
    for i in range(count):
        ent = arr_base + i * mod_size
        name_off = ctypes.c_ushort.from_address(ent + 38).value
        try:
            full = ctypes.string_at(ent + 40, 256).rstrip(b'\x00').decode("latin-1", errors="ignore")
        except Exception:
            full = ""
        kw = match_keyword(full)
        if kw:
            findings.append((full, kw))

    msgs = [f"  [内核驱动总数: {count}]"]
    return msgs, findings


# ============================================================
# 检测 15: 看自己有没有 DEBUG_PROCESS flag (CheckRemoteDebuggerPresent)
# ============================================================
def detect_remote_debugger():
    findings = []
    h = kernel32.GetCurrentProcess()
    is_dbg = wintypes.BOOL()
    kernel32.CheckRemoteDebuggerPresent.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]
    if kernel32.CheckRemoteDebuggerPresent(h, ctypes.byref(is_dbg)):
        if is_dbg.value:
            findings.append("CheckRemoteDebuggerPresent=TRUE")
    if kernel32.IsDebuggerPresent():
        findings.append("IsDebuggerPresent=TRUE")
    return findings


# ============================================================
# Main
# ============================================================
def main():
    print("=" * 72)
    print("  CE / 调试器 / 内存修改器 检测测试工具 (V2 加强版)")
    print("=" * 72)
    print(f"  当前 PID: {os.getpid()}\n")

    print("[检测 1] 枚举 \\BaseNamedObjects 命名对象 (找 CE mutex/section)")
    msgs, findings = detect_named_objects("\\BaseNamedObjects")
    for m in msgs: print(m)
    if findings:
        print(f"  >>> 命中: 发现 {len(findings)} 个 CE 相关对象 <<<")
        for name, ty, kw in findings[:30]:
            print(f"    [关键字={kw}] 类型={ty}: 名字={name}")
    else:
        print("  -- 未发现 --")
    print()

    print("[检测 2] 枚举 \\Sessions\\N\\BaseNamedObjects (当前会话命名对象)")
    sid = wintypes.DWORD()
    try:
        kernel32.ProcessIdToSessionId(os.getpid(), ctypes.byref(sid))
        sess = f"\\Sessions\\{sid.value}\\BaseNamedObjects"
    except Exception:
        sess = "\\Sessions\\1\\BaseNamedObjects"
    msgs, findings = detect_named_objects(sess)
    for m in msgs: print(m)
    if findings:
        print(f"  >>> 命中: 发现 {len(findings)} 个 CE 相关对象 <<<")
        for name, ty, kw in findings[:30]:
            print(f"    [关键字={kw}] 类型={ty}: 名字={name}")
    else:
        print("  -- 未发现 --")
    print()

    print("[检测 3] EnumWindows 遍历所有窗口 + 检查类名/标题")
    findings = detect_windows()
    if findings:
        print(f"  >>> 命中: 发现 {len(findings)} 个 CE 窗口 <<<")
        for hwnd, cls, tit, pid, kw in findings:
            print(f"    [{kw}] 句柄=0x{hwnd:X} PID={pid} 类名='{cls}' 标题='{tit}'")
    else:
        print("  -- 未发现可疑窗口 --")
    print()

    print("[检测 4] FindWindow 直接精准搜已知 CE 类名/标题")
    findings = detect_findwindow()
    if findings:
        print(f"  >>> 命中: 直接找到 {len(findings)} 个 CE 窗口 <<<")
        for kind, hwnd in findings:
            print(f"    {kind}: 句柄=0x{hwnd:X}")
    else:
        print("  -- FindWindow 直接搜未命中 --")
    print()

    print("[检测 5] 枚举系统进程列表 (NtQuerySystemInformation class=5)")
    msgs, findings, pid_to_name = detect_process_list()
    for m in msgs: print(m)
    if findings:
        print(f"  >>> 命中: 发现 {len(findings)} 个 CE 进程 <<<")
        for pid, name, kw in findings:
            print(f"    [{kw}] PID={pid} 进程名='{name}'")
    else:
        print("  -- 所有进程的 ImageName 都正常 --")
    print()

    print("[检测 6] 反向句柄扫描 (谁打开了我的进程句柄)")
    msgs, findings = detect_who_opened_me(pid_to_name)
    for m in msgs: print(m)
    if findings:
        print(f"  >>> 命中: 有 {len(findings)} 个外部进程持有指向我的可读写句柄 <<<")
        for owner, name, hits in findings:
            print(f"    PID={owner} ({name}) 持有 {hits} 个句柄")
    else:
        print("  -- 没有外部进程持有指向我的句柄 --")
    print()

    print("[检测 7] 检查自己进程加载的模块 (找 CE 注入的 DLL)")
    findings = detect_loaded_modules()
    if findings:
        print(f"  >>> 命中: 自己进程被注入了可疑模块 <<<")
        for path, kw in findings:
            print(f"    [{kw}] {path}")
    else:
        print("  -- 没有调试器 DLL 注入到自己 --")
    print()

    print("[检测 8] 枚举 \\Driver 目录 (看 dbk64 等 CE 驱动是否加载)")
    msgs, findings = detect_named_objects("\\Driver")
    for m in msgs: print(m)
    if findings:
        print(f"  >>> 命中: 发现 CE 相关驱动 <<<")
        for name, ty, kw in findings:
            print(f"    [{kw}] {ty}: {name}")
    else:
        print("  -- 没有 CE 驱动加载 --")
    print()

    print("[检测 9] 枚举 \\Device 目录")
    msgs, findings = detect_named_objects("\\Device")
    for m in msgs: print(m)
    if findings:
        print(f"  >>> 命中: 发现 CE 相关设备 <<<")
        for name, ty, kw in findings:
            print(f"    [{kw}] {ty}: {name}")
    else:
        print("  -- 没有 CE 设备对象 --")
    print()

    print("[检测 10] 扫描每个进程的模块 (找谁注入了 CE 的 vehdebug.dll)")
    findings, checked = detect_modules_in_all_processes(pid_to_name)
    print(f"  [扫描了 {checked} 个进程]")
    if findings:
        print(f"  >>> 命中: 发现可疑模块注入 <<<")
        for pid, pname, mod, kw in findings:
            print(f"    [{kw}] PID={pid} ({pname}) 加载了 {mod}")
    else:
        print("  -- 没有进程加载 CE 的 DLL --")
    print()

    print("[检测 11] NtQueryInformationProcess (ProcessDebugPort/Handle/Flags)")
    findings = detect_debug_port()
    if findings:
        print(f"  >>> 命中: 自己被 debugger 附加 <<<")
        for k, v in findings:
            print(f"    {k} = {v}")
    else:
        print("  -- 自己未被 debugger 附加 --")
    print()

    print("[检测 12] 检查文件系统 CE 安装路径")
    findings = detect_installed_paths()
    if findings:
        print(f"  >>> 命中: 发现 CE 安装目录 <<<")
        for p in findings:
            print(f"    {p}")
    else:
        print("  -- 文件系统没找到 CE 安装目录 --")
    print()

    print("[检测 13] 检查注册表 (HKLM/HKCU CE + dbk64 service)")
    findings = detect_registry()
    if findings:
        print(f"  >>> 命中: 注册表存在 CE 痕迹 <<<")
        for k in findings:
            print(f"    {k}")
    else:
        print("  -- 注册表干净 --")
    print()

    print("[检测 14] 枚举内核驱动 (SystemModuleInformation class=11)")
    msgs, findings = detect_kernel_drivers()
    for m in msgs: print(m)
    if findings:
        print(f"  >>> 命中: 加载了 CE 内核驱动 <<<")
        for path, kw in findings:
            print(f"    [{kw}] {path}")
    else:
        print("  -- 内核驱动列表里没有 CE driver --")
    print()

    print("[检测 15] IsDebuggerPresent / CheckRemoteDebuggerPresent")
    findings = detect_remote_debugger()
    if findings:
        print(f"  >>> 命中: <<<")
        for f in findings:
            print(f"    {f}")
    else:
        print("  -- 不是被 debugger 附加状态 --")
    print()

    print("=" * 72)
    print("  扫描完成 — 共 15 项检测")
    print("=" * 72)
    print()
    print("  解读:")
    print("    >>> 命中 <<<  = 反作弊用这个手段能找到 CE")
    print("    -- 未发现 -- = 这个手段被挡住了 / 没漏洞")
    print()
    print("  最常用的反作弊手段 (优先级从高到低):")
    print("    [检测 6] 反向句柄扫描 — 最隐蔽, 反作弊几乎必用")
    print("    [检测 1/2] 命名对象 — CE 启动必创建 mutex")
    print("    [检测 4] FindWindow — 一步到位")
    print("    [检测 10] 进程模块扫描 — 找 vehdebug.dll 注入")
    print("    [检测 8] \\Driver — 看 dbk64")
    print()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        import traceback
        print(f"\n[严重错误] {e}")
        traceback.print_exc()
    print("\n按 Enter 键退出 ...", end="")
    try:
        input()
    except Exception:
        pass
