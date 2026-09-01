"""ctypes mirrors of the kernel-side IOCTL structures.

All structures are declared with ``_pack_ = 1`` because the driver wraps every
typedef in ``#pragma pack(push, 1)`` (see ``Driver.c`` lines 75-208). Python
will therefore compute the same byte offsets and ``ctypes.sizeof`` as the
kernel ``sizeof()``.

Naming follows the kernel header (PascalCase fields) so a side-by-side read
with ``Driver.c`` stays obvious.
"""

from __future__ import annotations

import ctypes
from ctypes import c_int16, c_ubyte, c_uint32, c_uint64, c_wchar


# ----------------------------------------------------------------- status codes

HV_STATUS_SUCCESS              = 0
HV_STATUS_ERROR                = 1
HV_STATUS_NOT_INITIALIZED      = 2
HV_STATUS_INVALID_PARAMETER    = 3
HV_STATUS_NOT_FOUND            = 4
HV_STATUS_ALREADY_EXISTS       = 5
HV_STATUS_ACCESS_DENIED        = 6
HV_STATUS_INSUFFICIENT_BUFFER  = 7

HV_STATUS_NAMES = {
    HV_STATUS_SUCCESS:              "HV_STATUS_SUCCESS",
    HV_STATUS_ERROR:                "HV_STATUS_ERROR",
    HV_STATUS_NOT_INITIALIZED:      "HV_STATUS_NOT_INITIALIZED",
    HV_STATUS_INVALID_PARAMETER:    "HV_STATUS_INVALID_PARAMETER",
    HV_STATUS_NOT_FOUND:            "HV_STATUS_NOT_FOUND",
    HV_STATUS_ALREADY_EXISTS:       "HV_STATUS_ALREADY_EXISTS",
    HV_STATUS_ACCESS_DENIED:        "HV_STATUS_ACCESS_DENIED",
    HV_STATUS_INSUFFICIENT_BUFFER:  "HV_STATUS_INSUFFICIENT_BUFFER",
}


# 驱动侧 MEMORY_READ/WRITE/ALLOC 在失败时把原始 NTSTATUS 直接塞进 pResult->Status
# (避免被 IO Manager 抹成 Win32 87)。NTSTATUS failure 都 ≥ 0x80000000,绝不和
# HV_STATUS_* (0..7) 重叠,Python 端按高位区分。
NTSTATUS_NAMES = {
    0x00000000: "STATUS_SUCCESS",
    0xC0000001: "STATUS_UNSUCCESSFUL",
    0xC0000002: "STATUS_NOT_IMPLEMENTED",
    0xC0000005: "STATUS_ACCESS_VIOLATION",
    0xC0000008: "STATUS_INVALID_HANDLE",
    0xC000000B: "STATUS_INVALID_CID",                  # 进程 ID 不存在 (PID=1, 已退出, ...)
    0xC000000D: "STATUS_INVALID_PARAMETER",
    0xC0000017: "STATUS_NO_MEMORY",
    0xC0000022: "STATUS_ACCESS_DENIED",
    0xC0000023: "STATUS_BUFFER_TOO_SMALL",
    0xC0000034: "STATUS_OBJECT_NAME_NOT_FOUND",
    0xC000009A: "STATUS_INSUFFICIENT_RESOURCES",
    0xC00000A3: "STATUS_DEVICE_NOT_READY",
    0xC00000BB: "STATUS_NOT_SUPPORTED",
    0xC00000F0: "STATUS_INVALID_ADDRESS",
    0xC0000123: "STATUS_INVALID_LEVEL",                # IRQL > APC_LEVEL
    0xC0000139: "STATUS_ENTRYPOINT_NOT_FOUND",
    0xC0000142: "STATUS_DLL_INIT_FAILED",
    0xC0000184: "STATUS_INVALID_DEVICE_STATE",
    0xC0000207: "STATUS_INVALID_ADDRESS_COMPONENT",    # GVA 在目标 CR3 里未映射 (PML4/PDPT/PD entry 不 present)
    0xC0000225: "STATUS_NOT_FOUND",                    # PT entry 不 present / DTB=0
    0xC00002C5: "STATUS_DATATYPE_MISALIGNMENT_ERROR",
}


# 给最常见的 NTSTATUS 一段人话解释,贴在 NetrError 的 msg 后面让用户知道下一步该做什么。
NTSTATUS_HINTS = {
    0xC000000B: "进程不存在 (PID 错了或目标进程已退出,PID=0/4 不可用)",
    0xC0000022: "访问被拒绝 (目标可能是受保护进程, 例如 System/PPL/csrss)",
    0xC0000207: "目标地址未映射 (PID 选成 System=4 又读 user 地址, 或地址压根没在目标进程里 commit)",
    0xC0000225: "地址未在物理内存中 (paged out / transition / 未提交)",
    0xC00000BB: "不支持 (撞上 2MB/1GB 大页, 当前实现只走 4KB 拆分)",
    0xC0000123: "IRQL 过高 (内部错误, 不应该出现)",
}


def hv_status_name(code: int) -> str:
    """Decode either an HV_STATUS_* small int or a kernel NTSTATUS (≥ 0x80000000)."""
    # 32-bit 二进制兼容: ctypes 字段是 c_uint32, 但 NTSTATUS 是 LONG (有符号),
    # 同一比特模式在 Python 里读出来是无符号正数, 所以判断时按无符号阈值即可。
    if code & 0x80000000:
        name = NTSTATUS_NAMES.get(code & 0xFFFFFFFF)
        hint = NTSTATUS_HINTS.get(code & 0xFFFFFFFF)
        base = name if name else f"NTSTATUS_0x{code & 0xFFFFFFFF:08X}"
        return f"{base} — {hint}" if hint else base
    return HV_STATUS_NAMES.get(code, f"HV_STATUS_0x{code:08X}")


# ----------------------------------------------------------------- base struct

class _Packed(ctypes.Structure):
    _pack_ = 1


# ----------------------------------------------------------------- structures


class HvStatusInfo(_Packed):
    _fields_ = (
        ("Version",                 c_uint32),
        ("HypervisorActive",        c_ubyte),
        ("HookManagerInitialized",  c_ubyte),
        ("DseDisabled",             c_ubyte),
        ("AntiAntiDebugEnabled",    c_ubyte),
        ("HiddenProcessCount",      c_uint32),
        ("HiddenDriverCount",       c_uint32),
        ("ProtectedDebuggerCount",  c_uint32),
        ("ProtectedProcessCount",   c_uint32),
        ("CpuVendor",               c_uint32),
        ("ProcessorCount",          c_uint32),
        # ---- Phase F (2026-06-03): hook 链路就绪状态 ----
        # 末尾追加保持向后兼容:旧驱动不写这几个字节,但 _Packed 默认 0。
        ("VtRootEnabled",           c_ubyte),
        ("DebuggerProxyEnabled",    c_ubyte),
        ("AccessBypassEnabled",     c_ubyte),
    )


class HvDseStatus(_Packed):
    _fields_ = (
        ("DseEnabled",       c_ubyte),
        ("CiOptionsValue",   c_uint32),
        ("CiOptionsAddress", c_uint64),
    )


# ----------------------------------------------------------------- Phase G: 根因事件
#
# 驱动侧用 `#pragma pack(push, 8)` 包裹这三个结构,所以 Python 端继承默认对齐的
# ctypes.Structure 即可 (_pack_=1 在这里会算错偏移)。

HV_DBGEVT_DETAIL_MAX = 96

# Severity
HV_DBGEVT_SEV_INFO  = 0
HV_DBGEVT_SEV_WARN  = 1
HV_DBGEVT_SEV_ERROR = 2

# Category
HV_DBGEVT_CAT_ADD_DEBUGGER    = 1
HV_DBGEVT_CAT_REMOVE_DEBUGGER = 2
HV_DBGEVT_CAT_OPEN_PROCESS    = 3
HV_DBGEVT_CAT_READ_MEMORY     = 4
HV_DBGEVT_CAT_WRITE_MEMORY    = 5
HV_DBGEVT_CAT_AAD             = 6

HV_DBGEVT_SEV_NAME = {
    HV_DBGEVT_SEV_INFO:  "INFO",
    HV_DBGEVT_SEV_WARN:  "WARN",
    HV_DBGEVT_SEV_ERROR: "ERROR",
}

HV_DBGEVT_CAT_NAME = {
    HV_DBGEVT_CAT_ADD_DEBUGGER:    "AddDebugger",
    HV_DBGEVT_CAT_REMOVE_DEBUGGER: "RemoveDebugger",
    HV_DBGEVT_CAT_OPEN_PROCESS:    "OpenProcess",
    HV_DBGEVT_CAT_READ_MEMORY:     "ReadMemory",
    HV_DBGEVT_CAT_WRITE_MEMORY:    "WriteMemory",
    HV_DBGEVT_CAT_AAD:             "AntiAntiDebug",
}


class HvDbgEvt(ctypes.Structure):
    """Mirror of HV_DBGEVT (pack=8, see HvHook.h)."""
    _fields_ = (
        ("Sequence",     c_uint64),
        ("TimestampQpc", c_uint64),
        ("Severity",     c_uint32),
        ("Category",     c_uint32),
        ("Status",       ctypes.c_int32),   # NTSTATUS = LONG (signed)
        ("CallerPid",    c_uint32),
        ("TargetPid",    c_uint32),
        ("_pad",         c_uint32),
        ("Addr",         c_uint64),
        ("Size",         c_uint64),
        ("Detail",       ctypes.c_char * HV_DBGEVT_DETAIL_MAX),
    )

    @property
    def detail_str(self) -> str:
        return self.Detail.decode("ascii", errors="replace").rstrip("\x00")

    @property
    def severity_name(self) -> str:
        return HV_DBGEVT_SEV_NAME.get(self.Severity, f"SEV{self.Severity}")

    @property
    def category_name(self) -> str:
        return HV_DBGEVT_CAT_NAME.get(self.Category, f"CAT{self.Category}")


class HvDbgEvtPullReq(ctypes.Structure):
    """Mirror of HV_DBGEVT_PULL_REQ (pack=8)."""
    _fields_ = (
        ("SinceSequence", c_uint64),
        ("MaxCount",      c_uint32),
        ("_pad",          c_uint32),
    )


class HvDbgEvtPullRes(ctypes.Structure):
    """Mirror of HV_DBGEVT_PULL_RES header (pack=8). Items follow as HvDbgEvt[Count]."""
    _fields_ = (
        ("Count",        c_uint32),
        ("_pad",         c_uint32),
        ("NextSequence", c_uint64),
    )


class HvProcessRequest(_Packed):
    _fields_ = (
        ("ProcessId",   c_uint32),
        ("ProcessName", c_wchar * 260),
    )


class HvDriverRequest(_Packed):
    _fields_ = (("DriverName", c_wchar * 260),)


class HvMemoryRequest(_Packed):
    _fields_ = (
        ("ProcessId",   c_uint32),
        ("Address",     c_uint64),
        ("Size",        c_uint32),
        ("Protection",  c_uint32),
        ("Buffer",      c_ubyte * 4096),
    )


class HvMemoryResult(_Packed):
    _fields_ = (
        ("Status",            c_uint32),
        ("Address",           c_uint64),
        ("BytesTransferred",  c_uint32),
        ("Buffer",            c_ubyte * 4096),
    )


# ----------------------------------------------------------------- 变长内存读写 (优化 #3)
#
# Driver.c: HV_MEMORY_REQUEST_EX / HV_MEMORY_RESULT_EX —— METHOD_BUFFERED 变长尾。
# payload 不写进 struct, 由调用方拼接 / 解包。
#
#   READ_EX  ioctl: input = HvMemoryRequestEx (24 字节)
#                   output = HvMemoryResultEx (24 字节) + Size 字节 payload
#   WRITE_EX ioctl: input = HvMemoryRequestEx (24 字节) + Size 字节 payload
#                   output = HvMemoryResultEx (24 字节)

HV_MEMORY_EX_MAX_PAYLOAD = 0x10000   # 64 KB, 与驱动一致


class HvMemoryRequestEx(_Packed):
    _fields_ = (
        ("ProcessId",  c_uint32),
        ("Reserved0",  c_uint32),
        ("Address",    c_uint64),
        ("Size",       c_uint32),
        ("Reserved1",  c_uint32),
    )


class HvMemoryResultEx(_Packed):
    _fields_ = (
        ("Status",            c_uint32),
        ("Reserved0",         c_uint32),
        ("Address",           c_uint64),
        ("BytesTransferred",  c_uint32),
        ("Reserved1",         c_uint32),
    )


# ----------------------------------------------------------------- 批量读写 (优化 #1)
#
# 一次 IOCTL 处理 N 个独立 (Address, Size) 项, 摊薄 syscall/copy 开销。Items[Count]
# 数组紧贴 BatchRequest header, 数据 payload 段紧贴 Items[]。每项的 payload 位置由
# PayloadOffset 字段指明 (相对 payload 段开头)。
#
# 单项失败不中止 batch; ResItem.Status 携带 NTSTATUS, 调用方逐项检查。

HV_BATCH_MAX_ITEMS    = 256
HV_BATCH_MAX_PAYLOAD  = 0x10000   # 64 KB


class HvMemoryBatchItem(_Packed):
    _fields_ = (
        ("Address",        c_uint64),
        ("Size",           c_uint32),
        ("PayloadOffset",  c_uint32),
    )


class HvMemoryBatchResItem(_Packed):
    _fields_ = (
        ("Status",            c_uint32),
        ("BytesTransferred",  c_uint32),
    )


class HvMemoryBatchRequest(_Packed):
    _fields_ = (
        ("ProcessId",  c_uint32),
        ("Count",      c_uint32),
    )


class HvMemoryBatchResult(_Packed):
    _fields_ = (
        ("TopStatus",  c_uint32),
        ("Count",      c_uint32),
    )


# ----------------------------------------------------------------- module enum
#
# 与 HvPhysAccess.h / Driver.c 一致:
#   HV_MODULE_INFO          —— #pragma pack(push, 8) 自然对齐(注意!不是 pack 1)
#   HV_MODULE_ENUM_REQUEST  —— #pragma pack(push, 1) 紧凑布局(在 Driver.c 的全局 pragma 内)
#   HV_MODULE_ENUM_RESULT   —— 同上, 后随 HV_MODULE_INFO[Count]
# IOCTL_HV_ENUMERATE_MODULES 调用 METHOD_BUFFERED,输出 = 头(8B) + N × 272B 模块条目。

HV_MODULE_NAME_MAX         = 128       # WCHAR 数, 含末尾 0 (与驱动一致)
HV_MAX_MODULES_PER_PROCESS = 384       # 驱动侧上限, 防 LDR 链表 corruption 跑飞


class HvModuleInfo(ctypes.Structure):
    """HvPhysAccess.h:232  HV_MODULE_INFO — 自然对齐 (pack=8),不是 _Packed。

    布局(总 272 字节):
        UINT64 DllBase     @ +0x00  (8)
        ULONG  SizeOfImage @ +0x08  (4)
        ULONG  Reserved    @ +0x0C  (4)
        WCHAR  Name[128]   @ +0x10  (256)
    """
    _fields_ = (
        ("DllBase",     c_uint64),
        ("SizeOfImage", c_uint32),
        ("Reserved",    c_uint32),
        ("Name",        c_wchar * HV_MODULE_NAME_MAX),
    )


class HvModuleEnumRequest(_Packed):
    """Driver.c:179  HV_MODULE_ENUM_REQUEST"""
    _fields_ = (
        ("ProcessId",  c_uint32),
        ("MaxModules", c_uint32),
    )


class HvModuleEnumResult(_Packed):
    """Driver.c:186  HV_MODULE_ENUM_RESULT — 头部, 后接 HvModuleInfo[Count]"""
    _fields_ = (
        ("Status", c_uint32),
        ("Count",  c_uint32),
    )


class HvInjectDllRequest(_Packed):
    _fields_ = (
        ("TargetPid",      c_uint32),
        ("DllPath",        c_wchar * 520),
        ("HideFromPeb",    c_ubyte),
        ("ErasePeHeader",  c_ubyte),
        ("UseManualMap",   c_ubyte),
        ("StealthLevel",   c_uint32),
    )


class HvInjectDllResult(_Packed):
    _fields_ = (
        ("Status",      c_uint32),
        ("ModuleBase",  c_uint64),
        ("ModuleSize",  c_uint32),
    )


class HvInjectShellcodeRequest(_Packed):
    _fields_ = (
        ("TargetPid",           c_uint32),
        ("ShellcodeSize",       c_uint32),
        ("Parameter",           c_uint64),
        ("ExecuteImmediately",  c_ubyte),
        ("HideMemory",          c_ubyte),
        ("Shellcode",           c_ubyte * 4096),
    )


class HvInjectShellcodeResult(_Packed):
    _fields_ = (
        ("Status",           c_uint32),
        ("ShellcodeAddress", c_uint64),
    )


class HvDebuggerRequest(_Packed):
    _fields_ = (
        ("ProcessId",            c_uint32),
        ("ProcessName",          c_wchar * 260),
        ("EnablePrivilege",      c_ubyte),
        ("ProtectFromTerminate", c_ubyte),
        ("HideFromList",         c_ubyte),
        ("BridgeIdentityOnly",   c_ubyte),
    )


class HvProtectRequest(_Packed):
    _fields_ = (
        ("ProcessId",   c_uint32),
        ("ProcessName", c_wchar * 260),
        ("DebuggerPid", c_uint32),
    )


class HvAntiAntiDebugRequest(_Packed):
    _fields_ = (
        ("TargetPid",                       c_uint32),
        ("Enable",                          c_ubyte),
        ("HookNtQueryInformationProcess",   c_ubyte),
        ("HookNtQuerySystemInformation",    c_ubyte),
        ("HookNtSetInformationThread",      c_ubyte),
        ("HookNtClose",                     c_ubyte),
        ("HookNtQueryObject",               c_ubyte),
    )


# ----------------------------------------------------------------- HWBP (阶段 7)

# 与 HvDebugger.h:34-38 一致 (DR7 R/W 编码)
HV_HWBP_TYPE_EXEC  = 0
HV_HWBP_TYPE_WRITE = 1
HV_HWBP_TYPE_IO    = 2   # 保留,通常不可用
HV_HWBP_TYPE_RW    = 3

HV_HWBP_TYPE_NAMES = {
    HV_HWBP_TYPE_EXEC:  "EXEC",
    HV_HWBP_TYPE_WRITE: "WRITE",
    HV_HWBP_TYPE_IO:    "IO",
    HV_HWBP_TYPE_RW:    "RW",
}


class HvHwBpRequest(_Packed):
    """Driver.c:260-269  HV_HWBP_REQUEST — SET_HWBP / CLEAR_HWBP 共用"""
    _fields_ = (
        ("DebuggerPid",  c_uint32),
        ("TargetPid",    c_uint32),
        ("SlotIndex",    c_uint32),     # 0-3
        ("Reserved0",    c_uint32),
        ("Address",      c_uint64),
        ("Length",       c_ubyte),      # 1/2/4/8
        ("Type",         c_ubyte),      # HV_HWBP_TYPE_*
        ("Reserved1",    c_ubyte * 6),
    )


class HvDbgWaitRequest(_Packed):
    """Driver.c:272-275  HV_DBG_WAIT_REQUEST"""
    _fields_ = (
        ("DebuggerPid", c_uint32),
        ("TimeoutMs",   c_uint32),      # 0 = 不阻塞, 0xFFFFFFFF = INFINITE
    )


class HvDebugEvent(_Packed):
    """HvDebugger.h:65-78  HV_DEBUG_EVENT — #DB 命中事件 (HWBP)

    Gpr 顺序与 GUEST_CONTEXT 一致: Rax,Rbx,Rcx,Rdx,Rsi,Rdi,Rbp,R8..R15 (共 15 个)
    """
    _fields_ = (
        ("Sequence", c_uint64),
        ("Tid",      c_uint64),
        ("Pid",      c_uint64),
        ("Cr3",      c_uint64),
        ("Rip",      c_uint64),
        ("Rsp",      c_uint64),
        ("Rflags",   c_uint64),
        ("Gpr",      c_uint64 * 15),
        ("Dr6",      c_uint64),
        ("HitSlot",  c_uint32),         # 0..3
        ("Reserved", c_uint32),
    )

    # GPR 顺序索引 (方便取名访问)
    GPR_NAMES = ("Rax", "Rbx", "Rcx", "Rdx", "Rsi", "Rdi", "Rbp",
                 "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15")


class HvDbgWaitResult(_Packed):
    """Driver.c:278-282  HV_DBG_WAIT_RESULT"""
    _fields_ = (
        ("Status",   c_uint32),         # HV_STATUS_*
        ("Reserved", c_uint32),
        ("Event",    HvDebugEvent),
    )


class HvDbgContinueRequest(_Packed):
    """Driver.c:285-289  HV_DBG_CONTINUE_REQUEST"""
    _fields_ = (
        ("DebuggerPid", c_uint32),
        ("Reserved",    c_uint32),
        ("Sequence",    c_uint64),
    )


class HvDbgResult(_Packed):
    """Driver.c:292-296  HV_DBG_RESULT — HWBP 通用结果"""
    _fields_ = (
        ("Status",   c_uint32),
        ("Reserved", c_uint32),
        ("Info",     c_uint64),
    )


class HvNestedStatus(_Packed):
    _fields_ = (
        ("NestedVmxSupported",        c_ubyte),
        ("NestedSvmSupported",        c_ubyte),
        ("L1VmxEnabled",              c_ubyte),
        ("L2Running",                 c_ubyte),
        ("ActiveCpuCount",            c_uint32),
        ("TotalVmxonCount",           c_uint64),
        ("TotalVmlaunchCount",        c_uint64),
        ("TotalVmresumeCount",        c_uint64),
        ("TotalL2ExitCount",          c_uint64),
        ("TotalErrorCount",           c_uint64),
        ("CurrentVmcsGpa",            c_uint64),
        ("VmxonRegionGpa",            c_uint64),
        ("LastGvaToGpaError",         c_uint64),
        ("LastFailedGva",             c_uint64),
        ("LastGuestCr3",              c_uint64),
        ("LastIrql",                  c_uint32),
        ("LastVmcs12ValidationError", c_uint64),
    )


# ============================================================
# 阶段 7.10 — VT 透明键鼠注入 (HvInput.h)
# ============================================================

class HvInputKeyRequest(_Packed):
    """HvInput.h:32-37  HV_INPUT_KEY_REQUEST"""
    _fields_ = (
        ("Scancode",   c_ubyte),   # PS/2 set 1 scancode 低 7 bit (e.g. 'A' = 0x1E)
        ("IsExtended", c_ubyte),   # 1 = 前导 E0 (方向键、Ctrl-R、Alt-R 等)
        ("IsBreak",    c_ubyte),   # 0 = 按下, 1 = 释放
        ("AutoBreak",  c_ubyte),   # 1 = 按下后自动 30-80ms 内释放
    )


class HvInputMouseRequest(_Packed):
    """HvInput.h:39-45  HV_INPUT_MOUSE_REQUEST"""
    _fields_ = (
        ("Dx",       c_int16),
        ("Dy",       c_int16),
        ("Buttons",  c_ubyte),    # bit0=L bit1=R bit2=M
        ("Smooth",   c_ubyte),    # 1 = 拆成多帧插值 (≤ 8 px/frame, 16ms)
        ("Reserved", c_ubyte * 2),
    )


# 后端类型 — 与 HvInput.h:_HV_INPUT_BACKEND 枚举对齐
HV_INPUT_BACKEND_NONE    = 0
HV_INPUT_BACKEND_PS2     = 1
HV_INPUT_BACKEND_USB_HID = 2
HV_INPUT_BACKEND_XHCI    = 3

HV_INPUT_BACKEND_NAMES = {
    HV_INPUT_BACKEND_NONE:    "NONE",
    HV_INPUT_BACKEND_PS2:     "PS/2",
    HV_INPUT_BACKEND_USB_HID: "USB-HID",
    HV_INPUT_BACKEND_XHCI:    "xHCI (Layer 4)",
}


class HvUsbXhciStatus(_Packed):
    """HvUsbXhci.h  HV_USB_XHCI_STATUS — IOCTL_HV_INPUT_GET_XHCI_STATUS 输出

    诊断字段:Stat* 都是从驱动启动起到现在的累计计数,可以在 GUI 里
    采两次差值看每次按键对应的实际 inject / ISR consume 比率。
    """
    _fields_ = (
        ("Ready",               c_ubyte),
        ("HasKeyboard",         c_ubyte),
        ("HasMouse",            c_ubyte),
        ("MsiVector",           c_ubyte),
        ("PciVendorId",         ctypes.c_uint16),
        ("PciDeviceId",         ctypes.c_uint16),
        ("BarPhys",             c_uint64),
        ("EventRingSegPhys",    c_uint64),
        ("EventRingSegSize",    c_uint32),
        ("KbdTrPhys",           c_uint64),
        ("MouseTrPhys",         c_uint64),
        # 诊断计数器 — Item 1: scan-ahead 验证
        ("StatInjectAttempts",  c_uint32),  # HvUsbXhciTryDeliverMsi 进入次数
        ("StatInjectDelivered", c_uint32),  # 成功 HvVmExitInjectInterrupt
        ("StatInjectDeferred",  c_uint32),  # IF=0,等下次 VMEXIT
        ("StatErdpAdvanced",    c_uint32),  # ERDP 前进 (xhci.sys ISR 真消费了)
        ("StatErdpStalled",     c_uint32),  # ERDP 没动 (ISR 没运行 / fast-bail)
        ("StatTrbWriteOk",      c_uint32),  # Transfer Ring 写 NORMAL TRB 命中
        ("StatTrbWriteFailed",  c_uint32),  # 扫到 MAX_SCAN 都没找到 producer 槽
        ("CurrentErdp",         c_uint64),  # 当前 IR[0].ERDP & ~0xF
        ("LastInjectedErdp",    c_uint64),  # 上次注入前快照的 ERDP
    )


class HvInputStatus(_Packed):
    """HvInput.h:77-90  HV_INPUT_STATUS — IOCTL_HV_INPUT_GET_STATUS 输出"""
    _fields_ = (
        ("Backend",           c_ubyte),     # HV_INPUT_BACKEND_*
        ("Initialized",       c_ubyte),
        ("Enabled",           c_ubyte),
        ("KbdReady",          c_ubyte),
        ("MouseReady",        c_ubyte),
        ("StrictXhciMode",    c_ubyte),     # 1 = 严格模式 (xHCI 失败不回退 v3)
        ("Reserved",          c_ubyte * 2),
        ("KbdVector",         c_uint32),    # PS/2 only — IDT vector (USB HID 时 0)
        ("MouseVector",       c_uint32),
        ("KbdCallback",       c_uint64),    # USB HID only — kbdclass ClassService 地址
        ("MouseCallback",     c_uint64),
        ("KbdDeviceObject",   c_uint64),    # USB HID only
        ("MouseDeviceObject", c_uint64),
    )


class HvXhciEptTrapState(_Packed):
    """HvXhciEptTrap.h  HV_XHCI_EPT_TRAP_STATE — IOCTL_HV_XHCI_TRAP_GET_STATS 输出

    Item 2 (USBSTS/IMAN EPT 读 trap) 的运行时状态 + 累计计数。
    用户启用 trap 后,如果 Stats.ArmCount 在涨但 UsbstsReadFaked / ImanReadFaked
    没动 → ISR 没读 (xHCI 没收到 MSI / driver 没运行) → 应保持 trap OFF。
    """
    _fields_ = (
        ("Initialized",         c_ubyte),    # Init 是否成功
        ("UserEnabled",         c_ubyte),    # 用户开关 (默认 0)
        ("MtfSupported",        c_ubyte),    # CPU 是否支持 MTF (Init 时探到)
        ("Padding",             c_ubyte),
        ("TrapPageCount",       c_uint32),   # 实际 trap 的 4KB 页数 (1 或 2)
        ("PendingIsrReads",     ctypes.c_int32),  # 当前剩余"假冒读"配额
        # HV_XHCI_EPT_TRAP_STATS 内嵌
        ("StatArmCount",        c_uint32),
        ("StatUsbstsReadFaked", c_uint32),
        ("StatImanReadFaked",   c_uint32),
        ("StatOtherReadOnPage", c_uint32),
        ("StatMtfMisses",       c_uint32),
    )


# PS/2 Set 1 扫描码表 — 把 Python str/字面值映射到 (scancode, is_extended) 元组。
# 引用: https://wiki.osdev.org/PS/2_Keyboard, "Scan Code Set 1"
#
# 只覆盖 GUI 常用键; 缺失字符让 send_text() 自己跳过 (or raise KeyError)。
SCANCODE_MAP: dict[str, tuple[int, bool]] = {
    # ---- letters
    "A": (0x1E, False), "B": (0x30, False), "C": (0x2E, False), "D": (0x20, False),
    "E": (0x12, False), "F": (0x21, False), "G": (0x22, False), "H": (0x23, False),
    "I": (0x17, False), "J": (0x24, False), "K": (0x25, False), "L": (0x26, False),
    "M": (0x32, False), "N": (0x31, False), "O": (0x18, False), "P": (0x19, False),
    "Q": (0x10, False), "R": (0x13, False), "S": (0x1F, False), "T": (0x14, False),
    "U": (0x16, False), "V": (0x2F, False), "W": (0x11, False), "X": (0x2D, False),
    "Y": (0x15, False), "Z": (0x2C, False),
    # ---- digits (主键盘行)
    "0": (0x0B, False), "1": (0x02, False), "2": (0x03, False), "3": (0x04, False),
    "4": (0x05, False), "5": (0x06, False), "6": (0x07, False), "7": (0x08, False),
    "8": (0x09, False), "9": (0x0A, False),
    # ---- 符号
    "-": (0x0C, False), "=": (0x0D, False), "[": (0x1A, False), "]": (0x1B, False),
    ";": (0x27, False), "'": (0x28, False), "`": (0x29, False), "\\": (0x2B, False),
    ",": (0x33, False), ".": (0x34, False), "/": (0x35, False),
    " ": (0x39, False),
    # ---- 控制键
    "ESC":       (0x01, False),
    "BACKSPACE": (0x0E, False),
    "TAB":       (0x0F, False),
    "ENTER":     (0x1C, False),
    "LCTRL":     (0x1D, False),
    "LSHIFT":    (0x2A, False),
    "RSHIFT":    (0x36, False),
    "LALT":      (0x38, False),
    "CAPS":      (0x3A, False),
    # ---- F 键
    "F1":  (0x3B, False), "F2":  (0x3C, False), "F3":  (0x3D, False), "F4":  (0x3E, False),
    "F5":  (0x3F, False), "F6":  (0x40, False), "F7":  (0x41, False), "F8":  (0x42, False),
    "F9":  (0x43, False), "F10": (0x44, False), "F11": (0x57, False), "F12": (0x58, False),
    # ---- 扩展键 (E0 前缀)
    "RCTRL":  (0x1D, True),
    "RALT":   (0x38, True),
    "UP":     (0x48, True),
    "DOWN":   (0x50, True),
    "LEFT":   (0x4B, True),
    "RIGHT":  (0x4D, True),
    "HOME":   (0x47, True),
    "END":    (0x4F, True),
    "PGUP":   (0x49, True),
    "PGDN":   (0x51, True),
    "INSERT": (0x52, True),
    "DELETE": (0x53, True),
}

# 鼠标按钮位
HV_INPUT_MBUTTON_L = 0x01
HV_INPUT_MBUTTON_R = 0x02
HV_INPUT_MBUTTON_M = 0x04


# convenient introspection table used by structs.py self-test
ALL_STRUCTS = (
    HvStatusInfo, HvDseStatus,
    HvProcessRequest, HvDriverRequest,
    HvMemoryRequest, HvMemoryResult,
    HvMemoryRequestEx, HvMemoryResultEx,
    HvMemoryBatchItem, HvMemoryBatchResItem,
    HvMemoryBatchRequest, HvMemoryBatchResult,
    HvModuleInfo, HvModuleEnumRequest, HvModuleEnumResult,
    HvInjectDllRequest, HvInjectDllResult,
    HvInjectShellcodeRequest, HvInjectShellcodeResult,
    HvDebuggerRequest, HvProtectRequest,
    HvAntiAntiDebugRequest, HvNestedStatus,
    HvHwBpRequest, HvDbgWaitRequest, HvDebugEvent,
    HvDbgWaitResult, HvDbgContinueRequest, HvDbgResult,
    HvInputKeyRequest, HvInputMouseRequest, HvInputStatus,
)


if __name__ == "__main__":
    for s in ALL_STRUCTS:
        print(f"{s.__name__:30s}  size={ctypes.sizeof(s):6d}")
