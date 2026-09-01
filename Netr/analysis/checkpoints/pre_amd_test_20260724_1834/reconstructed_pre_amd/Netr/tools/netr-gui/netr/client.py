"""High-level NetrClient — one method per IOCTL, takes Pythonic args."""

from __future__ import annotations

import ctypes
import os
from typing import Optional

from .ioctl import (
    NetrDevice,
    IOCTL_HV_GET_STATUS, IOCTL_HV_GET_DSE_STATUS,
    IOCTL_HV_DISABLE_DSE, IOCTL_HV_ENABLE_DSE,
    IOCTL_HV_HIDE_PROCESS, IOCTL_HV_UNHIDE_PROCESS,
    IOCTL_HV_HIDE_DRIVER, IOCTL_HV_UNHIDE_DRIVER,
    IOCTL_HV_ADD_DEBUGGER, IOCTL_HV_REMOVE_DEBUGGER,
    IOCTL_HV_PROTECT_PROCESS, IOCTL_HV_UNPROTECT_PROCESS,
    IOCTL_HV_ENABLE_ACCESS_BYPASS, IOCTL_HV_DISABLE_ACCESS_BYPASS,
    IOCTL_HV_INPUT_ENABLE, IOCTL_HV_INPUT_DISABLE,
    IOCTL_HV_INPUT_SEND_KEY, IOCTL_HV_INPUT_SEND_MOUSE,
    IOCTL_HV_INPUT_GET_STATUS, IOCTL_HV_INPUT_GET_XHCI_STATUS,
    IOCTL_HV_INPUT_SET_STRICT_MODE,
    IOCTL_HV_XHCI_TRAP_ENABLE, IOCTL_HV_XHCI_TRAP_DISABLE,
    IOCTL_HV_XHCI_TRAP_GET_STATS,
    IOCTL_HV_ENABLE_ANTIANTIDEBUG, IOCTL_HV_DISABLE_ANTIANTIDEBUG,
    IOCTL_HV_INJECT_DLL, IOCTL_HV_INJECT_SHELLCODE,
    IOCTL_HV_MEMORY_READ, IOCTL_HV_MEMORY_WRITE,
    IOCTL_HV_MEMORY_ALLOC, IOCTL_HV_MEMORY_FREE,
    IOCTL_HV_MEMORY_READ_EX, IOCTL_HV_MEMORY_WRITE_EX,
    IOCTL_HV_MEMORY_BATCH_READ, IOCTL_HV_MEMORY_BATCH_WRITE,
    IOCTL_HV_ENUMERATE_MODULES,
    IOCTL_HV_GET_NESTED_STATUS,
    IOCTL_HV_DBG_SET_HWBP, IOCTL_HV_DBG_CLEAR_HWBP,
    IOCTL_HV_DBG_WAIT_EVENT, IOCTL_HV_DBG_CONTINUE,
    IOCTL_HV_GET_DBGEVT,
)
from .structs import (
    HvStatusInfo, HvDseStatus, HvNestedStatus,
    HvProcessRequest, HvDriverRequest,
    HvDebuggerRequest, HvProtectRequest, HvAntiAntiDebugRequest,
    HvMemoryRequest, HvMemoryResult,
    HvMemoryRequestEx, HvMemoryResultEx,
    HV_MEMORY_EX_MAX_PAYLOAD,
    HvMemoryBatchItem, HvMemoryBatchResItem,
    HvMemoryBatchRequest, HvMemoryBatchResult,
    HV_BATCH_MAX_ITEMS, HV_BATCH_MAX_PAYLOAD,
    HvModuleInfo, HvModuleEnumRequest, HvModuleEnumResult,
    HV_MAX_MODULES_PER_PROCESS,
    HvInjectDllRequest, HvInjectDllResult,
    HvInjectShellcodeRequest, HvInjectShellcodeResult,
    HvHwBpRequest, HvDbgWaitRequest, HvDbgWaitResult,
    HvDbgContinueRequest, HvDbgResult, HvDebugEvent,
    HvDbgEvt, HvDbgEvtPullReq, HvDbgEvtPullRes,
    HvInputKeyRequest, HvInputMouseRequest, HvInputStatus, HvUsbXhciStatus,
    HvXhciEptTrapState,
    SCANCODE_MAP,
    HV_INPUT_MBUTTON_L, HV_INPUT_MBUTTON_R, HV_INPUT_MBUTTON_M,
    HV_INPUT_BACKEND_NONE, HV_INPUT_BACKEND_PS2, HV_INPUT_BACKEND_USB_HID,
    HV_INPUT_BACKEND_NAMES,
    HV_HWBP_TYPE_EXEC, HV_HWBP_TYPE_WRITE, HV_HWBP_TYPE_IO, HV_HWBP_TYPE_RW,
    HV_STATUS_SUCCESS, HV_STATUS_NOT_FOUND,
    hv_status_name,
)


class NetrError(RuntimeError):
    """Raised when an IOCTL returns a non-success status code.

    ``status`` is either a small ``HV_STATUS_*`` enum value (0..7) when the
    driver classified the error itself, or a raw kernel NTSTATUS
    (``>= 0x80000000``) when it transparently passed up the inner failure.
    ``hv_status_name`` handles both.
    """

    def __init__(self, op: str, status: int):
        self.op     = op
        # ctypes c_uint32 round-trip: 把可能为负的 LONG 收成正的 32-bit pattern。
        self.status = status & 0xFFFFFFFF
        super().__init__(
            f"{op}: {hv_status_name(self.status)} (0x{self.status:08X})"
        )


# Windows 内核进程 —— PID=0/4 的处理策略:
#   0 = Idle  跑的是空闲线程,没有 EPROCESS,所有路径都失败 → 始终拒绝
#   4 = System 只有 kernel 半空间,user 半空间全为 0
#                读 kernel VA 通过 HvPhysReadProcessMemory 可行 (System CR3 + GVA→HPA walk),
#                ADD_DEBUGGER 全权限模式下放开;但写 kernel VA 极易 BSOD,始终拒绝。
_KERNEL_PIDS_NEVER    = frozenset({0})         # 读写都拒
_KERNEL_PIDS_NO_WRITE = frozenset({0, 4})      # 写专属拒(0 已含,4 额外)


def _validate_pid_range(pid: int, op: str) -> None:
    if not isinstance(pid, int):
        raise ValueError(f"{op}: pid must be int, got {type(pid).__name__}")
    if pid < 0 or pid > 0xFFFFFFFF:
        raise ValueError(f"{op}: pid {pid} out of range")


def _validate_user_pid_read(pid: int, op: str) -> None:
    """读路径:只拒 PID=0 (Idle 无 EPROCESS)。PID=4 (System) 现支持 kernel VA 读。"""
    _validate_pid_range(pid, op)
    if pid in _KERNEL_PIDS_NEVER:
        raise ValueError(
            f"{op}: PID=0 是 Idle 进程,无 EPROCESS,无任何地址空间。"
            f"请选一个真实的进程 PID(任务管理器 → 详细信息)。"
        )


def _validate_user_pid_write(pid: int, op: str) -> None:
    """写路径:拒 PID=0/4。System(4) 写 kernel VA 极易 BSOD,始终拒绝。"""
    _validate_pid_range(pid, op)
    if pid in _KERNEL_PIDS_NO_WRITE:
        if pid == 0:
            raise ValueError(
                f"{op}: PID=0 是 Idle 进程,无 EPROCESS,无任何地址空间。")
        raise ValueError(
            f"{op}: 拒绝写 PID=4 (System)。内核 VA 写极易 BSOD"
            f"(踩 PG 校验 / driver code / IDT)。读 System 仍允许。")


# 兼容旧调用点(alloc/free/enumerate_modules 等非 R/W 路径):严格按"必须真实用户进程"
def _validate_user_pid(pid: int, op: str) -> None:
    _validate_pid_range(pid, op)
    if pid in _KERNEL_PIDS_NO_WRITE:
        raise ValueError(
            f"{op}: PID={pid} 是 Windows 内核进程 "
            f"({'Idle' if pid == 0 else 'System'}),不适用于此操作。"
            f"请选一个真实的用户态进程 PID(任务管理器 → 详细信息)。"
        )


class NetrClient:
    """One method per IOCTL.

    The client takes ownership of a ``NetrDevice``. Pass an existing device in,
    or let the client open ``\\\\.\\HvControl`` automatically.
    """

    def __init__(self, device: Optional[NetrDevice] = None):
        self.device = device if device is not None else NetrDevice()

    def close(self) -> None:
        self.device.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # ================================================================ STATUS

    def get_status(self) -> HvStatusInfo:
        data = self.device.ioctl(IOCTL_HV_GET_STATUS,
                                 out_size=ctypes.sizeof(HvStatusInfo))
        return HvStatusInfo.from_buffer_copy(data)

    def get_nested_status(self) -> HvNestedStatus:
        data = self.device.ioctl(IOCTL_HV_GET_NESTED_STATUS,
                                 out_size=ctypes.sizeof(HvNestedStatus))
        return HvNestedStatus.from_buffer_copy(data)

    # ================================================================ DSE

    def get_dse_status(self) -> HvDseStatus:
        data = self.device.ioctl(IOCTL_HV_GET_DSE_STATUS,
                                 out_size=ctypes.sizeof(HvDseStatus))
        return HvDseStatus.from_buffer_copy(data)

    def disable_dse(self) -> None:
        self.device.ioctl(IOCTL_HV_DISABLE_DSE)

    def enable_dse(self) -> None:
        self.device.ioctl(IOCTL_HV_ENABLE_DSE)

    # ================================================================ PROCESS / DRIVER hide

    def hide_process(self, pid: int = 0, name: str = "") -> None:
        req = HvProcessRequest(ProcessId=pid, ProcessName=name)
        self.device.ioctl(IOCTL_HV_HIDE_PROCESS, in_buf=req)

    def unhide_process(self, pid: int = 0, name: str = "") -> None:
        req = HvProcessRequest(ProcessId=pid, ProcessName=name)
        self.device.ioctl(IOCTL_HV_UNHIDE_PROCESS, in_buf=req)

    def hide_driver(self, name: str) -> None:
        req = HvDriverRequest(DriverName=name)
        self.device.ioctl(IOCTL_HV_HIDE_DRIVER, in_buf=req)

    def unhide_driver(self, name: str) -> None:
        req = HvDriverRequest(DriverName=name)
        self.device.ioctl(IOCTL_HV_UNHIDE_DRIVER, in_buf=req)

    # ================================================================ debugger / protect

    def add_debugger(self, pid: int, name: str = "",
                     enable_priv: bool = True,
                     protect_terminate: bool = True,
                     hide_from_list: bool = False) -> None:
        req = HvDebuggerRequest(
            ProcessId=pid, ProcessName=name,
            EnablePrivilege=int(enable_priv),
            ProtectFromTerminate=int(protect_terminate),
            HideFromList=int(hide_from_list),
        )
        self.device.ioctl(IOCTL_HV_ADD_DEBUGGER, in_buf=req)

    def remove_debugger(self, pid: int = 0, name: str = "") -> None:
        req = HvDebuggerRequest(ProcessId=pid, ProcessName=name)
        self.device.ioctl(IOCTL_HV_REMOVE_DEBUGGER, in_buf=req)

    def protect_process(self, pid: int, name: str = "",
                        debugger_pid: int = 0) -> None:
        req = HvProtectRequest(ProcessId=pid, ProcessName=name,
                               DebuggerPid=debugger_pid)
        self.device.ioctl(IOCTL_HV_PROTECT_PROCESS, in_buf=req)

    def unprotect_process(self, pid: int = 0, name: str = "") -> None:
        req = HvProtectRequest(ProcessId=pid, ProcessName=name)
        self.device.ioctl(IOCTL_HV_UNPROTECT_PROCESS, in_buf=req)

    # 阶段 7.9: NtOpenProcess 访问绕过 (PPL/System=4),默认 OFF,高危。
    # 启用后,已 ADD_DEBUGGER 的 caller 对其 PROTECT_PROCESS 配对的 target
    # 调 OpenProcess() 会成功;其他 caller / 其他 target 走 hook 原路径。
    def enable_access_bypass(self) -> None:
        self.device.ioctl(IOCTL_HV_ENABLE_ACCESS_BYPASS)

    def disable_access_bypass(self) -> None:
        self.device.ioctl(IOCTL_HV_DISABLE_ACCESS_BYPASS)

    # ================================================================ INPUT (阶段 7.10)
    #
    # VT 透明键鼠注入:在 hypervisor 层拦截 PS/2 端口 0x60/0x64,合成 IRQ 1/IRQ 12,
    # 后面 i8042prt → KbdClass → win32k!RIM 全链路是 Windows 自己跑的,反作弊从
    # ring-3/ring-0 任何视角看都是物理输入 (LLKHF_INJECTED=0)。
    #
    # 启用条件:目标机必须有 PS/2 控制器 (虚拟机基本都有;USB-only laptop 会失败)。
    # 内核 HvInputEnable 启动时通过 IOAPIC redirection table 发现 IRQ 1/12 的 IDT
    # 向量,失败则 IOCTL 返回 STATUS_NOT_SUPPORTED。

    def enable_input(self) -> None:
        """Turn on PS/2 I/O bitmap + IRQ injection. Idempotent."""
        self.device.ioctl(IOCTL_HV_INPUT_ENABLE)

    def disable_input(self) -> None:
        """Stop synthetic input delivery; pending FIFO is flushed.
        I/O bitmap remains armed but handler runs in passthrough mode."""
        self.device.ioctl(IOCTL_HV_INPUT_DISABLE)

    def get_input_status(self) -> HvInputStatus:
        """Query the driver's input subsystem state — which backend was picked
        at HvInputInitialize, whether keyboard/mouse discovery succeeded, the
        underlying IDT vector (PS/2) or ClassService callback address (USB HID).
        """
        out = self.device.ioctl(IOCTL_HV_INPUT_GET_STATUS,
                                out_size=ctypes.sizeof(HvInputStatus))
        if len(out) < ctypes.sizeof(HvInputStatus):
            raise RuntimeError(
                f"INPUT_GET_STATUS returned {len(out)} bytes, "
                f"expected {ctypes.sizeof(HvInputStatus)}")
        return HvInputStatus.from_buffer_copy(out)

    def get_xhci_status(self) -> HvUsbXhciStatus:
        """Query xHCI Layer 4 诊断状态 — Item 1 (scan-ahead 验证 + ERDP 推进观测).

        返回 HvUsbXhciStatus,包含:
          - Ready / HasKeyboard / HasMouse:Layer 4 后端可用性
          - PCI VID/DID, BAR phys, Event Ring seg phys, kbd/mouse TR phys:基础拓扑
          - 7 个 Stat* 计数器:相邻两次采样差值即可看出每次按键的实际效果
              * StatInjectAttempts   每次 HvUsbXhciTryDeliverMsi 入口
              * StatInjectDelivered  实际发了 HvVmExitInjectInterrupt
              * StatInjectDeferred   IF=0,等下次 VMEXIT
              * StatErdpAdvanced     ERDP 前进 (xhci.sys ISR 真在消费)
              * StatErdpStalled      ERDP 没动 (ISR 没运行 / fast-bail)
              * StatTrbWriteOk       Transfer Ring 写 NORMAL TRB 命中 producer 槽
              * StatTrbWriteFailed   扫到 MAX_SCAN 都没找到 producer 槽
          - CurrentErdp:实时读 IR[0].ERDP & ~0xF
          - LastInjectedErdp:上次注入前快照的 ERDP

        诊断用法:
          before = client.get_xhci_status()
          client.send_key('A'); time.sleep(0.1)
          after  = client.get_xhci_status()
          delta_advanced = after.StatErdpAdvanced - before.StatErdpAdvanced
          delta_stalled  = after.StatErdpStalled  - before.StatErdpStalled
          # 一次按键预期: TrbWriteOk +1, InjectDelivered +1, ErdpAdvanced +1
        """
        out = self.device.ioctl(IOCTL_HV_INPUT_GET_XHCI_STATUS,
                                out_size=ctypes.sizeof(HvUsbXhciStatus))
        if len(out) < ctypes.sizeof(HvUsbXhciStatus):
            raise RuntimeError(
                f"INPUT_GET_XHCI_STATUS returned {len(out)} bytes, "
                f"expected {ctypes.sizeof(HvUsbXhciStatus)}")
        return HvUsbXhciStatus.from_buffer_copy(out)

    def set_strict_xhci_mode(self, strict: bool) -> None:
        """启/停 严格 xHCI 模式。

        strict=True  → xHCI Layer 4 失败时直接返错,不回退到 v3 ring-0 直调。
                       这条退路虽然能继续工作,但被任何 KbdClass 过滤驱动 hook
                       到 ClassServiceCallback 都看得见,反作弊 r0 视角不算透明。
        strict=False → 默认行为,xHCI 不可用时自动 fallback,保最大可用性。

        驱动里 g_StrictXhciMode 持久,设一次有效,直到下次设或驱动重载。
        """
        buf = (ctypes.c_ubyte * 1)(1 if strict else 0)
        self.device.ioctl(IOCTL_HV_INPUT_SET_STRICT_MODE, in_buf=bytes(buf))

    # ------------- Item 2: xHCI USBSTS/IMAN EPT 读 trap 控制 -------------

    def xhci_trap_enable(self) -> None:
        """启用 Item 2 trap (USBSTS/IMAN 读 EPT trap).

        作用:guest xHCI ISR 读 USBSTS/IMAN 时,hypervisor 注入伪 EINT/IP 位,
        让 ISR 不在 fast-bail 路径返回,真正去消费 Event Ring。

        风险:
          - 需要 CPU 支持 MTF (Monitor Trap Flag),不支持时 IOCTL 返回 STATUS_NOT_SUPPORTED
          - 启用后任何对 USBSTS/IMAN 4KB 页的读都会 VMEXIT (短时窗口,counter=16)
          - 默认 OFF — 显式启用以排查 hang/无响应/鼠标不响应

        排查顺序:
          1. 先不启用 trap,测试键盘/鼠标 → 确认基础链路 OK
          2. 启用 trap,再测试 → 看 stats 涨不涨,是否卡死
        """
        self.device.ioctl(IOCTL_HV_XHCI_TRAP_ENABLE)

    def xhci_trap_disable(self) -> None:
        """关闭 Item 2 trap,并立即恢复所有 trap 页 R=1 + 跨模式 INVEPT。

        安全可重入。即使 trap 当前正在 arm (R=0),disable 后下一次 guest 读
        立即恢复到透传状态。
        """
        self.device.ioctl(IOCTL_HV_XHCI_TRAP_DISABLE)

    def xhci_trap_get_stats(self) -> HvXhciEptTrapState:
        """读 Item 2 trap 当前状态 + 累计计数器.

        关键字段:
          - Initialized / UserEnabled / MtfSupported: 状态机
          - TrapPageCount: 1 或 2 (USBSTS 和 IMAN 是否同页)
          - PendingIsrReads: 当前 arm 剩余配额 (0 = 已 disarm,16 = 刚 arm)
          - StatArmCount: 累计 Arm() 调用次数 (= 成功 inject MSI 次数)
          - StatUsbstsReadFaked / StatImanReadFaked: 累计假冒读次数
          - StatMtfMisses: GPR diff 没找到目的寄存器的次数
            (>0 = ISR 用了 TEST/CMP 而非 MOV,极少见;>>0 说明出问题了)
        """
        out = self.device.ioctl(IOCTL_HV_XHCI_TRAP_GET_STATS,
                                out_size=ctypes.sizeof(HvXhciEptTrapState))
        if len(out) < ctypes.sizeof(HvXhciEptTrapState):
            raise RuntimeError(
                f"XHCI_TRAP_GET_STATS returned {len(out)} bytes, "
                f"expected {ctypes.sizeof(HvXhciEptTrapState)}")
        return HvXhciEptTrapState.from_buffer_copy(out)

    def send_key(self, char_or_scancode, *,
                 is_extended: bool = False,
                 is_break: bool = False,
                 auto_break: bool = True) -> None:
        """Inject a single key press.

        Args:
            char_or_scancode:  str ('A', 'F1', 'ENTER', ...) 查表 SCANCODE_MAP;
                               或 int 直接当 PS/2 set 1 scancode 用。
            is_extended:       是否带 E0 前缀 (str 路径会自动设置)。
            is_break:          False=按下 (make), True=释放 (break)。
            auto_break:        True=按下后 30-80ms 自动释放,适合打字。
                               False+is_break=False 适合需要长按 (例如游戏蓄力)。
        """
        if isinstance(char_or_scancode, str):
            key = char_or_scancode.upper()
            if key not in SCANCODE_MAP:
                raise ValueError(f"send_key: 未支持的按键 {char_or_scancode!r} "
                                 f"(SCANCODE_MAP 没有定义)")
            sc, ext = SCANCODE_MAP[key]
        else:
            sc, ext = int(char_or_scancode), is_extended
        if not 0 <= sc <= 0xFF:
            raise ValueError(f"send_key: scancode {sc} 越界 (0..255)")
        req = HvInputKeyRequest(
            Scancode=sc,
            IsExtended=int(ext),
            IsBreak=int(is_break),
            AutoBreak=int(auto_break),
        )
        self.device.ioctl(IOCTL_HV_INPUT_SEND_KEY, in_buf=req)

    def send_text(self, text: str, *, auto_break: bool = True) -> None:
        """Type a string char-by-char; skips chars not in SCANCODE_MAP.

        大写字母需要 Shift,本函数不自动按 Shift —— 输入纯大写字符串会发出小写
        扫描码 (取决于当前 Caps/Shift 状态)。GUI 层需要时自己包 LSHIFT。
        """
        for ch in text:
            key = ch.upper()
            if key in SCANCODE_MAP:
                self.send_key(key, auto_break=auto_break)

    def send_mouse(self, dx: int, dy: int, buttons: int = 0, *,
                   smooth: bool = True) -> None:
        """Inject a relative mouse movement / button event.

        Args:
            dx, dy:    相对位移 (像素;PS/2 Y 轴方向已在内核侧反转)。
            buttons:   按位 OR HV_INPUT_MBUTTON_{L,R,M} 表示哪几个键按下。
                       0 = 全释放。注意:PS/2 鼠标包总是 reportsbutton 状态,
                       所以"点击"需要先发 buttons=L 再发 buttons=0。
            smooth:    True=大位移拆 ≤8 px/帧, 16ms 间隔;False=一次到位。
        """
        if not -32768 <= dx <= 32767 or not -32768 <= dy <= 32767:
            raise ValueError(f"send_mouse: dx/dy ({dx},{dy}) 越界 (-32768..32767)")
        if buttons & ~0x07:
            raise ValueError(f"send_mouse: buttons=0x{buttons:X} 含未定义位 "
                             f"(只允许 L=1/R=2/M=4)")
        req = HvInputMouseRequest(
            Dx=dx, Dy=dy,
            Buttons=buttons,
            Smooth=int(smooth),
        )
        self.device.ioctl(IOCTL_HV_INPUT_SEND_MOUSE, in_buf=req)

    def click_mouse(self, button: int = HV_INPUT_MBUTTON_L) -> None:
        """便捷:在原地点击一次 (down 然后 up)。"""
        self.send_mouse(0, 0, button, smooth=False)
        self.send_mouse(0, 0, 0,      smooth=False)

    # ================================================================ AAD

    def enable_anti_anti_debug(self, target_pid: int = 0,
                                hook_ntqip: bool = True,
                                hook_ntqsi: bool = True,
                                hook_ntsit: bool = True,
                                hook_ntclose: bool = False,
                                hook_ntqo: bool = False) -> None:
        req = HvAntiAntiDebugRequest(
            TargetPid=target_pid, Enable=1,
            HookNtQueryInformationProcess=int(hook_ntqip),
            HookNtQuerySystemInformation=int(hook_ntqsi),
            HookNtSetInformationThread=int(hook_ntsit),
            HookNtClose=int(hook_ntclose),
            HookNtQueryObject=int(hook_ntqo),
        )
        self.device.ioctl(IOCTL_HV_ENABLE_ANTIANTIDEBUG, in_buf=req)

    def disable_anti_anti_debug(self) -> None:
        self.device.ioctl(IOCTL_HV_DISABLE_ANTIANTIDEBUG)

    # ================================================================ memory

    def memory_read(self, pid: int, addr: int, size: int) -> bytes:
        _validate_user_pid_read(pid, "memory_read")
        if size <= 0 or size > 4096:
            raise ValueError("size must be 1..4096")
        req = HvMemoryRequest(ProcessId=pid, Address=addr, Size=size)
        data = self.device.ioctl(IOCTL_HV_MEMORY_READ, in_buf=req,
                                 out_size=ctypes.sizeof(HvMemoryResult))
        res = HvMemoryResult.from_buffer_copy(data)
        if res.Status != 0:
            raise NetrError("memory_read", res.Status)
        return bytes(res.Buffer[: res.BytesTransferred])

    def memory_write(self, pid: int, addr: int, data: bytes) -> int:
        _validate_user_pid_write(pid, "memory_write")
        if not data or len(data) > 4096:
            raise ValueError("data must be 1..4096 bytes")
        req = HvMemoryRequest(ProcessId=pid, Address=addr, Size=len(data))
        ctypes.memmove(req.Buffer, data, len(data))
        out = self.device.ioctl(IOCTL_HV_MEMORY_WRITE, in_buf=req,
                                out_size=ctypes.sizeof(HvMemoryResult))
        res = HvMemoryResult.from_buffer_copy(out)
        if res.Status != 0:
            raise NetrError("memory_write", res.Status)
        return res.BytesTransferred

    # ---- 变长读写 (优化 #3): 单次最大 64 KB, 比 memory_read/write 高 16× -----
    #
    # 驱动 hot path: METHOD_BUFFERED 直接把 user buf 整块拷进 SystemBuffer,
    # 再逐页 vmcall 完成 GVA→HPA + memcpy。摊薄 syscall + vmexit 后,大块顺序
    # 读吞吐 ~1.6 GB/s,远高于固定 4KB IOCTL 的 100 MB/s 上限。
    # 反作弊视角:仍然只有 1 条 DeviceIoControl + 16 条 vmcall (64KB / 4KB),
    # 完全不引入新的 Mm*/Ps* 调用。

    def memory_read_ex(self, pid: int, addr: int, size: int) -> bytes:
        """读 1..65536 字节。size <= 4096 时与 memory_read 等价但 IOCTL 码不同。"""
        _validate_user_pid_read(pid, "memory_read_ex")
        if size <= 0 or size > HV_MEMORY_EX_MAX_PAYLOAD:
            raise ValueError(
                f"size must be 1..{HV_MEMORY_EX_MAX_PAYLOAD} (got {size})")

        req = HvMemoryRequestEx(ProcessId=pid, Address=addr, Size=size)
        head_size = ctypes.sizeof(HvMemoryResultEx)
        data = self.device.ioctl(IOCTL_HV_MEMORY_READ_EX, in_buf=req,
                                 out_size=head_size + size)
        if len(data) < head_size:
            raise RuntimeError(
                f"MEMORY_READ_EX returned {len(data)} bytes, "
                f"expected at least {head_size}")
        res = HvMemoryResultEx.from_buffer_copy(data[:head_size])
        if res.Status != 0:
            raise NetrError("memory_read_ex", res.Status)
        end = head_size + res.BytesTransferred
        if end > len(data):
            raise RuntimeError(
                f"MEMORY_READ_EX truncated: BytesTransferred={res.BytesTransferred} "
                f"but only {len(data) - head_size} payload bytes available")
        return bytes(data[head_size:end])

    def memory_write_ex(self, pid: int, addr: int, data: bytes) -> int:
        """写 1..65536 字节。len(data) <= 4096 时与 memory_write 等价但 IOCTL 码不同。"""
        _validate_user_pid_write(pid, "memory_write_ex")
        if not data or len(data) > HV_MEMORY_EX_MAX_PAYLOAD:
            raise ValueError(
                f"data must be 1..{HV_MEMORY_EX_MAX_PAYLOAD} bytes (got {len(data)})")

        # input = 24 字节 header + len(data) 字节 payload
        req = HvMemoryRequestEx(ProcessId=pid, Address=addr, Size=len(data))
        in_buf = bytes(req) + bytes(data)
        out = self.device.ioctl(IOCTL_HV_MEMORY_WRITE_EX, in_buf=in_buf,
                                out_size=ctypes.sizeof(HvMemoryResultEx))
        res = HvMemoryResultEx.from_buffer_copy(out)
        if res.Status != 0:
            raise NetrError("memory_write_ex", res.Status)
        return res.BytesTransferred

    # ---- 批量 R/W (优化 #1): 一次 IOCTL 处理 N 个地址 -----------------
    #
    # 适用场景: Cheat-Engine 多地址监视 (HUD 屏幕里同时显示 HP/MP/坐标/装备 ...)。
    # 与 N 次 memory_read 相比, 单次 IOCTL 摊薄 syscall + METHOD_BUFFERED copy
    # 开销, GUI 端 N=20 4-byte read 吞吐 ×6 (从 2K/s → 12K/s+ 全批)。
    #
    # 单项失败不中止 batch (e.g. 某地址已 unmap): 该项的 status 字段携带 NTSTATUS,
    # 其他项继续处理。

    def memory_batch_read(self, pid: int,
                          requests: list[tuple[int, int]]
                          ) -> list[tuple[int, bytes]]:
        """批量读多个地址。

        Args:
            pid:       目标进程 PID
            requests:  [(address, size), ...], 总 size ≤ 64 KB, count ≤ 256

        Returns:
            [(status, data), ...] 与 requests 同序; status=0 表示该项成功,
            data 是该项的字节。status != 0 时 data 为空 bytes。
        """
        _validate_user_pid_read(pid, "memory_batch_read")
        count = len(requests)
        if count == 0 or count > HV_BATCH_MAX_ITEMS:
            raise ValueError(
                f"requests count must be 1..{HV_BATCH_MAX_ITEMS} (got {count})")

        # 算 payload 总和 + 验证每项
        total_payload = 0
        for i, (addr, size) in enumerate(requests):
            if not isinstance(addr, int) or not isinstance(size, int):
                raise ValueError(f"requests[{i}]: (address, size) must be ints")
            if size <= 0 or size > HV_BATCH_MAX_PAYLOAD:
                raise ValueError(
                    f"requests[{i}].size must be 1..{HV_BATCH_MAX_PAYLOAD}")
            total_payload += size
        if total_payload > HV_BATCH_MAX_PAYLOAD:
            raise ValueError(
                f"total payload {total_payload} exceeds {HV_BATCH_MAX_PAYLOAD}")

        # 构造 input: header + Items[]
        head = HvMemoryBatchRequest(ProcessId=pid, Count=count)
        items_arr = (HvMemoryBatchItem * count)()
        cur_offset = 0
        for i, (addr, size) in enumerate(requests):
            items_arr[i].Address       = addr
            items_arr[i].Size          = size
            items_arr[i].PayloadOffset = cur_offset
            cur_offset += size

        in_buf = bytes(head) + bytes(items_arr)

        # output 大小 = header + ResItems[] + payload
        res_head_size  = ctypes.sizeof(HvMemoryBatchResult)
        res_item_size  = ctypes.sizeof(HvMemoryBatchResItem)
        out_header_end = res_head_size + count * res_item_size
        out_size       = out_header_end + total_payload

        data = self.device.ioctl(IOCTL_HV_MEMORY_BATCH_READ,
                                 in_buf=in_buf, out_size=out_size)
        if len(data) < out_header_end:
            raise RuntimeError(
                f"MEMORY_BATCH_READ returned {len(data)} bytes, "
                f"expected at least {out_header_end}")

        res_head = HvMemoryBatchResult.from_buffer_copy(data[:res_head_size])
        if res_head.TopStatus != 0:
            raise NetrError("memory_batch_read", res_head.TopStatus)
        if res_head.Count != count:
            raise RuntimeError(
                f"MEMORY_BATCH_READ count mismatch: got {res_head.Count}, "
                f"expected {count}")

        # 解析 ResItems[]
        results: list[tuple[int, bytes]] = []
        payload_base = out_header_end
        for i in range(count):
            ri_off = res_head_size + i * res_item_size
            ri = HvMemoryBatchResItem.from_buffer_copy(
                data[ri_off:ri_off + res_item_size])
            if ri.Status == 0 and ri.BytesTransferred > 0:
                start = payload_base + items_arr[i].PayloadOffset
                end   = start + ri.BytesTransferred
                if end > len(data):
                    raise RuntimeError(
                        f"MEMORY_BATCH_READ truncated at item {i}: "
                        f"need {end} bytes, have {len(data)}")
                results.append((ri.Status, bytes(data[start:end])))
            else:
                results.append((ri.Status, b""))
        return results

    def memory_batch_write(self, pid: int,
                           writes: list[tuple[int, bytes]]
                           ) -> list[tuple[int, int]]:
        """批量写多个地址。

        Args:
            pid:     目标进程 PID
            writes:  [(address, data), ...], 总数据 ≤ 64 KB, count ≤ 256

        Returns:
            [(status, bytes_written), ...] 与 writes 同序; status=0 表示该项成功。
        """
        _validate_user_pid_write(pid, "memory_batch_write")
        count = len(writes)
        if count == 0 or count > HV_BATCH_MAX_ITEMS:
            raise ValueError(
                f"writes count must be 1..{HV_BATCH_MAX_ITEMS} (got {count})")

        total_payload = 0
        for i, (addr, data) in enumerate(writes):
            if not isinstance(addr, int):
                raise ValueError(f"writes[{i}].address must be int")
            if not isinstance(data, (bytes, bytearray)):
                raise ValueError(f"writes[{i}].data must be bytes")
            if len(data) == 0 or len(data) > HV_BATCH_MAX_PAYLOAD:
                raise ValueError(
                    f"writes[{i}].data length must be 1..{HV_BATCH_MAX_PAYLOAD}")
            total_payload += len(data)
        if total_payload > HV_BATCH_MAX_PAYLOAD:
            raise ValueError(
                f"total payload {total_payload} exceeds {HV_BATCH_MAX_PAYLOAD}")

        head = HvMemoryBatchRequest(ProcessId=pid, Count=count)
        items_arr = (HvMemoryBatchItem * count)()
        payload_buf = bytearray(total_payload)
        cur_offset = 0
        for i, (addr, data) in enumerate(writes):
            items_arr[i].Address       = addr
            items_arr[i].Size          = len(data)
            items_arr[i].PayloadOffset = cur_offset
            payload_buf[cur_offset:cur_offset + len(data)] = data
            cur_offset += len(data)

        in_buf = bytes(head) + bytes(items_arr) + bytes(payload_buf)

        res_head_size = ctypes.sizeof(HvMemoryBatchResult)
        res_item_size = ctypes.sizeof(HvMemoryBatchResItem)
        out_size      = res_head_size + count * res_item_size

        data = self.device.ioctl(IOCTL_HV_MEMORY_BATCH_WRITE,
                                 in_buf=in_buf, out_size=out_size)
        if len(data) < out_size:
            raise RuntimeError(
                f"MEMORY_BATCH_WRITE returned {len(data)} bytes, "
                f"expected {out_size}")

        res_head = HvMemoryBatchResult.from_buffer_copy(data[:res_head_size])
        if res_head.TopStatus != 0:
            raise NetrError("memory_batch_write", res_head.TopStatus)
        if res_head.Count != count:
            raise RuntimeError(
                f"MEMORY_BATCH_WRITE count mismatch: got {res_head.Count}, "
                f"expected {count}")

        results: list[tuple[int, int]] = []
        for i in range(count):
            ri_off = res_head_size + i * res_item_size
            ri = HvMemoryBatchResItem.from_buffer_copy(
                data[ri_off:ri_off + res_item_size])
            results.append((ri.Status, ri.BytesTransferred))
        return results

    def memory_alloc(self, pid: int, size: int,
                     protection: int = 0x40) -> int:    # PAGE_EXECUTE_READWRITE
        _validate_user_pid(pid, "memory_alloc")
        req = HvMemoryRequest(ProcessId=pid, Address=0, Size=size,
                              Protection=protection)
        out = self.device.ioctl(IOCTL_HV_MEMORY_ALLOC, in_buf=req,
                                out_size=ctypes.sizeof(HvMemoryResult))
        res = HvMemoryResult.from_buffer_copy(out)
        if res.Status != 0:
            raise NetrError("memory_alloc", res.Status)
        return res.Address

    def memory_free(self, pid: int, addr: int, size: int = 0) -> None:
        _validate_user_pid(pid, "memory_free")
        req = HvMemoryRequest(ProcessId=pid, Address=addr, Size=size)
        self.device.ioctl(IOCTL_HV_MEMORY_FREE, in_buf=req)

    # ================================================================ module enum
    #
    # 无痕模块枚举: PID → PEB → Ldr → InLoadOrderModuleList,整条路径走 VtRoot
    # (VMCALL),驱动 hot path 零 Mm*/Ps*/Ob* 调用。返回 (DllBase, SizeOfImage, Name)
    # 列表,按链表顺序 (大致是加载顺序,主 EXE 在最前,后面是各 DLL)。
    #
    # MaxModules 默认 384(与驱动 HV_MAX_MODULES_PER_PROCESS 一致),实际进程
    # 一般几十到一两百个模块,内存占用 ~272B × 384 ≈ 100KB,够。

    def enumerate_modules(self, pid: int,
                          max_modules: int = HV_MAX_MODULES_PER_PROCESS
                          ) -> list[HvModuleInfo]:
        """枚举目标进程加载的模块 (DLL/EXE).

        Args:
            pid:           目标进程 PID。允许 user PID; PID=0/4 (Idle/System) 会被
                           驱动拒绝并返回 STATUS_NOT_FOUND (没有 PEB)。
            max_modules:   GUI 期望的最大返回条数,driver 仍受 HV_MAX_MODULES_PER_PROCESS
                           上限保护。

        Returns:
            HvModuleInfo 列表,可读 .DllBase / .SizeOfImage / .Name (str)。
            空列表 = STATUS_SUCCESS 但 Count=0 (例如 System 进程没 user-mode)。
        """
        _validate_user_pid(pid, "enumerate_modules")
        if max_modules <= 0 or max_modules > HV_MAX_MODULES_PER_PROCESS:
            raise ValueError(
                f"max_modules must be 1..{HV_MAX_MODULES_PER_PROCESS}, got {max_modules}")

        req = HvModuleEnumRequest(ProcessId=pid, MaxModules=max_modules)
        head_size = ctypes.sizeof(HvModuleEnumResult)
        ent_size  = ctypes.sizeof(HvModuleInfo)
        out_size  = head_size + max_modules * ent_size

        data = self.device.ioctl(IOCTL_HV_ENUMERATE_MODULES,
                                 in_buf=req, out_size=out_size)
        if len(data) < head_size:
            raise RuntimeError(
                f"ENUMERATE_MODULES returned {len(data)} bytes, "
                f"expected at least {head_size}")

        head = HvModuleEnumResult.from_buffer_copy(data[:head_size])
        if head.Status != 0:
            raise NetrError("enumerate_modules", head.Status)

        count = head.Count
        body_size = count * ent_size
        if len(data) < head_size + body_size:
            raise RuntimeError(
                f"ENUMERATE_MODULES truncated: Count={count} needs "
                f"{head_size + body_size} bytes, got {len(data)}")

        modules: list[HvModuleInfo] = []
        for i in range(count):
            off = head_size + i * ent_size
            mod = HvModuleInfo.from_buffer_copy(data[off:off + ent_size])
            modules.append(mod)
        return modules

    # ================================================================ injection

    def inject_dll(self, pid: int, dll_path: str,
                   hide_from_peb: bool = False,
                   erase_pe_header: bool = False,
                   manual_map: bool = False,
                   stealth_level: int = 0) -> HvInjectDllResult:
        if len(dll_path) >= 520:
            raise ValueError("dll_path too long (max 519 wide chars)")
        req = HvInjectDllRequest(
            TargetPid=pid, DllPath=dll_path,
            HideFromPeb=int(hide_from_peb),
            ErasePeHeader=int(erase_pe_header),
            UseManualMap=int(manual_map),
            StealthLevel=stealth_level,
        )
        out = self.device.ioctl(IOCTL_HV_INJECT_DLL, in_buf=req,
                                out_size=ctypes.sizeof(HvInjectDllResult))
        res = HvInjectDllResult.from_buffer_copy(out)
        if res.Status != 0:
            raise NetrError("inject_dll", res.Status)
        return res

    # ================================================================ HWBP (阶段 7)
    #
    # VT 透明硬件断点:CR3 切换时载入 DR0..3+DR7,命中后 #DB 被 hypervisor 拦下来
    # 投递事件到本进程 ring。MOV-DR 也被拦,target 进程看自己的 DR 永远是 0,
    # 反作弊从 ring-3 无法观察到任何痕迹。
    #
    # 前置:caller 已经通过 IOCTL_HV_ADD_DEBUGGER 注册成 debugger;driver 用
    # `HvHookIsDebuggerPid(caller)` 检查 IOCTL 权限。
    #
    # SET_HWBP / CLEAR_HWBP / WAIT_EVENT / CONTINUE 的内核实现:Driver.c:1068-1223
    # 数据通路:HvDebugger.c (event ring + DR shadow) ←→ HvVmExit.c (MOV-DR + #DB)

    HWBP_TYPE_EXEC  = HV_HWBP_TYPE_EXEC
    HWBP_TYPE_WRITE = HV_HWBP_TYPE_WRITE
    HWBP_TYPE_IO    = HV_HWBP_TYPE_IO
    HWBP_TYPE_RW    = HV_HWBP_TYPE_RW

    def set_hwbp(self, target_pid: int, slot: int, address: int,
                 length: int = 1, bp_type: int = HV_HWBP_TYPE_EXEC,
                 debugger_pid: Optional[int] = None) -> None:
        """Install a hardware breakpoint on target_pid's DR<slot>.

        Args:
            target_pid:  被监控进程 PID。
            slot:        0..3 (DR0..DR3)。
            address:     断点地址 (target 进程的 GVA)。
            length:      1/2/4/8 字节;EXEC 类型必须 1。
            bp_type:     HV_HWBP_TYPE_EXEC / WRITE / RW (IO 通常不可用)。
            debugger_pid: 默认 caller PID;指定时必须是已 ADD_DEBUGGER 的 PID。
        """
        _validate_user_pid(target_pid, "set_hwbp")
        if slot not in (0, 1, 2, 3):
            raise ValueError("slot must be 0..3")
        if length not in (1, 2, 4, 8):
            raise ValueError("length must be 1/2/4/8")
        if bp_type not in (HV_HWBP_TYPE_EXEC, HV_HWBP_TYPE_WRITE,
                           HV_HWBP_TYPE_IO, HV_HWBP_TYPE_RW):
            raise ValueError("bp_type must be HV_HWBP_TYPE_*")
        # x86 硬件约束:EXEC 类型 LEN 必须 = 1
        if bp_type == HV_HWBP_TYPE_EXEC and length != 1:
            raise ValueError("EXEC breakpoint requires length=1")

        req = HvHwBpRequest(
            DebuggerPid=debugger_pid if debugger_pid is not None else os.getpid(),
            TargetPid=target_pid,
            SlotIndex=slot,
            Address=address,
            Length=length,
            Type=bp_type,
        )
        out = self.device.ioctl(IOCTL_HV_DBG_SET_HWBP, in_buf=req,
                                out_size=ctypes.sizeof(HvDbgResult))
        res = HvDbgResult.from_buffer_copy(out)
        if res.Status != 0:
            raise NetrError("set_hwbp", res.Status)

    def clear_hwbp(self, target_pid: int, slot: int,
                   debugger_pid: Optional[int] = None) -> None:
        """Disable target_pid's DR<slot>.  Idempotent."""
        _validate_user_pid(target_pid, "clear_hwbp")
        if slot not in (0, 1, 2, 3):
            raise ValueError("slot must be 0..3")

        req = HvHwBpRequest(
            DebuggerPid=debugger_pid if debugger_pid is not None else os.getpid(),
            TargetPid=target_pid,
            SlotIndex=slot,
        )
        out = self.device.ioctl(IOCTL_HV_DBG_CLEAR_HWBP, in_buf=req,
                                out_size=ctypes.sizeof(HvDbgResult))
        res = HvDbgResult.from_buffer_copy(out)
        if res.Status != 0:
            raise NetrError("clear_hwbp", res.Status)

    # WAIT_EVENT 用 0xFFFFFFFF 表示无限阻塞;Python 端默认短超时,免得 GUI 卡死。
    WAIT_INFINITE = 0xFFFFFFFF

    def wait_event(self, timeout_ms: int = 0,
                   debugger_pid: Optional[int] = None) -> Optional[HvDebugEvent]:
        """Block (or poll) until a HWBP event arrives.

        Returns:
            HvDebugEvent  on hit
            None          on timeout (no event available)

        Note: This IOCTL holds the IRP in kernel for up to ``timeout_ms`` —
        call from a background thread when using INFINITE.
        """
        req = HvDbgWaitRequest(
            DebuggerPid=debugger_pid if debugger_pid is not None else os.getpid(),
            TimeoutMs=timeout_ms,
        )
        out = self.device.ioctl(IOCTL_HV_DBG_WAIT_EVENT, in_buf=req,
                                out_size=ctypes.sizeof(HvDbgWaitResult))
        res = HvDbgWaitResult.from_buffer_copy(out)
        if res.Status == HV_STATUS_SUCCESS:
            return res.Event
        if res.Status == HV_STATUS_NOT_FOUND:
            return None     # timeout / no event
        raise NetrError("wait_event", res.Status)

    def continue_event(self, sequence: int,
                       debugger_pid: Optional[int] = None) -> None:
        """Acknowledge an event (V1 is a pure trace ack, no side effect)."""
        req = HvDbgContinueRequest(
            DebuggerPid=debugger_pid if debugger_pid is not None else os.getpid(),
            Sequence=sequence,
        )
        out = self.device.ioctl(IOCTL_HV_DBG_CONTINUE, in_buf=req,
                                out_size=ctypes.sizeof(HvDbgResult))
        res = HvDbgResult.from_buffer_copy(out)
        if res.Status != 0:
            raise NetrError("continue_event", res.Status)

    # ================================================================ injection (cont.)

    def inject_shellcode(self, pid: int, shellcode: bytes,
                         parameter: int = 0,
                         execute: bool = True,
                         hide_memory: bool = False) -> HvInjectShellcodeResult:
        if not shellcode or len(shellcode) > 4096:
            raise ValueError("shellcode must be 1..4096 bytes")
        req = HvInjectShellcodeRequest(
            TargetPid=pid, ShellcodeSize=len(shellcode),
            Parameter=parameter,
            ExecuteImmediately=int(execute),
            HideMemory=int(hide_memory),
        )
        ctypes.memmove(req.Shellcode, shellcode, len(shellcode))
        out = self.device.ioctl(IOCTL_HV_INJECT_SHELLCODE, in_buf=req,
                                out_size=ctypes.sizeof(HvInjectShellcodeResult))
        res = HvInjectShellcodeResult.from_buffer_copy(out)
        if res.Status != 0:
            raise NetrError("inject_shellcode", res.Status)
        return res

    # ================================================================ Phase G: DbgEvt
    #
    # 拉取驱动 ring buffer 里的根因事件。GUI 后台线程 1s 调一次,把 last_seen seq
    # 持久化在调用方,只接收新事件。
    # 返回: (list[HvDbgEvt], next_sequence)
    #   next_sequence 是 ring 中最新事件的 Sequence (客户端下次传入)。
    #   首次调用传 since_sequence=0 -> 拉到 ring 中所有存活事件。

    def dbgevt_pull(self, since_sequence: int = 0,
                    max_count: int = 64) -> tuple[list, int]:
        if max_count <= 0 or max_count > 256:
            raise ValueError("max_count must be 1..256")

        req = HvDbgEvtPullReq(SinceSequence=since_sequence, MaxCount=max_count)

        head_size = ctypes.sizeof(HvDbgEvtPullRes)
        item_size = ctypes.sizeof(HvDbgEvt)
        out_size  = head_size + max_count * item_size

        data = self.device.ioctl(IOCTL_HV_GET_DBGEVT,
                                 in_buf=bytes(req), out_size=out_size)
        if len(data) < head_size:
            raise RuntimeError(
                f"GET_DBGEVT returned {len(data)} bytes, expected at least {head_size}")

        res = HvDbgEvtPullRes.from_buffer_copy(data[:head_size])
        count = res.Count
        if count > max_count:
            raise RuntimeError(
                f"GET_DBGEVT count {count} > requested max {max_count}")

        events: list[HvDbgEvt] = []
        for i in range(count):
            off = head_size + i * item_size
            ev = HvDbgEvt.from_buffer_copy(data[off:off + item_size])
            events.append(ev)
        return events, res.NextSequence
