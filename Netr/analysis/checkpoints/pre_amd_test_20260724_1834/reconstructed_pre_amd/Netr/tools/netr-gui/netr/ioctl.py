"""IOCTL codes and ``NetrDevice`` (CreateFile + DeviceIoControl wrapper).

The IOCTL macro values are computed via ``CTL_CODE`` exactly as the driver
defines them (Driver.c lines 37-59). All IOCTLs use ``FILE_DEVICE_UNKNOWN``,
``METHOD_BUFFERED``, ``FILE_ANY_ACCESS``.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from typing import Optional

from . import winapi
from .winapi import (
    CloseHandle, CreateFileW, DeviceIoControl,
    GENERIC_READ, GENERIC_WRITE, OPEN_EXISTING,
    FILE_SHARE_READ, FILE_SHARE_WRITE,
    INVALID_HANDLE_VALUE, Win32Error,
)


# Phase 8.4 — 设备名片段由驱动启动期随机生成,通过注册表暴露:
#   HKLM\Software\NetrSvc\DeviceName (REG_SZ) = 16-char leaf
# 读不到则回退到 DEVICE_PATH_FALLBACK(开发态固定名)。
DEVICE_PATH_FALLBACK = r"\\.\HvControl"
DEVICE_NAME_REG_SUBKEY = r"Software\NetrSvc"
DEVICE_NAME_REG_VALUE  = "DeviceName"


def resolve_device_path() -> str:
    r"""Read the dynamic device leaf name from HKLM and build the \\.\<leaf> path.

    Falls back to ``DEVICE_PATH_FALLBACK`` if the registry value is missing
    (driver not yet running, or built with HV_USE_FIXED_DEVICE_NAME=1).

    The driver's HvRegistryHook hides the "NetrSvc" key from enumeration,
    but RegOpenKeyEx with a direct path bypasses NtEnumerateKey, so this
    read works.
    """
    try:
        import winreg
    except ImportError:
        return DEVICE_PATH_FALLBACK

    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, DEVICE_NAME_REG_SUBKEY,
                            0, winreg.KEY_QUERY_VALUE | winreg.KEY_WOW64_64KEY) as k:
            leaf, kind = winreg.QueryValueEx(k, DEVICE_NAME_REG_VALUE)
    except (OSError, FileNotFoundError):
        return DEVICE_PATH_FALLBACK

    if kind != winreg.REG_SZ or not isinstance(leaf, str) or not leaf:
        return DEVICE_PATH_FALLBACK

    return f"\\\\.\\{leaf}"


# DEPRECATED — kept as a fallback display value. Do NOT use this for opening
# the device: it's captured at module-import time and goes stale as soon as
# the driver is unloaded and reloaded (each DriverEntry mints a fresh random
# leaf and overwrites the registry value, but this constant won't update).
# Callers that want the *current* path should call ``resolve_device_path()``.
DEVICE_PATH = resolve_device_path()


# --------------------------------------------------------------------- CTL_CODE

FILE_DEVICE_UNKNOWN = 0x22
METHOD_BUFFERED     = 0
FILE_ANY_ACCESS     = 0
HV_IOCTL_BASE       = 0x800


def CTL_CODE(device_type: int, function: int, method: int, access: int) -> int:
    return (device_type << 16) | (access << 14) | (function << 2) | method


def _hv(offset: int) -> int:
    return CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + offset,
                    METHOD_BUFFERED, FILE_ANY_ACCESS)


IOCTL_HV_GET_STATUS              = _hv(0x00)
IOCTL_HV_DISABLE_DSE             = _hv(0x10)
IOCTL_HV_ENABLE_DSE              = _hv(0x11)
IOCTL_HV_GET_DSE_STATUS          = _hv(0x12)
IOCTL_HV_HIDE_PROCESS            = _hv(0x20)
IOCTL_HV_UNHIDE_PROCESS          = _hv(0x21)
IOCTL_HV_HIDE_DRIVER             = _hv(0x30)
IOCTL_HV_UNHIDE_DRIVER           = _hv(0x31)
IOCTL_HV_ADD_DEBUGGER            = _hv(0x40)
IOCTL_HV_REMOVE_DEBUGGER         = _hv(0x41)
IOCTL_HV_PROTECT_PROCESS         = _hv(0x43)
IOCTL_HV_UNPROTECT_PROCESS       = _hv(0x44)
# 阶段 7.9: NtOpenProcess EPT 代理 (PPL/System=4 绕过,默认 OFF,高危)
IOCTL_HV_ENABLE_ACCESS_BYPASS    = _hv(0x4A)
IOCTL_HV_DISABLE_ACCESS_BYPASS   = _hv(0x4B)
# 阶段 7.10: VT 透明键鼠注入 (PS/2 I/O bitmap + IRQ injection)
IOCTL_HV_INPUT_ENABLE            = _hv(0x4C)
IOCTL_HV_INPUT_DISABLE           = _hv(0x4D)
IOCTL_HV_INPUT_SEND_KEY          = _hv(0x4E)
IOCTL_HV_INPUT_SEND_MOUSE        = _hv(0x4F)
IOCTL_HV_ENABLE_ANTIANTIDEBUG    = _hv(0x50)
IOCTL_HV_DISABLE_ANTIANTIDEBUG   = _hv(0x51)
IOCTL_HV_INPUT_GET_STATUS        = _hv(0x52)
IOCTL_HV_INPUT_GET_XHCI_STATUS   = _hv(0x53)
IOCTL_HV_INPUT_SET_STRICT_MODE   = _hv(0x54)
# Item 2: xHCI USBSTS/IMAN EPT 读 trap 控制 (默认 OFF,显式启用以排查 hang)
IOCTL_HV_XHCI_TRAP_ENABLE        = _hv(0x55)
IOCTL_HV_XHCI_TRAP_DISABLE       = _hv(0x56)
IOCTL_HV_XHCI_TRAP_GET_STATS     = _hv(0x57)
IOCTL_HV_INJECT_DLL              = _hv(0x60)
IOCTL_HV_INJECT_SHELLCODE        = _hv(0x70)
IOCTL_HV_MEMORY_READ             = _hv(0x80)
IOCTL_HV_MEMORY_WRITE            = _hv(0x81)
IOCTL_HV_MEMORY_ALLOC            = _hv(0x82)
IOCTL_HV_MEMORY_FREE             = _hv(0x83)
# 无痕模块枚举(走 VtRoot, 零 Mm*/Ps*/Ob* 调用)
IOCTL_HV_ENUMERATE_MODULES       = _hv(0x84)
# 变长内存读写 (优化 #3, METHOD_BUFFERED 变长尾, 单次 ≤ 64 KB)
IOCTL_HV_MEMORY_READ_EX          = _hv(0x85)
IOCTL_HV_MEMORY_WRITE_EX         = _hv(0x86)
# 批量内存读写 (优化 #1, Items[Count] + 紧贴 payload, Count ≤ 256, payload 总 ≤ 64 KB)
IOCTL_HV_MEMORY_BATCH_READ       = _hv(0x87)
IOCTL_HV_MEMORY_BATCH_WRITE      = _hv(0x88)
IOCTL_HV_GET_NESTED_STATUS       = _hv(0xA0)
IOCTL_HV_GET_NESTED_EVENTS       = _hv(0xA1)
IOCTL_HV_CLEAR_NESTED_EVENTS     = _hv(0xA2)
# 阶段 7: VT 透明硬件断点 (HWBP)
# Driver.c:85-88 - 0x100..0x103
IOCTL_HV_DBG_SET_HWBP            = _hv(0x100)
IOCTL_HV_DBG_CLEAR_HWBP          = _hv(0x101)
IOCTL_HV_DBG_WAIT_EVENT          = _hv(0x102)
IOCTL_HV_DBG_CONTINUE            = _hv(0x103)
# Phase G: 根因事件 ring buffer 拉取 (GUI 1s 轮询)
IOCTL_HV_GET_DBGEVT              = _hv(0x106)


IOCTL_NAME = {
    IOCTL_HV_GET_STATUS:            "GET_STATUS",
    IOCTL_HV_DISABLE_DSE:           "DISABLE_DSE",
    IOCTL_HV_ENABLE_DSE:            "ENABLE_DSE",
    IOCTL_HV_GET_DSE_STATUS:        "GET_DSE_STATUS",
    IOCTL_HV_HIDE_PROCESS:          "HIDE_PROCESS",
    IOCTL_HV_UNHIDE_PROCESS:        "UNHIDE_PROCESS",
    IOCTL_HV_HIDE_DRIVER:           "HIDE_DRIVER",
    IOCTL_HV_UNHIDE_DRIVER:         "UNHIDE_DRIVER",
    IOCTL_HV_ADD_DEBUGGER:          "ADD_DEBUGGER",
    IOCTL_HV_REMOVE_DEBUGGER:       "REMOVE_DEBUGGER",
    IOCTL_HV_PROTECT_PROCESS:       "PROTECT_PROCESS",
    IOCTL_HV_UNPROTECT_PROCESS:     "UNPROTECT_PROCESS",
    IOCTL_HV_ENABLE_ACCESS_BYPASS:  "ENABLE_ACCESS_BYPASS",
    IOCTL_HV_DISABLE_ACCESS_BYPASS: "DISABLE_ACCESS_BYPASS",
    IOCTL_HV_INPUT_ENABLE:          "INPUT_ENABLE",
    IOCTL_HV_INPUT_DISABLE:         "INPUT_DISABLE",
    IOCTL_HV_INPUT_SEND_KEY:        "INPUT_SEND_KEY",
    IOCTL_HV_INPUT_SEND_MOUSE:      "INPUT_SEND_MOUSE",
    IOCTL_HV_INPUT_GET_STATUS:      "INPUT_GET_STATUS",
    IOCTL_HV_INPUT_GET_XHCI_STATUS: "INPUT_GET_XHCI_STATUS",
    IOCTL_HV_INPUT_SET_STRICT_MODE: "INPUT_SET_STRICT_MODE",
    IOCTL_HV_XHCI_TRAP_ENABLE:      "XHCI_TRAP_ENABLE",
    IOCTL_HV_XHCI_TRAP_DISABLE:     "XHCI_TRAP_DISABLE",
    IOCTL_HV_XHCI_TRAP_GET_STATS:   "XHCI_TRAP_GET_STATS",
    IOCTL_HV_ENABLE_ANTIANTIDEBUG:  "ENABLE_ANTIANTIDEBUG",
    IOCTL_HV_DISABLE_ANTIANTIDEBUG: "DISABLE_ANTIANTIDEBUG",
    IOCTL_HV_INJECT_DLL:            "INJECT_DLL",
    IOCTL_HV_INJECT_SHELLCODE:      "INJECT_SHELLCODE",
    IOCTL_HV_MEMORY_READ:           "MEMORY_READ",
    IOCTL_HV_MEMORY_WRITE:          "MEMORY_WRITE",
    IOCTL_HV_MEMORY_ALLOC:          "MEMORY_ALLOC",
    IOCTL_HV_MEMORY_FREE:           "MEMORY_FREE",
    IOCTL_HV_MEMORY_READ_EX:        "MEMORY_READ_EX",
    IOCTL_HV_MEMORY_WRITE_EX:       "MEMORY_WRITE_EX",
    IOCTL_HV_MEMORY_BATCH_READ:     "MEMORY_BATCH_READ",
    IOCTL_HV_MEMORY_BATCH_WRITE:    "MEMORY_BATCH_WRITE",
    IOCTL_HV_ENUMERATE_MODULES:     "ENUMERATE_MODULES",
    IOCTL_HV_GET_NESTED_STATUS:     "GET_NESTED_STATUS",
    IOCTL_HV_GET_NESTED_EVENTS:     "GET_NESTED_EVENTS",
    IOCTL_HV_CLEAR_NESTED_EVENTS:   "CLEAR_NESTED_EVENTS",
    IOCTL_HV_DBG_SET_HWBP:          "DBG_SET_HWBP",
    IOCTL_HV_DBG_CLEAR_HWBP:        "DBG_CLEAR_HWBP",
    IOCTL_HV_DBG_WAIT_EVENT:        "DBG_WAIT_EVENT",
    IOCTL_HV_DBG_CONTINUE:          "DBG_CONTINUE",
    IOCTL_HV_GET_DBGEVT:            "GET_DBGEVT",
}


# --------------------------------------------------------------------- device

class NetrDevice:
    """Wraps the handle to ``\\\\.\\HvControl`` and ``DeviceIoControl`` calls."""

    def __init__(self, path: Optional[str] = None):
        # Resolve fresh on every open: the driver picks a new random leaf on
        # every DriverEntry, so any cached value (e.g. module-level
        # ``DEVICE_PATH``) goes stale across stop/start cycles.
        if path is None:
            path = resolve_device_path()
        self.path = path
        h = CreateFileW(path,
                        GENERIC_READ | GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        None, OPEN_EXISTING,
                        0, None)
        if h == 0 or h == INVALID_HANDLE_VALUE:
            raise Win32Error(f"CreateFileW({path})")
        self._handle = h

    @property
    def handle(self) -> int:
        return self._handle

    def is_open(self) -> bool:
        return self._handle not in (0, INVALID_HANDLE_VALUE, None)

    def close(self) -> None:
        if self.is_open():
            CloseHandle(self._handle)
            self._handle = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()

    # ------------------------------------------------------------------ ioctl

    def ioctl(self, code: int,
              in_buf: Optional[bytes | ctypes.Structure] = None,
              out_size: int = 0) -> bytes:
        """Issue a DeviceIoControl, returns the truncated output bytes."""
        if not self.is_open():
            raise RuntimeError("device handle is closed")

        # ----- input
        if in_buf is None:
            in_ptr, in_len = None, 0
        elif isinstance(in_buf, (bytes, bytearray)):
            in_arr = (ctypes.c_ubyte * len(in_buf)).from_buffer_copy(bytes(in_buf))
            in_ptr = ctypes.cast(in_arr, ctypes.c_void_p)
            in_len = len(in_buf)
            self._inkeepalive = in_arr   # keep buffer alive across the call
        elif isinstance(in_buf, ctypes.Structure):
            in_ptr = ctypes.cast(ctypes.pointer(in_buf), ctypes.c_void_p)
            in_len = ctypes.sizeof(in_buf)
            self._inkeepalive = in_buf
        else:
            raise TypeError(f"unsupported in_buf type {type(in_buf).__name__}")

        # ----- output
        out_arr = (ctypes.c_ubyte * out_size)() if out_size else None
        out_ptr = ctypes.cast(out_arr, ctypes.c_void_p) if out_arr else None
        returned = wintypes.DWORD(0)

        ok = DeviceIoControl(self._handle, code, in_ptr, in_len,
                             out_ptr, out_size,
                             ctypes.byref(returned), None)
        if not ok:
            raise Win32Error(f"DeviceIoControl({IOCTL_NAME.get(code, hex(code))})")

        if out_arr is None:
            return b""
        return bytes(out_arr[: returned.value])
