"""Process enumeration via Toolhelp32 — pure ctypes, no psutil dependency.

Toolhelp 走快照,不需要对每个 target 开 handle —— PPL 进程 (lsass、csrss、
MsMpEng) 也能列出来。比 EnumProcesses + GetModuleBaseNameW 简单也更安全。
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from dataclasses import dataclass


_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value
TH32CS_SNAPPROCESS   = 0x00000002
MAX_PATH             = 260


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = (
        ("dwSize",              wintypes.DWORD),
        ("cntUsage",            wintypes.DWORD),
        ("th32ProcessID",       wintypes.DWORD),
        ("th32DefaultHeapID",   ctypes.c_void_p),
        ("th32ModuleID",        wintypes.DWORD),
        ("cntThreads",          wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase",      wintypes.LONG),
        ("dwFlags",             wintypes.DWORD),
        ("szExeFile",           wintypes.WCHAR * MAX_PATH),
    )


CreateToolhelp32Snapshot = _kernel32.CreateToolhelp32Snapshot
CreateToolhelp32Snapshot.argtypes = (wintypes.DWORD, wintypes.DWORD)
CreateToolhelp32Snapshot.restype  = wintypes.HANDLE

Process32FirstW = _kernel32.Process32FirstW
Process32FirstW.argtypes = (wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W))
Process32FirstW.restype  = wintypes.BOOL

Process32NextW = _kernel32.Process32NextW
Process32NextW.argtypes = (wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W))
Process32NextW.restype  = wintypes.BOOL

CloseHandle = _kernel32.CloseHandle
CloseHandle.argtypes = (wintypes.HANDLE,)
CloseHandle.restype  = wintypes.BOOL


@dataclass(frozen=True)
class ProcessInfo:
    pid:        int
    name:       str
    parent_pid: int
    threads:    int


# 默认隐藏的系统进程 (按 name 匹配,大小写不敏感)
_SYSTEM_NAMES = frozenset({
    "system",
    "registry",
    "memory compression",
    "secure system",
    "system idle process",
})


def list_processes() -> list[ProcessInfo]:
    """Return all processes via Toolhelp snapshot. Never raises on missing entries."""
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == INVALID_HANDLE_VALUE or snap == 0:
        return []
    out: list[ProcessInfo] = []
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        if not Process32FirstW(snap, ctypes.byref(entry)):
            return out
        while True:
            out.append(ProcessInfo(
                pid=int(entry.th32ProcessID),
                name=entry.szExeFile,
                parent_pid=int(entry.th32ParentProcessID),
                threads=int(entry.cntThreads),
            ))
            if not Process32NextW(snap, ctypes.byref(entry)):
                break
    finally:
        CloseHandle(snap)
    return out


def is_system_process(p: ProcessInfo) -> bool:
    """True for processes that are not user-targetable (Idle, System, Registry, …)."""
    if p.pid in (0, 4):
        return True
    return p.name.lower() in _SYSTEM_NAMES
