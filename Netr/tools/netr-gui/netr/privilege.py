"""Token privilege helpers (SeLoadDriverPrivilege)."""

from __future__ import annotations

import ctypes
from ctypes import wintypes

from . import winapi
from .winapi import (
    TOKEN_ADJUST_PRIVILEGES, TOKEN_QUERY, SE_PRIVILEGE_ENABLED,
    LUID, TOKEN_PRIVILEGES,
    OpenProcessToken, LookupPrivilegeValueW, AdjustTokenPrivileges,
    GetCurrentProcess, CloseHandle, Win32Error,
)


SE_LOAD_DRIVER_NAME = "SeLoadDriverPrivilege"


def enable_privilege(name: str = SE_LOAD_DRIVER_NAME) -> bool:
    """Enable the named privilege on the current process token.

    Returns True if the privilege was newly enabled, False if it was already
    enabled. Raises ``Win32Error`` if the call fails outright; raises
    ``PermissionError`` if the privilege is not held by the token.
    """
    token = wintypes.HANDLE()
    if not OpenProcessToken(GetCurrentProcess(),
                            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                            ctypes.byref(token)):
        raise Win32Error("OpenProcessToken")
    try:
        luid = LUID()
        if not LookupPrivilegeValueW(None, name, ctypes.byref(luid)):
            raise Win32Error(f"LookupPrivilegeValueW({name})")

        tp = TOKEN_PRIVILEGES()
        tp.PrivilegeCount = 1
        tp.Privileges[0].Luid = luid
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED

        if not AdjustTokenPrivileges(token, False,
                                     ctypes.byref(tp), ctypes.sizeof(tp),
                                     None, None):
            raise Win32Error("AdjustTokenPrivileges")

        # AdjustTokenPrivileges succeeds even if the privilege isn't held —
        # GetLastError reports ERROR_NOT_ALL_ASSIGNED (1300) in that case.
        last = ctypes.get_last_error()
        if last == 1300:
            raise PermissionError(
                f"privilege '{name}' is not held by the current token "
                "(run as Administrator)"
            )
        return last == 0
    finally:
        CloseHandle(token)


def is_admin() -> bool:
    """Quick check using ``shell32!IsUserAnAdmin``."""
    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    return bool(shell32.IsUserAnAdmin())
