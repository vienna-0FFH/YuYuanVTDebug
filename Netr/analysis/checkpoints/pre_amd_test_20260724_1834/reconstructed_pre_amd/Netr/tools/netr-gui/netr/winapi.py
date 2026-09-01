"""Win32 ctypes prototypes and constants.

All raw advapi32 / kernel32 entry points used by the rest of the package live
here. Keeping them in one module makes the prototypes auditable and lets every
caller use the same signature.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes


kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)


INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value

GENERIC_READ  = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ  = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x80

FORMAT_MESSAGE_FROM_SYSTEM     = 0x00001000
FORMAT_MESSAGE_IGNORE_INSERTS  = 0x00000200

TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_QUERY             = 0x0008
SE_PRIVILEGE_ENABLED    = 0x00000002

SC_MANAGER_ALL_ACCESS  = 0xF003F
SERVICE_ALL_ACCESS     = 0xF01FF
SERVICE_KERNEL_DRIVER  = 0x00000001
SERVICE_DEMAND_START   = 0x00000003
SERVICE_ERROR_NORMAL   = 0x00000001
SERVICE_CONTROL_STOP   = 0x00000001
SC_STATUS_PROCESS_INFO = 0
SERVICE_STOPPED          = 0x00000001
SERVICE_START_PENDING    = 0x00000002
SERVICE_STOP_PENDING     = 0x00000003
SERVICE_RUNNING          = 0x00000004
SERVICE_CONTINUE_PENDING = 0x00000005
SERVICE_PAUSE_PENDING    = 0x00000006
SERVICE_PAUSED           = 0x00000007

ERROR_SUCCESS               = 0
ERROR_FILE_NOT_FOUND        = 2
ERROR_ACCESS_DENIED         = 5
ERROR_SERVICE_EXISTS        = 1073
ERROR_SERVICE_ALREADY_RUNNING = 1056
ERROR_SERVICE_DOES_NOT_EXIST  = 1060
ERROR_SERVICE_NOT_ACTIVE      = 1062
ERROR_SERVICE_MARKED_FOR_DELETE = 1072


# ---------------------------------------------------------------------- types

class LUID(ctypes.Structure):
    _fields_ = (("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG))


class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = (("Luid", LUID), ("Attributes", wintypes.DWORD))


class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = (
        ("PrivilegeCount", wintypes.DWORD),
        ("Privileges", LUID_AND_ATTRIBUTES * 1),
    )


class SERVICE_STATUS(ctypes.Structure):
    _fields_ = (
        ("dwServiceType",             wintypes.DWORD),
        ("dwCurrentState",            wintypes.DWORD),
        ("dwControlsAccepted",        wintypes.DWORD),
        ("dwWin32ExitCode",           wintypes.DWORD),
        ("dwServiceSpecificExitCode", wintypes.DWORD),
        ("dwCheckPoint",              wintypes.DWORD),
        ("dwWaitHint",                wintypes.DWORD),
    )


class SERVICE_STATUS_PROCESS(ctypes.Structure):
    _fields_ = (
        ("dwServiceType",             wintypes.DWORD),
        ("dwCurrentState",            wintypes.DWORD),
        ("dwControlsAccepted",        wintypes.DWORD),
        ("dwWin32ExitCode",           wintypes.DWORD),
        ("dwServiceSpecificExitCode", wintypes.DWORD),
        ("dwCheckPoint",              wintypes.DWORD),
        ("dwWaitHint",                wintypes.DWORD),
        ("dwProcessId",               wintypes.DWORD),
        ("dwServiceFlags",            wintypes.DWORD),
    )


SC_HANDLE = wintypes.HANDLE


# ---------------------------------------------------------------------- kernel32

CreateFileW = kernel32.CreateFileW
CreateFileW.argtypes = (
    wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
    ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
)
CreateFileW.restype = wintypes.HANDLE

DeviceIoControl = kernel32.DeviceIoControl
DeviceIoControl.argtypes = (
    wintypes.HANDLE, wintypes.DWORD,
    ctypes.c_void_p, wintypes.DWORD,
    ctypes.c_void_p, wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p,
)
DeviceIoControl.restype = wintypes.BOOL

CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = (wintypes.HANDLE,)
CloseHandle.restype = wintypes.BOOL

GetCurrentProcess = kernel32.GetCurrentProcess
GetCurrentProcess.argtypes = ()
GetCurrentProcess.restype = wintypes.HANDLE

FormatMessageW = kernel32.FormatMessageW
FormatMessageW.argtypes = (
    wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
    wintypes.LPWSTR, wintypes.DWORD, ctypes.c_void_p,
)
FormatMessageW.restype = wintypes.DWORD


# ---------------------------------------------------------------------- advapi32

OpenProcessToken = advapi32.OpenProcessToken
OpenProcessToken.argtypes = (wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE))
OpenProcessToken.restype = wintypes.BOOL

LookupPrivilegeValueW = advapi32.LookupPrivilegeValueW
LookupPrivilegeValueW.argtypes = (wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.POINTER(LUID))
LookupPrivilegeValueW.restype = wintypes.BOOL

AdjustTokenPrivileges = advapi32.AdjustTokenPrivileges
AdjustTokenPrivileges.argtypes = (
    wintypes.HANDLE, wintypes.BOOL,
    ctypes.POINTER(TOKEN_PRIVILEGES), wintypes.DWORD,
    ctypes.POINTER(TOKEN_PRIVILEGES), ctypes.POINTER(wintypes.DWORD),
)
AdjustTokenPrivileges.restype = wintypes.BOOL

OpenSCManagerW = advapi32.OpenSCManagerW
OpenSCManagerW.argtypes = (wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD)
OpenSCManagerW.restype = SC_HANDLE

CreateServiceW = advapi32.CreateServiceW
CreateServiceW.argtypes = (
    SC_HANDLE, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
    wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.LPCWSTR,
    wintypes.LPCWSTR, ctypes.POINTER(wintypes.DWORD), wintypes.LPCWSTR,
    wintypes.LPCWSTR, wintypes.LPCWSTR,
)
CreateServiceW.restype = SC_HANDLE

OpenServiceW = advapi32.OpenServiceW
OpenServiceW.argtypes = (SC_HANDLE, wintypes.LPCWSTR, wintypes.DWORD)
OpenServiceW.restype = SC_HANDLE

StartServiceW = advapi32.StartServiceW
StartServiceW.argtypes = (SC_HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.LPCWSTR))
StartServiceW.restype = wintypes.BOOL

ControlService = advapi32.ControlService
ControlService.argtypes = (SC_HANDLE, wintypes.DWORD, ctypes.POINTER(SERVICE_STATUS))
ControlService.restype = wintypes.BOOL

DeleteService = advapi32.DeleteService
DeleteService.argtypes = (SC_HANDLE,)
DeleteService.restype = wintypes.BOOL

QueryServiceStatusEx = advapi32.QueryServiceStatusEx
QueryServiceStatusEx.argtypes = (
    SC_HANDLE, wintypes.DWORD,
    ctypes.POINTER(SERVICE_STATUS_PROCESS),
    wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
)
QueryServiceStatusEx.restype = wintypes.BOOL

CloseServiceHandle = advapi32.CloseServiceHandle
CloseServiceHandle.argtypes = (SC_HANDLE,)
CloseServiceHandle.restype = wintypes.BOOL


# ---------------------------------------------------------------------- helpers

def format_error(code: int | None = None) -> str:
    """Translate a Win32 error code to a readable string."""
    if code is None:
        code = ctypes.get_last_error()
    if code == 0:
        return "ERROR_SUCCESS"
    buf = ctypes.create_unicode_buffer(512)
    n = FormatMessageW(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        None, code, 0, buf, len(buf), None,
    )
    msg = buf.value.strip() if n else f"unknown error 0x{code:08X}"
    return f"[{code}/0x{code:08X}] {msg}"


class Win32Error(OSError):
    """Carries Win32 error code + formatted message."""

    def __init__(self, where: str, code: int | None = None):
        if code is None:
            code = ctypes.get_last_error()
        self.code = code
        self.where = where
        super().__init__(f"{where} failed: {format_error(code)}")
