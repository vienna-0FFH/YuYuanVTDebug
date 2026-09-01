"""SCM-based driver service management."""

from __future__ import annotations

import ctypes
import os
import time
from ctypes import wintypes
from dataclasses import dataclass
from enum import IntEnum
from typing import Optional

from . import winapi
from .winapi import (
    SC_MANAGER_ALL_ACCESS, SERVICE_ALL_ACCESS,
    SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
    SERVICE_CONTROL_STOP, SC_STATUS_PROCESS_INFO,
    SERVICE_STOPPED, SERVICE_RUNNING, SERVICE_STOP_PENDING, SERVICE_START_PENDING,
    ERROR_SERVICE_EXISTS, ERROR_SERVICE_ALREADY_RUNNING,
    ERROR_SERVICE_DOES_NOT_EXIST, ERROR_SERVICE_NOT_ACTIVE,
    ERROR_SERVICE_MARKED_FOR_DELETE,
    SERVICE_STATUS, SERVICE_STATUS_PROCESS,
    OpenSCManagerW, CreateServiceW, OpenServiceW,
    StartServiceW, ControlService, DeleteService,
    QueryServiceStatusEx, CloseServiceHandle,
    Win32Error,
)


class ServiceState(IntEnum):
    STOPPED          = SERVICE_STOPPED
    START_PENDING    = SERVICE_START_PENDING
    STOP_PENDING     = SERVICE_STOP_PENDING
    RUNNING          = SERVICE_RUNNING
    UNKNOWN          = 0xFFFF
    NOT_INSTALLED    = 0xFFFE


@dataclass
class ServiceInfo:
    state:    ServiceState
    pid:      int
    name:     str
    bin_path: Optional[str]


class NetrService:
    """Lifecycle wrapper around the Netr kernel driver service."""

    def __init__(self, name: str = "Netr", display: Optional[str] = None):
        self.name    = name
        self.display = display or name

    # ----------------------------------------------------------- low-level

    @staticmethod
    def _open_scm() -> int:
        h = OpenSCManagerW(None, None, SC_MANAGER_ALL_ACCESS)
        if not h:
            raise Win32Error("OpenSCManagerW")
        return h

    def _open_service(self, scm: int, access: int = SERVICE_ALL_ACCESS) -> int:
        h = OpenServiceW(scm, self.name, access)
        if not h:
            raise Win32Error(f"OpenServiceW({self.name})")
        return h

    # ----------------------------------------------------------- public ops

    def install(self, sys_path: str) -> None:
        """Create the kernel service pointing at *sys_path*.

        Idempotent: if the service already exists, this is a no-op (the
        existing entry is left intact so the caller can ``start()`` it).
        """
        sys_path = os.path.abspath(sys_path)
        if not os.path.isfile(sys_path):
            raise FileNotFoundError(sys_path)

        scm = self._open_scm()
        try:
            h = CreateServiceW(
                scm, self.name, self.display, SERVICE_ALL_ACCESS,
                SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
                sys_path, None, None, None, None, None,
            )
            if not h:
                err = ctypes.get_last_error()
                if err == ERROR_SERVICE_EXISTS:
                    return                           # already installed
                raise Win32Error("CreateServiceW", err)
            CloseServiceHandle(h)
        finally:
            CloseServiceHandle(scm)

    def start(self, wait_seconds: float = 10.0) -> None:
        scm = self._open_scm()
        try:
            svc = self._open_service(scm)
            try:
                ok = StartServiceW(svc, 0, None)
                if not ok:
                    err = ctypes.get_last_error()
                    if err != ERROR_SERVICE_ALREADY_RUNNING:
                        raise Win32Error("StartServiceW", err)
            finally:
                CloseServiceHandle(svc)
        finally:
            CloseServiceHandle(scm)

        self._wait_state(ServiceState.RUNNING, wait_seconds)

    def stop(self, wait_seconds: float = 10.0) -> None:
        scm = self._open_scm()
        try:
            svc = self._open_service(scm)
            try:
                st = SERVICE_STATUS()
                ok = ControlService(svc, SERVICE_CONTROL_STOP, ctypes.byref(st))
                if not ok:
                    err = ctypes.get_last_error()
                    if err not in (ERROR_SERVICE_NOT_ACTIVE,
                                   ERROR_SERVICE_DOES_NOT_EXIST):
                        raise Win32Error("ControlService(STOP)", err)
            finally:
                CloseServiceHandle(svc)
        finally:
            CloseServiceHandle(scm)

        self._wait_state(ServiceState.STOPPED, wait_seconds)

    def uninstall(self) -> None:
        scm = self._open_scm()
        try:
            try:
                svc = self._open_service(scm)
            except Win32Error as e:
                if e.code == ERROR_SERVICE_DOES_NOT_EXIST:
                    return
                raise
            try:
                ok = DeleteService(svc)
                if not ok:
                    err = ctypes.get_last_error()
                    if err not in (ERROR_SERVICE_MARKED_FOR_DELETE,
                                   ERROR_SERVICE_DOES_NOT_EXIST):
                        raise Win32Error("DeleteService", err)
            finally:
                CloseServiceHandle(svc)
        finally:
            CloseServiceHandle(scm)

    # ----------------------------------------------------------- query

    def query(self) -> ServiceInfo:
        scm = self._open_scm()
        try:
            try:
                svc = self._open_service(scm)
            except Win32Error as e:
                if e.code == ERROR_SERVICE_DOES_NOT_EXIST:
                    return ServiceInfo(ServiceState.NOT_INSTALLED, 0, self.name, None)
                raise
            try:
                ssp = SERVICE_STATUS_PROCESS()
                needed = wintypes.DWORD()
                ok = QueryServiceStatusEx(
                    svc, SC_STATUS_PROCESS_INFO,
                    ctypes.byref(ssp), ctypes.sizeof(ssp),
                    ctypes.byref(needed),
                )
                if not ok:
                    raise Win32Error("QueryServiceStatusEx")
                try:
                    state = ServiceState(ssp.dwCurrentState)
                except ValueError:
                    state = ServiceState.UNKNOWN
                return ServiceInfo(state, ssp.dwProcessId, self.name, None)
            finally:
                CloseServiceHandle(svc)
        finally:
            CloseServiceHandle(scm)

    # ----------------------------------------------------------- helpers

    def _wait_state(self, target: ServiceState, timeout: float) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            info = self.query()
            if info.state == target:
                return
            if info.state == ServiceState.NOT_INSTALLED:
                raise RuntimeError(f"service '{self.name}' disappeared while waiting for {target.name}")
            time.sleep(0.2)
        info = self.query()
        raise TimeoutError(
            f"service '{self.name}' did not reach {target.name} within {timeout}s "
            f"(current={info.state.name})"
        )
