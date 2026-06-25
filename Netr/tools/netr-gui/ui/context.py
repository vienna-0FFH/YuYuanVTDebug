"""Shared application context — single source of truth for driver state.

Every page receives an ``AppContext`` reference. Pages do not own the device
handle or the service object directly; they go through the context so that
opening/closing happens in one place and the main window can drive enable
state for the whole tree from a single notify().
"""

from __future__ import annotations

from typing import Optional

from PySide6.QtCore import QObject, QTimer, Signal

from netr.client import NetrClient
from netr.ioctl import NetrDevice
from netr.service import NetrService, ServiceInfo, ServiceState
from netr.structs import (
    HV_DBGEVT_SEV_INFO, HV_DBGEVT_SEV_WARN, HV_DBGEVT_SEV_ERROR,
)
from netr.winapi import Win32Error

from .log_panel import LogPanel


# Phase G: 根因事件轮询间隔。1s 是 spec 决议的折衷 —— 人眼反应足够快,
# IOCTL 开销 <50us, 一天累计 < 0.4 秒主线程占用。
DBGEVT_POLL_INTERVAL_MS = 1000

# 单次拉取上限。256 是 ring 容量;通常一秒内事件远少于此,够用且不会让
# 偶发风暴(例如 CE 一次扫 100 个进程触发 100 个 OpenProcess 事件)丢数据。
DBGEVT_PULL_MAX = 256


class AppContext(QObject):
    """Holds the driver service + open device handle for the whole app."""

    # Emitted whenever service state OR device-open state changes.
    state_changed = Signal()

    def __init__(self, log: LogPanel, service_name: str = "Netr"):
        super().__init__()
        self.log      = log
        self.service  = NetrService(service_name)
        self.client:  Optional[NetrClient]  = None
        self._last_info: Optional[ServiceInfo] = None

        # Phase G: 根因事件轮询状态
        self._dbgevt_last_seq: int = 0
        self._dbgevt_timer = QTimer(self)
        self._dbgevt_timer.setInterval(DBGEVT_POLL_INTERVAL_MS)
        self._dbgevt_timer.timeout.connect(self._poll_dbgevt)
        # 启停由 open_device / close_device 控制
        self._dbgevt_consec_errors: int = 0   # 连错降级,避免日志刷屏

    # ---------------------------------------------------------- device

    def device_open(self) -> bool:
        return self.client is not None and self.client.device.is_open()

    def open_device(self) -> None:
        if self.device_open():
            return
        try:
            dev = NetrDevice()
            self.client = NetrClient(dev)
            self.log.ok(f"Opened device {dev.path}")
        except Win32Error as e:
            self.log.error(f"Open device failed: {e}")
            raise
        # 设备打开后从最新事件开始拉(避免一开 GUI 就被驱动里历史事件淹没)。
        # 用 0 拉一次拿到 NextSequence,再把 last_seq 设到那里 —— 之后只看新事件。
        try:
            _, next_seq = self.client.dbgevt_pull(since_sequence=0,
                                                  max_count=DBGEVT_PULL_MAX)
            self._dbgevt_last_seq = next_seq
        except Exception:                            # noqa: BLE001
            self._dbgevt_last_seq = 0
        self._dbgevt_consec_errors = 0
        self._dbgevt_timer.start()
        self.state_changed.emit()

    def close_device(self) -> None:
        self._dbgevt_timer.stop()
        if self.client is not None:
            try:
                self.client.close()
            except Exception:                        # noqa: BLE001
                pass
            self.client = None
            self.log.info("Closed device handle")
        self.state_changed.emit()

    # ---------------------------------------------------------- Phase G: dbgevt

    def _poll_dbgevt(self) -> None:
        """1Hz tick: 从驱动 ring 拉新事件,格式化到 LogPanel。"""
        if not self.device_open():
            return
        try:
            events, next_seq = self.client.dbgevt_pull(
                since_sequence=self._dbgevt_last_seq,
                max_count=DBGEVT_PULL_MAX)
        except Exception as e:                       # noqa: BLE001
            self._dbgevt_consec_errors += 1
            if self._dbgevt_consec_errors <= 2:
                self.log.warn(f"dbgevt poll failed: {e}")
            elif self._dbgevt_consec_errors == 3:
                self.log.warn("dbgevt poll failed 3 times, suppressing further errors")
            return

        self._dbgevt_consec_errors = 0
        if events:
            for ev in events:
                self._emit_event(ev)
        # 即使没事件也要推进 last_seq,避免下次重复拉 NextSequence 同段
        self._dbgevt_last_seq = next_seq

    @staticmethod
    def _format_event(ev) -> str:
        cat = ev.category_name
        detail = ev.detail_str
        # status: 0 = info-only,其余按 NTSTATUS 16 进制
        status_part = "" if ev.Status == 0 else f" status=0x{ev.Status & 0xFFFFFFFF:08X}"
        # caller/target: 仅在非 0 时显示
        ct_parts = []
        if ev.CallerPid:
            ct_parts.append(f"caller={ev.CallerPid}")
        if ev.TargetPid:
            ct_parts.append(f"target={ev.TargetPid}")
        if ev.Addr:
            ct_parts.append(f"addr=0x{ev.Addr:016X}")
        if ev.Size:
            ct_parts.append(f"size={ev.Size}")
        ct = (" " + " ".join(ct_parts)) if ct_parts else ""
        return f"[{cat}]{ct}{status_part}  {detail}"

    def _emit_event(self, ev) -> None:
        line = self._format_event(ev)
        if ev.Severity == HV_DBGEVT_SEV_ERROR:
            self.log.error(line)
        elif ev.Severity == HV_DBGEVT_SEV_WARN:
            self.log.warn(line)
        else:
            self.log.info(line)

    # ---------------------------------------------------------- service

    def refresh_service(self) -> ServiceInfo:
        info = self.service.query()
        self._last_info = info
        self.state_changed.emit()
        return info

    @property
    def last_service_info(self) -> Optional[ServiceInfo]:
        return self._last_info

    @property
    def service_running(self) -> bool:
        return (self._last_info is not None
                and self._last_info.state == ServiceState.RUNNING)
