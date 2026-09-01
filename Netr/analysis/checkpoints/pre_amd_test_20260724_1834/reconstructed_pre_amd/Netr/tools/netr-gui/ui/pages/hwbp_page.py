"""VT-transparent hardware breakpoint page — DR0..DR3 + event stream.

阶段 7 HWBP:在 hypervisor 里拦 MOV-DR 和 #DB,target 进程从 ring-3 看自己的
DR 始终是 0,反作弊扫不到。前置:对应 debugger PID 必须先 ADD_DEBUGGER。

UI:
  1) target / debugger PID 设定
  2) 四个 DR 槽 (address + length + type + Set/Clear)
  3) 事件流监听 (后台 QThread 阻塞 wait_event,命中后 continue_event)
"""

from __future__ import annotations

from typing import Optional

from PySide6.QtCore import QObject, QThread, Qt, Signal, Slot
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QComboBox, QLabel, QLineEdit, QListWidget, QPushButton,
)

from netr.structs import (
    HvDebugEvent,
    HV_HWBP_TYPE_EXEC, HV_HWBP_TYPE_WRITE, HV_HWBP_TYPE_IO, HV_HWBP_TYPE_RW,
    HV_HWBP_TYPE_NAMES,
)

from .base import BasePage
from ..context import AppContext
from ..widgets import PidPicker


# 下拉框枚举
_LENGTH_OPTIONS = [("1 byte", 1), ("2 bytes", 2), ("4 bytes", 4), ("8 bytes", 8)]
_TYPE_OPTIONS   = [
    ("EXEC  (执行)",    HV_HWBP_TYPE_EXEC),
    ("WRITE (写入)",    HV_HWBP_TYPE_WRITE),
    ("RW    (读写)",    HV_HWBP_TYPE_RW),
    ("IO    (保留)",    HV_HWBP_TYPE_IO),
]


def _parse_hex(text: str) -> int:
    text = text.strip()
    if not text:
        raise ValueError("address is empty")
    return int(text, 16)


# ======================================================================
# Listener — 后台 QThread 阻塞在 wait_event 上,有事件就 emit 上来
# ======================================================================

class _EventListener(QObject):
    """Runs in its own QThread; signals events back to the UI thread.

    使用 short-timeout polling (200ms) 而不是 INFINITE,这样在 _stop() 被设置后
    最多 200ms 就能退出 —— 比单纯的 QThread.terminate() 干净得多。
    """

    event_received = Signal(object)        # HvDebugEvent
    listener_error = Signal(str)
    listener_done  = Signal()

    def __init__(self, client, debugger_pid: int):
        super().__init__()
        self._client = client
        self._debugger_pid = debugger_pid
        self._stop = False

    def request_stop(self) -> None:
        self._stop = True

    @Slot()
    def run(self) -> None:
        try:
            while not self._stop:
                ev: Optional[HvDebugEvent] = self._client.wait_event(
                    timeout_ms=200,
                    debugger_pid=self._debugger_pid,
                )
                if ev is None:
                    continue        # timeout, loop and re-check stop flag
                # ack the event so the kernel ring slot frees up immediately
                try:
                    self._client.continue_event(int(ev.Sequence),
                                                debugger_pid=self._debugger_pid)
                except Exception as e:                  # noqa: BLE001
                    self.listener_error.emit(f"continue_event failed: {e}")
                self.event_received.emit(ev)
        except Exception as e:                          # noqa: BLE001
            self.listener_error.emit(f"{type(e).__name__}: {e}")
        finally:
            self.listener_done.emit()


# ======================================================================
# Page
# ======================================================================

class HwBpPage(BasePage):
    title = "VT 透明硬件断点 (HWBP)"

    def __init__(self, ctx: AppContext, parent=None):
        super().__init__(ctx, parent)

        # ---------------------------------------------------------- target
        sec_t = self.add_section("目标 / 调试器")
        self._target_pid = PidPicker()
        self._target_pid.setToolTip("被监控的进程 PID。它对 DR 寄存器的读写会被 hypervisor 拦下。")

        self._debugger_pid = PidPicker()
        self._debugger_pid.setToolTip(
            "执行 IOCTL 的进程 PID,默认 = 本 GUI 自己 (os.getpid())。"
            "该 PID 必须先通过 IOCTL_HV_ADD_DEBUGGER 注册,否则 driver 拒掉。"
        )

        sec_t.addRow("Target PID (被监控):", self._target_pid)
        sec_t.addRow("Debugger PID (caller):", self._debugger_pid)

        info_t = QLabel(
            "前置:debugger PID 必须先 ADD_DEBUGGER。Target 看到的 DR0..DR3+DR7\n"
            "永远是 0 —— MOV-DR 被 hypervisor 拦截走影子寄存器,target 无感。\n"
            "x86 硬件约束:EXEC 类型 length 必须 = 1。"
        )
        info_t.setWordWrap(True)
        sec_t.addRow(info_t)

        # ---------------------------------------------------------- 4 slots
        self._slots: list[dict] = []
        for slot_idx in range(4):
            sec = self.add_section(f"DR{slot_idx}")
            addr = QLineEdit()
            addr.setPlaceholderText("0x7FF6_xxxx_xxxx")

            length = QComboBox()
            for label, _ in _LENGTH_OPTIONS:
                length.addItem(label)

            bp_type = QComboBox()
            for label, _ in _TYPE_OPTIONS:
                bp_type.addItem(label)

            sec.addRow("Address (hex):", addr)
            sec.addRow("Length:",        length)
            sec.addRow("Type:",          bp_type)

            btn_set = QPushButton(f"Set DR{slot_idx}")
            btn_clr = QPushButton(f"Clear DR{slot_idx}")
            # 用默认参数绑死 slot_idx,避免 lambda late-binding 陷阱
            btn_set.clicked.connect(lambda _=False, s=slot_idx: self._set_slot(s))
            btn_clr.clicked.connect(lambda _=False, s=slot_idx: self._clear_slot(s))
            self.add_button_row(btn_set, btn_clr)

            self._slots.append({
                "addr": addr,
                "length": length,
                "type": bp_type,
            })

        # ---------------------------------------------------------- events
        sec_e = self.add_section("事件流 (#DB 命中)")
        self._btn_listen_start = QPushButton("开始监听")
        self._btn_listen_stop  = QPushButton("停止监听")
        self._btn_listen_stop.setEnabled(False)
        self._btn_listen_start.clicked.connect(self._start_listener)
        self._btn_listen_stop.clicked.connect(self._stop_listener)
        btn_clear_view = QPushButton("清空事件")
        btn_clear_view.clicked.connect(lambda: self._events.clear())
        self.add_button_row(self._btn_listen_start, self._btn_listen_stop,
                            btn_clear_view)

        self._events = QListWidget()
        self._events.setFont(QFont("Consolas", 9))
        self._events.setMinimumHeight(160)
        self._body.addWidget(self._events, 1)

        # 监听器状态
        self._listener_thread: Optional[QThread] = None
        self._listener: Optional[_EventListener] = None

        self.add_stretch()

    # ============================================================== slots

    def _set_slot(self, slot: int) -> None:
        if not self.require_device():
            return
        widgets = self._slots[slot]
        try:
            addr = _parse_hex(widgets["addr"].text())
        except ValueError as e:
            self.ctx.log.warn(f"DR{slot} address: {e}")
            return
        length  = _LENGTH_OPTIONS[widgets["length"].currentIndex()][1]
        bp_type = _TYPE_OPTIONS  [widgets["type"  ].currentIndex()][1]

        if bp_type == HV_HWBP_TYPE_EXEC and length != 1:
            self.ctx.log.warn(f"DR{slot}: EXEC 类型必须 length=1 (x86 硬件约束)")
            return

        target = self._target_pid.value()
        dbg    = self._debugger_pid.value()
        type_name = HV_HWBP_TYPE_NAMES.get(bp_type, str(bp_type))

        self.run(self.ctx.client.set_hwbp,
                 target, slot, addr, length, bp_type, dbg,
                 success_msg=(f"SET_HWBP DR{slot} ok "
                              f"(pid={target} @ 0x{addr:X}, len={length}, type={type_name})"))

    def _clear_slot(self, slot: int) -> None:
        if not self.require_device():
            return
        target = self._target_pid.value()
        dbg    = self._debugger_pid.value()
        self.run(self.ctx.client.clear_hwbp,
                 target, slot, dbg,
                 success_msg=f"CLEAR_HWBP DR{slot} ok (pid={target})")

    # ============================================================== listener

    def _start_listener(self) -> None:
        if not self.require_device():
            return
        if self._listener_thread is not None:
            self.ctx.log.warn("监听器已经在运行")
            return

        dbg = self._debugger_pid.value()

        # 起一个 QThread + 一个 QObject worker。worker 在 thread 上跑 run()。
        thread = QThread(self)
        listener = _EventListener(self.ctx.client, dbg)
        listener.moveToThread(thread)

        thread.started.connect(listener.run)
        listener.event_received.connect(self._on_event, Qt.QueuedConnection)
        listener.listener_error.connect(self._on_listener_error, Qt.QueuedConnection)
        listener.listener_done.connect(thread.quit, Qt.QueuedConnection)
        thread.finished.connect(listener.deleteLater)
        thread.finished.connect(thread.deleteLater)
        thread.finished.connect(self._on_listener_finished)

        self._listener_thread = thread
        self._listener = listener
        self._btn_listen_start.setEnabled(False)
        self._btn_listen_stop.setEnabled(True)

        thread.start()
        self.ctx.log.ok(f"事件监听启动 (debugger_pid={dbg})")

    def _stop_listener(self) -> None:
        if self._listener is not None:
            self._listener.request_stop()
            self.ctx.log.info("已请求停止监听(最多 200ms 后真正退出)")
        self._btn_listen_stop.setEnabled(False)

    @Slot(object)
    def _on_event(self, ev: HvDebugEvent) -> None:
        # 一行摘要 + RIP/Tid/Hit slot
        line = (f"seq={ev.Sequence}  tid={ev.Tid}  pid={ev.Pid}  "
                f"DR6=0x{ev.Dr6:X}  hit=DR{ev.HitSlot}  "
                f"rip=0x{ev.Rip:016X}  rsp=0x{ev.Rsp:016X}  "
                f"rflags=0x{ev.Rflags:X}")
        self._events.addItem(line)
        self._events.scrollToBottom()

    @Slot(str)
    def _on_listener_error(self, msg: str) -> None:
        self.ctx.log.error(f"listener: {msg}")

    @Slot()
    def _on_listener_finished(self) -> None:
        self._listener_thread = None
        self._listener = None
        self._btn_listen_start.setEnabled(True)
        self._btn_listen_stop.setEnabled(False)
        self.ctx.log.info("事件监听已停止")
