"""Process protection page — PROTECT / UNPROTECT_PROCESS.

DEPRECATED (2026-06-03)
========================
调试器对被保护进程的全权限访问已自动整合到 ADD_DEBUGGER 路径:
HvHookAddDebugger 在 0→1 时会一并启用 NtOpenProcess bypass 和
Nt[R/W]VirtualMemory 重定向,caller 是注册的 debugger 即对任意
user/PPL/System(只读) target 放行,无需 PROTECT_PROCESS 配对。

本页面已从 main_window.py 的页面树中移除,IOCTL 在驱动侧仍保留
作兼容性,但 hook 路径不再读 PROTECTED 列表。文件留作历史回退,
请勿重新挂回页面树。
"""

from __future__ import annotations

from PySide6.QtWidgets import QLineEdit, QPushButton

from .base import BasePage
from ..context import AppContext
from ..widgets import PidPicker


class ProtectPage(BasePage):
    title = "进程保护"

    def __init__(self, ctx: AppContext, parent=None):
        super().__init__(ctx, parent)

        sec = self.add_section("受保护进程")
        self._pid  = PidPicker(default_self=False, allow_zero=True,
                               zero_label="（按名称匹配）")
        self._name = QLineEdit()
        self._name.setMaxLength(259)
        self._name.setPlaceholderText("例如 game.exe（PID 留空时按名称匹配）")
        self._dbg  = PidPicker(default_self=False, allow_zero=True,
                               zero_label="（无白名单调试器）")
        sec.addRow("ProcessId:",     self._pid)
        sec.addRow("ProcessName:",   self._name)
        sec.addRow("DebuggerPid (白名单):", self._dbg)

        btn_add = QPushButton("启用保护")
        btn_rem = QPushButton("解除保护")
        btn_add.clicked.connect(self._protect)
        btn_rem.clicked.connect(self._unprotect)
        self.add_button_row(btn_add, btn_rem)

        self.add_stretch()

    def _protect(self):
        if not self.require_device():
            return
        self.run(self.ctx.client.protect_process,
                 self._pid.value(), self._name.text(), self._dbg.value(),
                 success_msg=f"PROTECT_PROCESS sent (pid={self._pid.value()})")

    def _unprotect(self):
        if not self.require_device():
            return
        self.run(self.ctx.client.unprotect_process,
                 self._pid.value(), self._name.text(),
                 success_msg=f"UNPROTECT_PROCESS sent (pid={self._pid.value()})")
