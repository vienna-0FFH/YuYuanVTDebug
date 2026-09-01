"""Process hide / unhide page."""

from __future__ import annotations

from PySide6.QtWidgets import QLineEdit, QPushButton

from .base import BasePage
from ..context import AppContext
from ..widgets import PidPicker


class ProcessPage(BasePage):
    title = "进程隐藏 / 取消隐藏"

    def __init__(self, ctx: AppContext, parent=None):
        super().__init__(ctx, parent)

        sec = self.add_section("目标进程（PID 或 名称，至少填一个）")
        self._pid = PidPicker(default_self=False, allow_zero=True,
                              zero_label="（按名称匹配）")
        self._name = QLineEdit()
        self._name.setMaxLength(259)
        self._name.setPlaceholderText("例如 notepad.exe（PID 留空时按名称匹配）")

        sec.addRow("ProcessId:",   self._pid)
        sec.addRow("ProcessName:", self._name)

        btn_h = QPushButton("隐藏")
        btn_u = QPushButton("取消隐藏")
        btn_h.clicked.connect(self._hide)
        btn_u.clicked.connect(self._unhide)
        self.add_button_row(btn_h, btn_u)

        self.add_stretch()

    def _args(self):
        return self._pid.value(), self._name.text()

    def _hide(self):
        if not self.require_device():
            return
        pid, name = self._args()
        self.run(self.ctx.client.hide_process, pid, name,
                 success_msg=f"HIDE_PROCESS sent (pid={pid}, name={name!r})")

    def _unhide(self):
        if not self.require_device():
            return
        pid, name = self._args()
        self.run(self.ctx.client.unhide_process, pid, name,
                 success_msg=f"UNHIDE_PROCESS sent (pid={pid}, name={name!r})")
