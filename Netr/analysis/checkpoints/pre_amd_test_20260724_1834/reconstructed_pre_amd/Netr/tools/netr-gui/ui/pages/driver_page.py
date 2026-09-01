"""Driver hide / unhide page."""

from __future__ import annotations

from PySide6.QtWidgets import QLineEdit, QPushButton

from .base import BasePage
from ..context import AppContext


class DriverPage(BasePage):
    title = "驱动隐藏 / 取消隐藏"

    def __init__(self, ctx: AppContext, parent=None):
        super().__init__(ctx, parent)

        sec = self.add_section("驱动名（不含 .sys 后缀）")
        self._name = QLineEdit()
        self._name.setMaxLength(259)
        self._name.setPlaceholderText("例如 Netr 或 mydriver")
        sec.addRow("DriverName:", self._name)

        btn_h = QPushButton("隐藏驱动")
        btn_u = QPushButton("取消隐藏")
        btn_h.clicked.connect(self._hide)
        btn_u.clicked.connect(self._unhide)
        self.add_button_row(btn_h, btn_u)

        self.add_stretch()

    def _hide(self):
        if not self.require_device():
            return
        name = self._name.text().strip()
        if not name:
            self.ctx.log.warn("Driver name is required.")
            return
        self.run(self.ctx.client.hide_driver, name,
                 success_msg=f"HIDE_DRIVER sent ({name!r})")

    def _unhide(self):
        if not self.require_device():
            return
        name = self._name.text().strip()
        if not name:
            self.ctx.log.warn("Driver name is required.")
            return
        self.run(self.ctx.client.unhide_driver, name,
                 success_msg=f"UNHIDE_DRIVER sent ({name!r})")
