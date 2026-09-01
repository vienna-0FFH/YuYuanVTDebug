"""DSE page — GET / DISABLE / ENABLE DSE."""

from __future__ import annotations

from PySide6.QtWidgets import QLabel, QPushButton

from .base import BasePage
from ..context import AppContext


class DsePage(BasePage):
    title = "DSE — Driver Signature Enforcement"

    def __init__(self, ctx: AppContext, parent=None):
        super().__init__(ctx, parent)

        sec = self.add_section("当前状态 (IOCTL_HV_GET_DSE_STATUS)")
        self._lbl_enabled = QLabel("?")
        self._lbl_value   = QLabel("?")
        self._lbl_addr    = QLabel("?")
        sec.addRow("DseEnabled:",       self._lbl_enabled)
        sec.addRow("CiOptions value:",  self._lbl_value)
        sec.addRow("CiOptions address:", self._lbl_addr)

        btn_q = QPushButton("查询")
        btn_d = QPushButton("禁用 DSE")
        btn_e = QPushButton("启用 DSE")
        btn_q.clicked.connect(self._query)
        btn_d.clicked.connect(self._disable)
        btn_e.clicked.connect(self._enable)
        self.add_button_row(btn_q, btn_d, btn_e)

        self.add_stretch()

    # ---------------------------------------------------------- actions

    def _query(self):
        if not self.require_device():
            return
        self.run(self.ctx.client.get_dse_status, on_success=self._render)

    def _disable(self):
        if not self.require_device():
            return
        self.run(self.ctx.client.disable_dse,
                 success_msg="DSE disabled — code integrity bypassed",
                 on_success=lambda _r: self._query())

    def _enable(self):
        if not self.require_device():
            return
        self.run(self.ctx.client.enable_dse,
                 success_msg="DSE re-enabled",
                 on_success=lambda _r: self._query())

    def _render(self, s):
        self._lbl_enabled.setText(str(bool(s.DseEnabled)))
        self._lbl_value.setText(f"0x{s.CiOptionsValue:08X}")
        self._lbl_addr.setText(f"0x{s.CiOptionsAddress:016X}")
        self.ctx.log.ok(f"GET_DSE_STATUS: enabled={bool(s.DseEnabled)}, "
                        f"value=0x{s.CiOptionsValue:08X}")
