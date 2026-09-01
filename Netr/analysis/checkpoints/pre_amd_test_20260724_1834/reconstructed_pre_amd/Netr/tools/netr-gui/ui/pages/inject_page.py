"""Process injection page — INJECT_DLL / INJECT_SHELLCODE."""

from __future__ import annotations

from PySide6.QtWidgets import (
    QCheckBox, QFileDialog, QLineEdit, QPlainTextEdit, QPushButton, QSpinBox,
)

from .base import BasePage
from ..context import AppContext
from ..widgets import PidPicker


def _parse_hex_bytes(text: str) -> bytes:
    cleaned = "".join(ch for ch in text if ch.isalnum())
    if len(cleaned) % 2 != 0:
        raise ValueError("hex string must have an even number of nibbles")
    return bytes.fromhex(cleaned)


class InjectPage(BasePage):
    title = "进程注入 — DLL / Shellcode"

    def __init__(self, ctx: AppContext, parent=None):
        super().__init__(ctx, parent)

        # ----------------------------------------------------------- DLL
        sec_d = self.add_section("DLL 注入 (INJECT_DLL)")
        self._d_pid  = PidPicker(default_self=False)
        self._d_path = QLineEdit(); self._d_path.setMaxLength(519)
        self._d_path.setPlaceholderText(r"C:\path\to\payload.dll")
        btn_browse = QPushButton("浏览…")
        btn_browse.clicked.connect(self._browse_dll)
        sec_d.addRow("TargetPid:", self._d_pid)
        sec_d.addRow("DllPath:",   self._d_path)
        sec_d.addRow("",           btn_browse)

        self._d_hide_peb   = QCheckBox("HideFromPeb (从 PEB Ldr 列表摘除)")
        self._d_erase_hdr  = QCheckBox("ErasePeHeader (注入后抹除 PE 头)")
        self._d_manual_map = QCheckBox("UseManualMap (手动映射，不走 LoadLibrary)")
        self._d_stealth    = QSpinBox(); self._d_stealth.setRange(0, 3)
        sec_d.addRow(self._d_hide_peb)
        sec_d.addRow(self._d_erase_hdr)
        sec_d.addRow(self._d_manual_map)
        sec_d.addRow("StealthLevel (0..3):", self._d_stealth)

        btn_inject_dll = QPushButton("注入 DLL")
        btn_inject_dll.clicked.connect(self._do_inject_dll)
        self.add_button_row(btn_inject_dll)

        # ----------------------------------------------------------- Shellcode
        sec_s = self.add_section("Shellcode 注入 (INJECT_SHELLCODE)")
        self._s_pid   = PidPicker(default_self=False)
        self._s_param = QLineEdit(); self._s_param.setPlaceholderText("0 (传给 shellcode 的 RCX，hex)")
        self._s_param.setText("0")
        sec_s.addRow("TargetPid:",   self._s_pid)
        sec_s.addRow("Parameter:",   self._s_param)

        self._s_exec = QCheckBox("ExecuteImmediately (立即创建远程线程)")
        self._s_hide = QCheckBox("HideMemory (从 VAD 摘除分配)")
        self._s_exec.setChecked(True)
        sec_s.addRow(self._s_exec)
        sec_s.addRow(self._s_hide)

        self._s_data = QPlainTextEdit()
        self._s_data.setPlaceholderText(
            "粘贴 shellcode 的 hex (1..4096 字节), 例如:\n"
            "48 31 C0 48 89 C1 48 89 C2 ..."
        )
        self._s_data.setMinimumHeight(120)
        self._body.addWidget(self._s_data, 1)

        btn_inject_sc = QPushButton("注入 Shellcode")
        btn_inject_sc.clicked.connect(self._do_inject_shellcode)
        self.add_button_row(btn_inject_sc)

        self.add_stretch()

    # ----------------------------------------------------------- handlers
    def _browse_dll(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "选择要注入的 DLL", "", "DLL 文件 (*.dll);;所有文件 (*)"
        )
        if path:
            self._d_path.setText(path)

    def _do_inject_dll(self):
        if not self.require_device():
            return
        pid  = self._d_pid.value()
        path = self._d_path.text().strip()
        if not path:
            self.ctx.log.warn("DllPath is required.")
            return

        def on_ok(res):
            self.ctx.log.ok(
                f"INJECT_DLL ok: pid={pid}, ModuleBase=0x{res.ModuleBase:X}, "
                f"ModuleSize=0x{res.ModuleSize:X}"
            )

        self.run(self.ctx.client.inject_dll, pid, path,
                 self._d_hide_peb.isChecked(),
                 self._d_erase_hdr.isChecked(),
                 self._d_manual_map.isChecked(),
                 self._d_stealth.value(),
                 on_success=on_ok)

    def _do_inject_shellcode(self):
        if not self.require_device():
            return
        try:
            data = _parse_hex_bytes(self._s_data.toPlainText())
        except ValueError as e:
            self.ctx.log.warn(f"Shellcode: {e}")
            return
        if not data:
            self.ctx.log.warn("Shellcode is empty.")
            return
        if len(data) > 4096:
            self.ctx.log.warn(f"Shellcode too large ({len(data)}B); max is 4096.")
            return
        try:
            param_txt = self._s_param.text().strip() or "0"
            param = int(param_txt, 16) if param_txt.lower().startswith("0x") else int(param_txt, 16)
        except ValueError:
            self.ctx.log.warn("Parameter must be a hex integer.")
            return

        pid = self._s_pid.value()

        def on_ok(res):
            self.ctx.log.ok(
                f"INJECT_SHELLCODE ok: pid={pid}, "
                f"ShellcodeAddress=0x{res.ShellcodeAddress:X} ({len(data)}B)"
            )

        self.run(self.ctx.client.inject_shellcode, pid, data, param,
                 self._s_exec.isChecked(),
                 self._s_hide.isChecked(),
                 on_success=on_ok)
