"""Status page — GET_STATUS + GET_NESTED_STATUS."""

from __future__ import annotations

from PySide6.QtGui import QFont
from PySide6.QtWidgets import QPlainTextEdit, QPushButton

from .base import BasePage
from ..context import AppContext


CPU_VENDOR = {0: "Unknown", 1: "Intel (VMX)", 2: "AMD (SVM)"}


class StatusPage(BasePage):
    title = "状态查询"

    def __init__(self, ctx: AppContext, parent=None):
        super().__init__(ctx, parent)

        # ---- general
        sec = self.add_section("驱动总览 (IOCTL_HV_GET_STATUS)")
        self._txt_status = self._make_text()
        sec.addRow(self._txt_status)
        btn_status = QPushButton("查询总览")
        btn_status.clicked.connect(self._query_status)
        self.add_button_row(btn_status)

        # ---- nested
        sec2 = self.add_section("嵌套虚拟化 (IOCTL_HV_GET_NESTED_STATUS)")
        self._txt_nested = self._make_text()
        sec2.addRow(self._txt_nested)
        btn_nested = QPushButton("查询嵌套状态")
        btn_nested.clicked.connect(self._query_nested)
        self.add_button_row(btn_nested)

        self.add_stretch()

    @staticmethod
    def _make_text() -> QPlainTextEdit:
        e = QPlainTextEdit()
        e.setReadOnly(True)
        f = QFont("Consolas")
        f.setStyleHint(QFont.Monospace)
        e.setFont(f)
        e.setMinimumHeight(160)
        return e

    # ---------------------------------------------------------- handlers

    def _query_status(self):
        if not self.require_device():
            return
        self.run(self.ctx.client.get_status, on_success=self._render_status)

    def _render_status(self, s):
        def mark(b):
            return "✓" if bool(b) else "✗"

        # hook 链路:VT root (HvPhys 物理直通) + 三组 hook 是"启动并保护"全权限的基础。
        # 三组 hook 由 ADD_DEBUGGER 在 0→1 时自动启用,REMOVE_DEBUGGER 在 1→0 时卸载。
        # 任何一项 ✗ 都意味着对应功能链路断了,需要立即排查驱动日志 DbgView。
        lines = [
            "── 基础 ───────────────────────────────",
            f"Version              = 0x{s.Version:08X}",
            f"{mark(s.HypervisorActive)} HypervisorActive",
            f"{mark(s.HookManagerInitialized)} HookManagerInit",
            f"  CpuVendor            = {CPU_VENDOR.get(s.CpuVendor, s.CpuVendor)}",
            f"  ProcessorCount       = {s.ProcessorCount}",
            "",
            "── Hook 链路 (调试器全权限基础) ────────",
            f"{mark(s.VtRootEnabled)} VtRoot               物理 R/W 直通 (HvVtRootCopyByPid)",
            f"{mark(s.DebuggerProxyEnabled)} DebuggerProxy        NtSetContextThread + Nt[R/W]VirtualMemory",
            f"{mark(s.AccessBypassEnabled)} AccessBypass         NtOpenProcess (PPL/System 绕过)",
            f"{mark(s.AntiAntiDebugEnabled)} AntiAntiDebug        反反调试 (NtQuery* 系)",
            "",
            "── 注册表 ──────────────────────────────",
            f"  ProtectedDebuggers   = {s.ProtectedDebuggerCount}",
            f"  ProtectedProcesses   = {s.ProtectedProcessCount}    (已废弃, 仅兼容)",
            f"  HiddenProcessCount   = {s.HiddenProcessCount}",
            f"  HiddenDriverCount    = {s.HiddenDriverCount}",
            "",
            "── 其他 ────────────────────────────────",
            f"{mark(s.DseDisabled)} DseDisabled",
        ]
        self._txt_status.setPlainText("\n".join(lines))

        # 关键链路有一项 ✗ 时在日志高亮提示
        broken = []
        if not s.VtRootEnabled:        broken.append("VtRoot")
        if not s.DebuggerProxyEnabled: broken.append("DebuggerProxy")
        if not s.AccessBypassEnabled:  broken.append("AccessBypass")
        if broken and s.ProtectedDebuggerCount > 0:
            self.ctx.log.warn(
                f"GET_STATUS: 注册了 {s.ProtectedDebuggerCount} 个调试器但 "
                f"{'/'.join(broken)} 未启用 — DbgView 看驱动日志查 hook 安装失败"
            )
        else:
            self.ctx.log.ok(
                f"GET_STATUS: active={bool(s.HypervisorActive)}, cpus={s.ProcessorCount}, "
                f"VtRoot={mark(s.VtRootEnabled)} Proxy={mark(s.DebuggerProxyEnabled)} "
                f"Bypass={mark(s.AccessBypassEnabled)} AAD={mark(s.AntiAntiDebugEnabled)}"
            )

    def _query_nested(self):
        if not self.require_device():
            return
        self.run(self.ctx.client.get_nested_status, on_success=self._render_nested)

    def _render_nested(self, n):
        lines = [
            f"NestedVmxSupported    = {bool(n.NestedVmxSupported)}",
            f"NestedSvmSupported    = {bool(n.NestedSvmSupported)}",
            f"L1VmxEnabled          = {bool(n.L1VmxEnabled)}",
            f"L2Running             = {bool(n.L2Running)}",
            f"ActiveCpuCount        = {n.ActiveCpuCount}",
            f"TotalVmxonCount       = {n.TotalVmxonCount}",
            f"TotalVmlaunchCount    = {n.TotalVmlaunchCount}",
            f"TotalVmresumeCount    = {n.TotalVmresumeCount}",
            f"TotalL2ExitCount      = {n.TotalL2ExitCount}",
            f"TotalErrorCount       = {n.TotalErrorCount}",
            f"CurrentVmcsGpa        = 0x{n.CurrentVmcsGpa:016X}",
            f"VmxonRegionGpa        = 0x{n.VmxonRegionGpa:016X}",
            f"LastGvaToGpaError     = 0x{n.LastGvaToGpaError:016X}",
            f"LastFailedGva         = 0x{n.LastFailedGva:016X}",
            f"LastGuestCr3          = 0x{n.LastGuestCr3:016X}",
            f"LastIrql              = {n.LastIrql}",
            f"LastVmcs12ValidationError = 0x{n.LastVmcs12ValidationError:016X}",
        ]
        self._txt_nested.setPlainText("\n".join(lines))
        self.ctx.log.ok(f"GET_NESTED_STATUS: L1={bool(n.L1VmxEnabled)}, L2={bool(n.L2Running)}")
