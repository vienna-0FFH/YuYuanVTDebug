"""Service page — install / start / stop / uninstall the kernel driver."""

from __future__ import annotations

import os

from PySide6.QtWidgets import (
    QFileDialog, QHBoxLayout, QLabel, QLineEdit, QPushButton,
)

from netr.privilege import enable_privilege

from .base import BasePage
from ..context import AppContext


class ServicePage(BasePage):
    title = "驱动管理 — 服务加载 / 卸载"

    def __init__(self, ctx: AppContext, parent=None):
        super().__init__(ctx, parent)

        # -------- .sys path row
        form = self.add_section("驱动文件")
        self._path_edit = QLineEdit()
        self._path_edit.setPlaceholderText(r"C:\path\to\Netr.sys")
        self._path_edit.setText(self._guess_default_sys())

        browse = QPushButton("浏览…")
        browse.clicked.connect(self._browse)

        row = QHBoxLayout()
        row.addWidget(self._path_edit, 1)
        row.addWidget(browse)
        form.addRow("Netr.sys:", row)

        # -------- action buttons
        self._btn_install   = QPushButton("安装服务")
        self._btn_start     = QPushButton("启动驱动")
        self._btn_stop      = QPushButton("停止驱动")
        self._btn_uninstall = QPushButton("卸载服务")
        self._btn_open_dev  = QPushButton("打开设备")
        self._btn_close_dev = QPushButton("关闭设备")
        self._btn_refresh   = QPushButton("刷新状态")

        self._btn_install.clicked.connect(self._install)
        self._btn_start.clicked.connect(self._start)
        self._btn_stop.clicked.connect(self._stop)
        self._btn_uninstall.clicked.connect(self._uninstall)
        self._btn_open_dev.clicked.connect(self._open_dev)
        self._btn_close_dev.clicked.connect(self._close_dev)
        self._btn_refresh.clicked.connect(self._refresh)

        self.add_button_row(self._btn_install, self._btn_start,
                            self._btn_stop, self._btn_uninstall)
        self.add_button_row(self._btn_open_dev, self._btn_close_dev,
                            self._btn_refresh)

        # -------- live state labels
        sec = self.add_section("当前状态")
        self._lbl_state = QLabel("?")
        self._lbl_dev   = QLabel("?")
        sec.addRow("服务状态:", self._lbl_state)
        sec.addRow("设备句柄:", self._lbl_dev)

        self.add_stretch()

        self.ctx.state_changed.connect(self._refresh_labels)
        self._refresh_labels()

    # -------------------------------------------------------- helpers

    @staticmethod
    def _guess_default_sys() -> str:
        # Best-effort guess: ../../x64/Release/Netr.sys relative to GUI root
        here = os.path.dirname(os.path.abspath(__file__))
        guess = os.path.normpath(
            os.path.join(here, "..", "..", "..", "..", "x64", "Release", "Netr.sys")
        )
        return guess if os.path.isfile(guess) else ""

    def _browse(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "选择 Netr.sys",
            os.path.dirname(self._path_edit.text() or "C:\\"),
            "Driver files (*.sys);;All files (*.*)",
        )
        if path:
            self._path_edit.setText(path)

    def _refresh_labels(self) -> None:
        info = self.ctx.last_service_info
        self._lbl_state.setText(info.state.name if info else "?")
        self._lbl_dev.setText("OPEN" if self.ctx.device_open() else "CLOSED")

    # -------------------------------------------------------- actions

    def _install(self) -> None:
        path = self._path_edit.text().strip()
        self.ctx.log.info(f"[安装服务] 点击 — path={path!r}")
        if not path:
            self.ctx.log.warn("请先选择 Netr.sys 文件路径。")
            return
        if not os.path.isfile(path):
            self.ctx.log.error(f"文件不存在: {path}")
            return
        try:
            enable_privilege()                       # SeLoadDriverPrivilege
            self.ctx.log.info("SeLoadDriverPrivilege 已启用。")
        except Exception as e:
            self.ctx.log.error(f"enable_privilege 失败: {e}")
            return

        def _do():
            self.ctx.service.install(path)
            return self.ctx.service.query()

        self.run(_do, success_msg=f"服务已安装: {path}",
                 on_success=lambda info: self._after_query(info))

    def _start(self) -> None:
        self.ctx.log.info("[启动驱动] 点击")
        try:
            enable_privilege()
        except Exception as e:
            self.ctx.log.error(f"enable_privilege 失败: {e}")
            return

        def _do():
            self.ctx.service.start()
            info = self.ctx.service.query()
            # Automatically open the device once the service is RUNNING.
            try:
                self.ctx.open_device()
            except Exception as e:
                return ("running-but-device-failed", info, str(e))
            return ("running", info, None)

        def _on(result):
            tag, info, err = result
            self.ctx._last_info = info               # noqa: SLF001
            self.ctx.state_changed.emit()
            if tag == "running":
                self.ctx.log.ok("服务已启动 + 设备已打开。")
            else:
                self.ctx.log.warn(f"服务已启动，但打开设备失败: {err}")

        self.run(_do, on_success=_on)

    def _stop(self) -> None:
        self.ctx.log.info("[停止驱动] 点击")
        self.ctx.close_device()                      # release handle first

        def _do():
            self.ctx.service.stop()
            return self.ctx.service.query()

        self.run(_do, success_msg="服务已停止。",
                 on_success=self._after_query)

    def _uninstall(self) -> None:
        self.ctx.log.info("[卸载服务] 点击")
        self.ctx.close_device()

        def _do():
            self.ctx.service.uninstall()
            return self.ctx.service.query()

        self.run(_do, success_msg="服务已删除。",
                 on_success=self._after_query)

    def _open_dev(self) -> None:
        try:
            self.ctx.open_device()
        except Exception as e:
            self.ctx.log.error(f"open_device: {e}")

    def _close_dev(self) -> None:
        self.ctx.close_device()

    def _refresh(self) -> None:
        def _do():
            return self.ctx.service.query()

        self.run(_do, on_success=self._after_query)

    def _after_query(self, info) -> None:
        self.ctx._last_info = info                   # noqa: SLF001
        self.ctx.state_changed.emit()
