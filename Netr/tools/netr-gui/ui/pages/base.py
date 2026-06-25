"""Page base class and helpers."""

from __future__ import annotations

from typing import Any, Callable

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFormLayout, QGroupBox, QHBoxLayout, QLabel, QPushButton,
    QVBoxLayout, QWidget,
)

from ..async_worker import run_async
from ..context import AppContext


class BasePage(QWidget):
    """Common page chrome: title, vertical layout, async helper."""

    title: str = "Untitled"

    def __init__(self, ctx: AppContext, parent=None):
        super().__init__(parent)
        self.ctx = ctx
        self._outer = QVBoxLayout(self)
        self._outer.setContentsMargins(16, 16, 16, 16)

        self._title_lbl = QLabel(f"<h2>{self.title}</h2>")
        self._outer.addWidget(self._title_lbl)

        self._body = QVBoxLayout()
        self._outer.addLayout(self._body, 1)

    # ---------------------------------------------------------- helpers

    def add_section(self, name: str) -> QFormLayout:
        box = QGroupBox(name)
        form = QFormLayout(box)
        form.setLabelAlignment(Qt.AlignRight)
        self._body.addWidget(box)
        return form

    def add_button_row(self, *buttons: QPushButton) -> QHBoxLayout:
        row = QHBoxLayout()
        for b in buttons:
            row.addWidget(b)
        row.addStretch(1)
        self._body.addLayout(row)
        return row

    def add_stretch(self) -> None:
        self._body.addStretch(1)

    # ---------------------------------------------------------- async wrapper

    def run(self, func: Callable[..., Any], *args,
            success_msg: str | None = None,
            on_success: Callable[[Any], None] | None = None,
            **kwargs) -> None:
        """Run *func* off the UI thread; log result/error automatically."""
        def _ok(result):
            if success_msg is not None:
                self.ctx.log.ok(success_msg)
            if on_success is not None:
                on_success(result)

        def _err(msg):
            self.ctx.log.error(msg)

        run_async(self, func, *args, on_success=_ok, on_error=_err, **kwargs)

    # ---------------------------------------------------------- guards

    def require_device(self) -> bool:
        if not self.ctx.device_open():
            self.ctx.log.warn("Device not open — please load the driver first.")
            return False
        return True
