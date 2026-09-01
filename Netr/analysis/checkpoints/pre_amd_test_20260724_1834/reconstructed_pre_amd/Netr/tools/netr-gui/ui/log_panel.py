"""Bottom log panel — append-only, monospaced, timestamped.

Thread safety: ``log()`` (and the level helpers ``info/warn/error/ok``) are
safe to call from any thread. They emit a signal that is delivered to the
widget thread via Qt's AutoConnection — DirectConnection when the caller is
already on the GUI thread, QueuedConnection from worker threads. Direct
``QPlainTextEdit`` API calls from worker threads would otherwise abort the
process on Windows.
"""

from __future__ import annotations

import time

from PySide6.QtCore import Qt, Signal, Slot
from PySide6.QtGui import QFont, QTextCursor
from PySide6.QtWidgets import QPlainTextEdit


class LogPanel(QPlainTextEdit):
    """Read-only log widget."""

    _append_requested = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setMaximumBlockCount(2000)              # cap memory
        font = QFont("Consolas")
        font.setStyleHint(QFont.Monospace)
        font.setPointSize(9)
        self.setFont(font)
        self.setPlaceholderText("Log output appears here.")
        # AutoConnection: direct when emitted on GUI thread, queued from workers.
        self._append_requested.connect(self._append_on_ui_thread,
                                       Qt.AutoConnection)

    # ----------------------------------------------------------- public API

    def log(self, line: str, *, level: str = "INFO") -> None:
        ts = time.strftime("%H:%M:%S")
        self._append_requested.emit(f"[{ts}] {level:>5}  {line}")

    def info(self, line: str)  -> None: self.log(line, level="INFO")
    def warn(self, line: str)  -> None: self.log(line, level="WARN")
    def error(self, line: str) -> None: self.log(line, level="ERROR")
    def ok(self, line: str)    -> None: self.log(line, level="OK")

    # ----------------------------------------------------------- internals

    @Slot(str)
    def _append_on_ui_thread(self, formatted: str) -> None:
        self.appendPlainText(formatted)
        self.moveCursor(QTextCursor.End)
