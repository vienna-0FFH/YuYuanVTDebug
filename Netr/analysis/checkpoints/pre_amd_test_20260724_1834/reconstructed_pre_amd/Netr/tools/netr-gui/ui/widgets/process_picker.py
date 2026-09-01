"""Process picker — modal dialog (searchable table) + inline PidPicker widget.

ProcessPickerDialog
    打开后枚举所有进程 (Toolhelp snapshot),用户可以按 PID/Name 搜索,
    双击或选中后回车确认。默认隐藏 PID 0/4 + System/Registry/Memory
    Compression 等系统进程;勾上 [显示系统进程] 才会列出来。

PidPicker
    页面内嵌的小部件:只读 QLineEdit (显示 "1234 (notepad.exe)") + "选择…" 按钮。
    支持 set_pid()/pid/name 编程接口,以及 changed(pid, name) 信号。
    某些场景允许 pid=0 表示"全局"(如 AAD TargetPid),通过 allow_zero=True 启用。
"""

from __future__ import annotations

import os
from typing import Optional

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView, QCheckBox, QDialog, QDialogButtonBox, QHBoxLayout,
    QHeaderView, QLabel, QLineEdit, QPushButton, QTableWidget,
    QTableWidgetItem, QVBoxLayout, QWidget,
)

from netr.processes import ProcessInfo, is_system_process, list_processes


# ====================================================================== dialog

class ProcessPickerDialog(QDialog):
    """Modal picker. Use ``pick(parent, ...)`` to invoke."""

    COL_PID, COL_NAME, COL_THREADS = 0, 1, 2

    def __init__(self,
                 parent: Optional[QWidget] = None,
                 *,
                 title: str = "选择进程",
                 show_system_default: bool = False,
                 allow_zero: bool = False):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(560, 480)

        self._allow_zero = allow_zero
        self._chosen: Optional[ProcessInfo] = None
        self._all: list[ProcessInfo] = []

        root = QVBoxLayout(self)

        # ---- toolbar
        bar = QHBoxLayout()
        bar.addWidget(QLabel("搜索:"))
        self._search = QLineEdit()
        self._search.setPlaceholderText("按 PID 或 进程名 过滤")
        self._search.textChanged.connect(self._apply_filter)
        bar.addWidget(self._search, 1)

        self._show_system = QCheckBox("显示系统进程")
        self._show_system.setChecked(show_system_default)
        self._show_system.toggled.connect(self._apply_filter)
        bar.addWidget(self._show_system)

        btn_refresh = QPushButton("刷新")
        btn_refresh.clicked.connect(self._reload)
        bar.addWidget(btn_refresh)
        root.addLayout(bar)

        # ---- table
        self._tbl = QTableWidget(0, 3)
        self._tbl.setHorizontalHeaderLabels(["PID", "进程名", "线程"])
        self._tbl.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._tbl.setSelectionMode(QAbstractItemView.SingleSelection)
        self._tbl.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._tbl.setSortingEnabled(True)
        self._tbl.verticalHeader().setVisible(False)
        hh = self._tbl.horizontalHeader()
        hh.setSectionResizeMode(self.COL_PID,     QHeaderView.ResizeToContents)
        hh.setSectionResizeMode(self.COL_NAME,    QHeaderView.Stretch)
        hh.setSectionResizeMode(self.COL_THREADS, QHeaderView.ResizeToContents)
        self._tbl.itemDoubleClicked.connect(lambda *_: self.accept())
        root.addWidget(self._tbl, 1)

        # ---- buttons
        btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        root.addWidget(btns)
        self._ok_btn = btns.button(QDialogButtonBox.Ok)
        self._ok_btn.setEnabled(False)
        self._tbl.itemSelectionChanged.connect(self._update_ok_state)

        self._reload()

    # ---------------------------------------------------------------- internals

    def _reload(self) -> None:
        self._all = list_processes()
        self._all.sort(key=lambda p: p.pid)
        self._apply_filter()

    def _apply_filter(self) -> None:
        needle = self._search.text().strip().lower()
        show_sys = self._show_system.isChecked()

        self._tbl.setSortingEnabled(False)        # 避免 setItem 触发重排
        self._tbl.setRowCount(0)
        for p in self._all:
            if not show_sys and is_system_process(p):
                continue
            if needle:
                if needle not in str(p.pid) and needle not in p.name.lower():
                    continue
            row = self._tbl.rowCount()
            self._tbl.insertRow(row)

            it_pid = QTableWidgetItem()
            it_pid.setData(Qt.DisplayRole, int(p.pid))         # 数字排序而不是字典序
            it_pid.setData(Qt.UserRole,   p)
            it_pid.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)

            it_name = QTableWidgetItem(p.name)

            it_th = QTableWidgetItem()
            it_th.setData(Qt.DisplayRole, int(p.threads))
            it_th.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)

            self._tbl.setItem(row, self.COL_PID,     it_pid)
            self._tbl.setItem(row, self.COL_NAME,    it_name)
            self._tbl.setItem(row, self.COL_THREADS, it_th)

        self._tbl.setSortingEnabled(True)
        self._update_ok_state()

    def _update_ok_state(self) -> None:
        self._ok_btn.setEnabled(self._tbl.currentRow() >= 0)

    def selected(self) -> Optional[ProcessInfo]:
        row = self._tbl.currentRow()
        if row < 0:
            return None
        item = self._tbl.item(row, self.COL_PID)
        if item is None:
            return None
        info = item.data(Qt.UserRole)
        return info if isinstance(info, ProcessInfo) else None

    # ---------------------------------------------------------------- public API

    @classmethod
    def pick(cls,
             parent: Optional[QWidget] = None,
             *,
             title: str = "选择进程",
             show_system_default: bool = False) -> Optional[ProcessInfo]:
        dlg = cls(parent, title=title, show_system_default=show_system_default)
        if dlg.exec() != QDialog.Accepted:
            return None
        return dlg.selected()


# ====================================================================== inline picker

class PidPicker(QWidget):
    """Inline read-only display + 选择… button. Emits ``changed(pid, name)``."""

    changed = Signal(int, str)

    def __init__(self,
                 parent: Optional[QWidget] = None,
                 *,
                 default_self: bool = True,
                 allow_zero: bool = False,
                 zero_label: str = "(全局, pid=0)",
                 show_system_default: bool = False,
                 placeholder: str = "未选择"):
        super().__init__(parent)
        self._pid:  int = 0
        self._name: str = ""
        self._allow_zero = allow_zero
        self._zero_label = zero_label
        self._show_system_default = show_system_default

        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)

        self._display = QLineEdit()
        self._display.setReadOnly(True)
        self._display.setPlaceholderText(placeholder)
        lay.addWidget(self._display, 1)

        self._btn = QPushButton("选择…")
        self._btn.clicked.connect(self._pick)
        lay.addWidget(self._btn)

        if allow_zero:
            self._btn_zero = QPushButton("全局")
            self._btn_zero.setToolTip("把 PID 清成 0(表示全局/任意进程)")
            self._btn_zero.clicked.connect(lambda: self.set_pid(0, ""))
            lay.addWidget(self._btn_zero)

        if default_self:
            self.set_pid(os.getpid(), "(self)")

    # ---------------------------------------------------------------- accessors

    @property
    def pid(self) -> int:
        return self._pid

    @property
    def name(self) -> str:
        return self._name

    def set_pid(self, pid: int, name: str = "") -> None:
        self._pid  = int(pid)
        self._name = name or ""
        self._refresh_display()
        self.changed.emit(self._pid, self._name)

    def value(self) -> int:
        """Alias for QSpinBox.value()."""
        return self._pid

    def setValue(self, pid: int) -> None:                # noqa: N802 — Qt style
        """Alias for QSpinBox.setValue()."""
        self.set_pid(pid, "")

    # ---------------------------------------------------------------- internals

    def _refresh_display(self) -> None:
        if self._pid == 0 and self._allow_zero:
            self._display.setText(self._zero_label)
        elif self._pid == 0:
            self._display.setText("")
        elif self._name:
            self._display.setText(f"{self._pid}  ({self._name})")
        else:
            self._display.setText(str(self._pid))

    def _pick(self) -> None:
        info = ProcessPickerDialog.pick(
            self, show_system_default=self._show_system_default,
        )
        if info is None:
            return
        self.set_pid(info.pid, info.name)
