"""Memory operations page — MEMORY_READ / WRITE / ALLOC / FREE + 无痕模块枚举."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QAbstractItemView, QComboBox, QHBoxLayout, QHeaderView, QLabel,
    QLineEdit, QPlainTextEdit, QPushButton, QSpinBox,
    QTableWidget, QTableWidgetItem,
)

from netr.structs import HvModuleInfo

from .base import BasePage
from ..context import AppContext
from ..widgets import PidPicker


# Win32 memory protection constants (subset)
PROTECT_OPTIONS = [
    ("PAGE_EXECUTE_READWRITE (0x40)", 0x40),
    ("PAGE_READWRITE        (0x04)", 0x04),
    ("PAGE_EXECUTE_READ     (0x20)", 0x20),
    ("PAGE_READONLY         (0x02)", 0x02),
    ("PAGE_EXECUTE          (0x10)", 0x10),
]


def _parse_addr(text: str) -> int:
    text = text.strip()
    if not text:
        raise ValueError("address is empty")
    return int(text, 16) if text.lower().startswith("0x") else int(text, 16)


def _parse_hex_bytes(text: str) -> bytes:
    """Accept "DE AD BE EF", "deadbeef", "de:ad:be:ef" or mixed."""
    cleaned = "".join(ch for ch in text if ch.isalnum())
    if len(cleaned) % 2 != 0:
        raise ValueError("hex string must have an even number of nibbles")
    try:
        return bytes.fromhex(cleaned)
    except ValueError as e:
        raise ValueError(f"invalid hex: {e}") from None


def _hex_dump(data: bytes, base: int = 0) -> str:
    """Classic 16-byte-per-row hex dump."""
    lines = []
    for off in range(0, len(data), 16):
        chunk = data[off : off + 16]
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        hex_part = hex_part.ljust(16 * 3 - 1)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{base + off:016X}  {hex_part}  |{ascii_part}|")
    return "\n".join(lines)


class MemoryPage(BasePage):
    title = "内存读 / 写 / 分配 / 释放"

    def __init__(self, ctx: AppContext, parent=None):
        super().__init__(ctx, parent)

        # ----------------------------------------------------------- 目标进程 (统一)
        # 整页所有操作共用同一个 PID,避免在 5 个 PidPicker 之间反复同步。
        # show_system_default=True:进程选择 dialog 默认显示 System (PID=4)。
        # 配合驱动 ADD_DEBUGGER 自动启用的 NtOpenProcess bypass + Nt[R/W]VirtualMemory
        # 重定向,可对 System 读 kernel VA;写 PID=4 在驱动侧拒掉 (避免 BSOD)。
        sec_pid = self.add_section("目标进程 (整页共用)")
        self._pid = PidPicker(show_system_default=True)
        sec_pid.addRow("ProcessId:", self._pid)

        # ----------------------------------------------------------- 模块枚举
        # 无痕路径: VtRoot VMCALL → root mode 解 PID → EPROCESS → PEB → Ldr 链表。
        # Hot path 不调任何 Mm*/Ps*/Ob* API,反作弊视角只看到 1 条 vmcall 指令。
        self.add_section("模块枚举 (无痕, VtRoot)")

        m_bar = QHBoxLayout()
        btn_enum = QPushButton("枚举模块")
        btn_enum.clicked.connect(self._do_enum_modules)
        m_bar.addWidget(btn_enum)
        btn_use_read = QPushButton("→ 填到读取 Address")
        btn_use_read.setToolTip("把当前选中模块的 DllBase 写到下方“内存读取”的 Address 框")
        btn_use_read.clicked.connect(self._use_module_for_read)
        m_bar.addWidget(btn_use_read)
        btn_use_write = QPushButton("→ 填到写入 Address")
        btn_use_write.clicked.connect(self._use_module_for_write)
        m_bar.addWidget(btn_use_write)
        self._m_count = QLabel("0 modules")
        m_bar.addStretch(1)
        m_bar.addWidget(self._m_count)
        self._body.addLayout(m_bar)

        self._m_tbl = QTableWidget(0, 3)
        self._m_tbl.setHorizontalHeaderLabels(["DllBase", "Size", "Name"])
        self._m_tbl.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._m_tbl.setSelectionMode(QAbstractItemView.SingleSelection)
        self._m_tbl.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._m_tbl.setSortingEnabled(True)
        self._m_tbl.verticalHeader().setVisible(False)
        self._m_tbl.setFont(QFont("Consolas", 9))
        hh = self._m_tbl.horizontalHeader()
        hh.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        hh.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        hh.setSectionResizeMode(2, QHeaderView.Stretch)
        self._m_tbl.setMinimumHeight(160)
        self._body.addWidget(self._m_tbl, 1)

        # ----------------------------------------------------------- READ
        # 走 MEMORY_READ_EX (优化 #3): 单次 ≤64KB, 比固定 4KB 高 16×。
        # ≤4096 时与旧 IOCTL 等价但码不同 (0x222214 vs 0x222204)。
        sec_r = self.add_section("内存读取 (MEMORY_READ_EX)")
        self._r_addr = QLineEdit(); self._r_addr.setPlaceholderText("0x7FFE0000")
        self._r_size = QSpinBox(); self._r_size.setRange(1, 0x10000); self._r_size.setValue(256)
        sec_r.addRow("Address (hex):", self._r_addr)
        sec_r.addRow("Size (bytes, ≤65536):", self._r_size)
        btn_read = QPushButton("读取")
        btn_read.clicked.connect(self._do_read)
        self.add_button_row(btn_read)

        self._r_view = QPlainTextEdit()
        self._r_view.setReadOnly(True)
        self._r_view.setFont(QFont("Consolas", 9))
        self._r_view.setPlaceholderText("hex dump 将在此处显示…")
        self._body.addWidget(self._r_view, 1)

        # ----------------------------------------------------------- WRITE
        # 走 MEMORY_WRITE_EX (优化 #3): 单次 ≤64KB。
        sec_w = self.add_section("内存写入 (MEMORY_WRITE_EX)")
        self._w_addr = QLineEdit(); self._w_addr.setPlaceholderText("0x7FFE0000")
        self._w_data = QLineEdit(); self._w_data.setPlaceholderText("DE AD BE EF (max 65536 bytes)")
        sec_w.addRow("Address (hex):", self._w_addr)
        sec_w.addRow("Bytes (hex):", self._w_data)
        btn_write = QPushButton("写入")
        btn_write.clicked.connect(self._do_write)
        self.add_button_row(btn_write)

        # ----------------------------------------------------------- ALLOC
        sec_a = self.add_section("分配内存 (MEMORY_ALLOC)")
        self._a_size  = QSpinBox(); self._a_size.setRange(1, 0x7FFFFFFF); self._a_size.setValue(4096)
        self._a_prot  = QComboBox()
        for label, _ in PROTECT_OPTIONS:
            self._a_prot.addItem(label)
        sec_a.addRow("Size:",       self._a_size)
        sec_a.addRow("Protection:", self._a_prot)
        btn_alloc = QPushButton("分配")
        btn_alloc.clicked.connect(self._do_alloc)
        self.add_button_row(btn_alloc)

        # ----------------------------------------------------------- FREE
        sec_f = self.add_section("释放内存 (MEMORY_FREE)")
        self._f_addr = QLineEdit(); self._f_addr.setPlaceholderText("0x...")
        self._f_size = QSpinBox(); self._f_size.setRange(0, 0x7FFFFFFF)
        self._f_size.setSpecialValueText("（整块释放，size=0）")
        sec_f.addRow("Address (hex):", self._f_addr)
        sec_f.addRow("Size:",          self._f_size)
        btn_free = QPushButton("释放")
        btn_free.clicked.connect(self._do_free)
        self.add_button_row(btn_free)

        self.add_stretch()

    # ----------------------------------------------------------- handlers
    def _do_read(self):
        if not self.require_device():
            return
        try:
            addr = _parse_addr(self._r_addr.text())
        except ValueError as e:
            self.ctx.log.warn(f"Address: {e}")
            return
        pid, size = self._pid.value(), self._r_size.value()

        def on_ok(data: bytes):
            self._r_view.setPlainText(_hex_dump(data, base=addr))
            self.ctx.log.ok(f"MEMORY_READ_EX ok: {len(data)} bytes from pid={pid} @ 0x{addr:X}")

        self.run(self.ctx.client.memory_read_ex, pid, addr, size,
                 on_success=on_ok)

    def _do_write(self):
        if not self.require_device():
            return
        try:
            addr = _parse_addr(self._w_addr.text())
            data = _parse_hex_bytes(self._w_data.text())
        except ValueError as e:
            self.ctx.log.warn(str(e))
            return
        if not data:
            self.ctx.log.warn("Hex bytes input is empty.")
            return
        if len(data) > 0x10000:
            self.ctx.log.warn(f"Payload too large ({len(data)}B); max is 65536.")
            return
        pid = self._pid.value()
        self.run(self.ctx.client.memory_write_ex, pid, addr, data,
                 success_msg=f"MEMORY_WRITE_EX ok ({len(data)}B → pid={pid} @ 0x{addr:X})")

    def _do_alloc(self):
        if not self.require_device():
            return
        pid  = self._pid.value()
        size = self._a_size.value()
        prot = PROTECT_OPTIONS[self._a_prot.currentIndex()][1]

        def on_ok(address: int):
            self.ctx.log.ok(f"MEMORY_ALLOC ok: pid={pid}, size={size}, prot=0x{prot:X} → 0x{address:X}")

        self.run(self.ctx.client.memory_alloc, pid, size, prot,
                 on_success=on_ok)

    def _do_free(self):
        if not self.require_device():
            return
        try:
            addr = _parse_addr(self._f_addr.text())
        except ValueError as e:
            self.ctx.log.warn(f"Address: {e}")
            return
        pid, size = self._pid.value(), self._f_size.value()
        self.run(self.ctx.client.memory_free, pid, addr, size,
                 success_msg=f"MEMORY_FREE ok (pid={pid} @ 0x{addr:X}, size={size})")

    # ----------------------------------------------------------- 模块枚举 handlers

    def _do_enum_modules(self):
        if not self.require_device():
            return
        pid = self._pid.value()

        def on_ok(modules: list[HvModuleInfo]):
            self._m_tbl.setSortingEnabled(False)
            self._m_tbl.setRowCount(0)
            for m in modules:
                row = self._m_tbl.rowCount()
                self._m_tbl.insertRow(row)

                it_base = QTableWidgetItem(f"0x{m.DllBase:016X}")
                it_base.setData(Qt.UserRole, int(m.DllBase))
                it_base.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)

                it_size = QTableWidgetItem(f"0x{m.SizeOfImage:X}")
                it_size.setData(Qt.DisplayRole, int(m.SizeOfImage))
                it_size.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)

                it_name = QTableWidgetItem(str(m.Name))

                self._m_tbl.setItem(row, 0, it_base)
                self._m_tbl.setItem(row, 1, it_size)
                self._m_tbl.setItem(row, 2, it_name)
            self._m_tbl.setSortingEnabled(True)
            self._m_count.setText(f"{len(modules)} modules")
            self.ctx.log.ok(f"ENUMERATE_MODULES ok: pid={pid} → {len(modules)} modules")

        self.run(self.ctx.client.enumerate_modules, pid,
                 on_success=on_ok)

    def _selected_module_base(self) -> int | None:
        row = self._m_tbl.currentRow()
        if row < 0:
            self.ctx.log.warn("先在模块表里选一行")
            return None
        item = self._m_tbl.item(row, 0)
        if item is None:
            return None
        base = item.data(Qt.UserRole)
        return int(base) if isinstance(base, int) else None

    def _use_module_for_read(self):
        base = self._selected_module_base()
        if base is None:
            return
        self._r_addr.setText(f"0x{base:X}")

    def _use_module_for_write(self):
        base = self._selected_module_base()
        if base is None:
            return
        self._w_addr.setText(f"0x{base:X}")
