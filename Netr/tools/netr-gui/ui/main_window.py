"""Main window — tree navigation, stacked pages, status bar, log dock."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QAction, QIcon
from PySide6.QtWidgets import (
    QDockWidget, QHBoxLayout, QLabel, QMainWindow, QSplitter,
    QStackedWidget, QStatusBar, QTreeWidget, QTreeWidgetItem, QWidget,
)

from netr.privilege import is_admin
from netr.ioctl import resolve_device_path

from .context import AppContext
from .log_panel import LogPanel
from .pages.debugger_page  import DebuggerPage
from .pages.driver_page    import DriverPage
from .pages.dse_page       import DsePage
from .pages.hwbp_page      import HwBpPage
from .pages.inject_page    import InjectPage
from .pages.input_page     import InputPage
from .pages.memory_page    import MemoryPage
from .pages.process_page   import ProcessPage
# protect_page DEPRECATED — 调试器全权限已自动整合到 ADD_DEBUGGER 路径
# (HvHookAddDebugger 0→1 时一并启用 NtOpenProcess bypass + Nt[R/W]VirtualMemory 重定向)。
# 文件保留作历史回退,不再加入页面树。
from .pages.service_page   import ServicePage
from .pages.status_page    import StatusPage


# Tree node "userData" identifiers
NODE_SERVICE        = "service"
NODE_STATUS         = "status"
NODE_DSE            = "dse"
NODE_PROCESS        = "process"
NODE_DRIVER         = "driver"
NODE_DEBUGGER       = "debugger"
# NODE_PROTECT 已废弃,见 protect_page import 处注释
NODE_MEMORY         = "memory"
NODE_INJECT         = "inject"
NODE_HWBP           = "hwbp"
NODE_INPUT          = "input"


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Netr Hypervisor Control")
        # 默认尺寸适配 1366×768 (常见 1K 笔记本) — 高度留出任务栏 + 标题栏
        self.resize(1280, 680)
        self.setMinimumSize(900, 560)

        # ---------- log panel + context
        self.log = LogPanel()
        self.ctx = AppContext(self.log)

        # ---------- central: tree + stacked
        self.tree = QTreeWidget()
        self.tree.setHeaderHidden(True)
        self.tree.setColumnCount(1)
        self.tree.setMinimumWidth(220)

        self.stack = QStackedWidget()
        self._pages: dict[str, QWidget] = {}

        self._build_pages()
        self._build_tree()

        splitter = QSplitter(Qt.Horizontal)
        splitter.addWidget(self.tree)
        splitter.addWidget(self.stack)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([240, 1040])

        self.setCentralWidget(splitter)

        # ---------- log dock
        dock = QDockWidget("Log", self)
        dock.setAllowedAreas(Qt.BottomDockWidgetArea | Qt.TopDockWidgetArea)
        dock.setWidget(self.log)
        self.addDockWidget(Qt.BottomDockWidgetArea, dock)

        # ---------- status bar
        self._build_status_bar()

        # ---------- menu
        self._build_menu()

        # ---------- wiring
        self.tree.currentItemChanged.connect(self._on_tree_changed)
        self.ctx.state_changed.connect(self._on_state_changed)

        # initial state
        self.tree.setCurrentItem(self._service_item)
        self.log.info("Netr GUI started.")
        if not is_admin():
            self.log.warn("Process is NOT running as Administrator — driver load will fail.")
        self.ctx.refresh_service()                   # populate status bar

    # ===================================================================== build

    def _build_pages(self) -> None:
        self._pages[NODE_SERVICE]   = ServicePage(self.ctx)
        self._pages[NODE_STATUS]    = StatusPage(self.ctx)
        self._pages[NODE_DSE]       = DsePage(self.ctx)
        self._pages[NODE_PROCESS]   = ProcessPage(self.ctx)
        self._pages[NODE_DRIVER]    = DriverPage(self.ctx)
        self._pages[NODE_DEBUGGER]  = DebuggerPage(self.ctx)
        self._pages[NODE_MEMORY]    = MemoryPage(self.ctx)
        self._pages[NODE_INJECT]    = InjectPage(self.ctx)
        self._pages[NODE_HWBP]      = HwBpPage(self.ctx)
        self._pages[NODE_INPUT]     = InputPage(self.ctx)
        for w in self._pages.values():
            self.stack.addWidget(w)

    def _build_tree(self) -> None:
        def add(parent: QTreeWidget | QTreeWidgetItem, text: str,
                key: str | None = None) -> QTreeWidgetItem:
            it = QTreeWidgetItem([text])
            if key is not None:
                it.setData(0, Qt.UserRole, key)
            (parent.addTopLevelItem(it) if isinstance(parent, QTreeWidget)
             else parent.addChild(it))
            return it

        # 驱动管理
        g_svc = add(self.tree, "驱动管理")
        self._service_item = add(g_svc, "服务加载/卸载", NODE_SERVICE)
        g_svc.setExpanded(True)

        # 状态查询
        g_state = add(self.tree, "状态查询")
        add(g_state, "总览 / 嵌套虚拟化", NODE_STATUS)
        g_state.setExpanded(True)

        # 安全
        g_sec = add(self.tree, "安全 / DSE")
        add(g_sec, "DSE 开关与查询", NODE_DSE)
        g_sec.setExpanded(True)

        # 隐藏
        g_hide = add(self.tree, "隐藏")
        add(g_hide, "进程隐藏",  NODE_PROCESS)
        add(g_hide, "驱动隐藏",  NODE_DRIVER)
        g_hide.setExpanded(True)

        # 保护
        g_prot = add(self.tree, "保护")
        add(g_prot, "调试器管理",   NODE_DEBUGGER)
        # "进程保护" 入口已废弃: 启动调试器即获得对任意 user/PPL/System(只读) 的全权限
        g_prot.setExpanded(True)

        # 进程操作
        g_op = add(self.tree, "进程操作")
        add(g_op, "内存读写/分配/释放", NODE_MEMORY)
        add(g_op, "DLL / Shellcode 注入", NODE_INJECT)
        g_op.setExpanded(True)

        # 调试
        g_dbg = add(self.tree, "调试")
        add(g_dbg, "VT 透明硬件断点 (HWBP)", NODE_HWBP)
        g_dbg.setExpanded(True)

        # 输入注入
        g_in = add(self.tree, "输入注入")
        add(g_in, "VT 透明键鼠注入", NODE_INPUT)
        g_in.setExpanded(True)

    def _build_status_bar(self) -> None:
        sb = QStatusBar(self)
        self.setStatusBar(sb)
        self._lbl_admin = QLabel("Admin: ?")
        self._lbl_svc   = QLabel("Service: ?")
        self._lbl_dev   = QLabel("Device: closed")
        sb.addPermanentWidget(self._lbl_admin)
        sb.addPermanentWidget(self._lbl_svc)
        sb.addPermanentWidget(self._lbl_dev)
        self._lbl_admin.setText(f"Admin: {'YES' if is_admin() else 'NO'}")

    def _build_menu(self) -> None:
        mb = self.menuBar()

        m_file = mb.addMenu("文件(&F)")
        act_quit = QAction("退出(&Q)", self)
        act_quit.setShortcut("Ctrl+Q")
        act_quit.triggered.connect(self.close)
        m_file.addAction(act_quit)

        m_view = mb.addMenu("视图(&V)")
        act_refresh = QAction("刷新状态(&R)", self)
        act_refresh.setShortcut("F5")
        act_refresh.triggered.connect(self.ctx.refresh_service)
        m_view.addAction(act_refresh)

        m_help = mb.addMenu("帮助(&H)")
        act_about = QAction("关于(&A)", self)
        act_about.triggered.connect(self._show_about)
        m_help.addAction(act_about)

    # ===================================================================== slots

    def _on_tree_changed(self, current: QTreeWidgetItem | None, _prev) -> None:
        if current is None:
            return
        key = current.data(0, Qt.UserRole)
        if key in self._pages:
            self.stack.setCurrentWidget(self._pages[key])

    def _on_state_changed(self) -> None:
        # device label — show the path the device was actually opened on, not
        # a module-level constant that was frozen at import time.
        if self.ctx.device_open():
            path = self.ctx.client.device.path if self.ctx.client else resolve_device_path()
            self._lbl_dev.setText(f"Device: open ({path})")
        else:
            self._lbl_dev.setText("Device: closed")

        # service label
        info = self.ctx.last_service_info
        if info is None:
            self._lbl_svc.setText("Service: ?")
        else:
            self._lbl_svc.setText(f"Service: {info.state.name}")

        # enable/disable IOCTL-bound nodes
        self._set_ioctl_nodes_enabled(self.ctx.device_open())

    def _set_ioctl_nodes_enabled(self, enabled: bool) -> None:
        """All nodes except 'service' depend on an open device handle."""
        def walk(it: QTreeWidgetItem):
            key = it.data(0, Qt.UserRole)
            if key is not None and key != NODE_SERVICE:
                it.setDisabled(not enabled)
            for i in range(it.childCount()):
                walk(it.child(i))
        for i in range(self.tree.topLevelItemCount()):
            walk(self.tree.topLevelItem(i))

    def _show_about(self) -> None:
        from PySide6.QtWidgets import QMessageBox
        QMessageBox.about(self, "关于 Netr GUI",
            "Netr Hypervisor Control GUI\n\n"
            "Python + PySide6 客户端，覆盖驱动 23 个 IOCTL。\n"
            "需要管理员权限 + 测试签名模式。")

    # ===================================================================== window close

    def closeEvent(self, ev):                        # noqa: N802 — Qt name
        try:
            self.ctx.close_device()
        finally:
            super().closeEvent(ev)
