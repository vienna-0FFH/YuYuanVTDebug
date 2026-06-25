"""VT 透明键鼠注入页 (阶段 7.10).

驱动启动时按机器实际硬件二选一:
  - PS/2 后端:在 hypervisor 层拦 0x60/0x64 端口 + 合成 IRQ 1/12 (虚拟机/老台式)
  - USB HID 后端:在 ring-0 直接调 kbdclass/mouclass 的 ClassService 回调
                  (现代 USB 键鼠笔记本;不动 VMCS,不打 hook)

从 ring-3 看两条路径都跟物理输入无法区分 —— LLKHF_INJECTED = 0 是 SendInput
路径才会置位,我们走的两条路 win32k 都不会标记。

页面分三块:
  1) 顶部:Backend 状态标签 + 启用/禁用开关 + 适配后端的风险说明
  2) Tab 1 (键盘):多行打字输入区 + 速度滑块,快捷键按钮 (Esc/Enter/方向键/F1-12)
  3) Tab 2 (鼠标):dx/dy + 按钮组合发送一次;点击/平滑移动便捷按钮

设计上不在 GUI 线程做长循环 (打字时一秒发上百个字符也只是排队进 fifo,
真正的节流由 driver 端 spinlock + 计时器搞定)。所有 IOCTL 通过 ``self.run``
扔到 async_worker,避免阻塞 Qt 主循环。
"""

from __future__ import annotations

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QCheckBox, QHBoxLayout, QLabel, QPlainTextEdit, QPushButton, QSlider,
    QSpinBox, QTabWidget, QVBoxLayout, QWidget,
)

from netr.structs import (
    SCANCODE_MAP,
    HV_INPUT_MBUTTON_L, HV_INPUT_MBUTTON_R, HV_INPUT_MBUTTON_M,
    HV_INPUT_BACKEND_NONE, HV_INPUT_BACKEND_PS2, HV_INPUT_BACKEND_USB_HID,
    HV_INPUT_BACKEND_XHCI,
    HV_INPUT_BACKEND_NAMES,
)

from .base import BasePage
from ..context import AppContext


# 快捷键面板布局:每行 (label, send_key_arg)
_QUICK_KEYS_ROW1 = [
    ("Esc",   "ESC"),
    ("Tab",   "TAB"),
    ("Enter", "ENTER"),
    ("Back",  "BACKSPACE"),
    ("Space", " "),
    ("Caps",  "CAPS"),
]
_QUICK_KEYS_ROW2 = [
    ("←",  "LEFT"),
    ("↑",  "UP"),
    ("↓",  "DOWN"),
    ("→",  "RIGHT"),
    ("Home", "HOME"),
    ("End",  "END"),
    ("PgUp", "PGUP"),
    ("PgDn", "PGDN"),
    ("Ins",  "INSERT"),
    ("Del",  "DELETE"),
]
_QUICK_KEYS_FN = [f"F{i}" for i in range(1, 13)]


class InputPage(BasePage):
    title = "VT 透明键鼠注入 (阶段 7.10)"

    def __init__(self, ctx: AppContext, parent=None):
        super().__init__(ctx, parent)

        # ---------------------------------------------------------- 后端状态
        self._lbl_backend = QLabel("<b>Backend:</b> (未查询)")
        self._lbl_backend.setTextFormat(Qt.RichText)
        self._lbl_backend.setFont(QFont("Consolas", 10))
        self._body.addWidget(self._lbl_backend)

        self._lbl_warn = QLabel("")  # 文案由 _refresh_status 写
        self._lbl_warn.setWordWrap(True)
        self._lbl_warn.setTextFormat(Qt.RichText)
        self._body.addWidget(self._lbl_warn)

        btn_enable  = QPushButton("启用输入注入")
        btn_disable = QPushButton("关闭输入注入")
        btn_status  = QPushButton("刷新状态")
        btn_xhci    = QPushButton("xHCI 诊断")
        btn_enable.clicked.connect(self._enable)
        btn_disable.clicked.connect(self._disable)
        btn_status.clicked.connect(self._refresh_status)
        btn_xhci.clicked.connect(self._refresh_xhci_diag)
        self.add_button_row(btn_enable, btn_disable, btn_status, btn_xhci)

        # xHCI 诊断信息显示 (Item 1 — scan-ahead 验证 + ERDP 推进观测)
        # 默认隐藏,后端 = xHCI 时由 _apply_status 显式 setVisible(True)
        self._lbl_xhci_diag = QLabel("")
        self._lbl_xhci_diag.setFont(QFont("Consolas", 9))
        self._lbl_xhci_diag.setTextFormat(Qt.RichText)
        self._lbl_xhci_diag.setWordWrap(True)
        self._lbl_xhci_diag.setVisible(False)
        self._body.addWidget(self._lbl_xhci_diag)
        # 用来算 delta 的快照
        self._xhci_prev = None

        # ---------------------------------------------------------- 严格 xHCI 模式
        # 默认 OFF;勾上后 xHCI 失败不会回退 v3 ring-0 ClassService 直调
        # (后者被任何 r0 hook 都能看见)。为反检测/反作弊场景准备。
        strict_row = QHBoxLayout()
        self._chk_strict = QCheckBox("严格 xHCI 模式 (xHCI 失败时不回退 v3 ring-0 直调)")
        self._chk_strict.setToolTip(
            "勾上 = 严格模式:只走 xHCI Layer 4 (真 VT-透明 USB event ring 注入)。\n"
            "         xHCI 不可用时键鼠操作全部失败,但保证 ring-0 任何 hook\n"
            "         (KbdClass 过滤、ETWTI、PG)都看不见我们的注入路径。\n"
            "不勾 = 默认:xHCI 失败时自动回退到 v3 (kbdclass!ClassServiceCallback 直调),\n"
            "         保最大可用性,但 r0 hook 可观测此路径。"
        )
        self._chk_strict.toggled.connect(self._on_strict_toggled)
        strict_row.addWidget(self._chk_strict)
        strict_row.addStretch(1)
        self._body.addLayout(strict_row)

        # ---------------------------------------------------------- Item 2: EPT 读 trap
        # 默认 OFF — 显式启用以排查 hang/无响应/鼠标不响应。
        # 原理:USBSTS.EINT 和 IMAN.IP 被 OR 进读取结果,让 xhci.sys ISR 不在
        # fast-bail 路径返回,真正消费我们写进 Event Ring 的 TRB。
        trap_row = QHBoxLayout()
        self._chk_xhci_trap = QCheckBox("Item 2: xHCI USBSTS/IMAN EPT 读 trap (高风险 — 显式启用)")
        self._chk_xhci_trap.setToolTip(
            "勾上 = hypervisor 在 guest 读 USBSTS/IMAN 时 OR 进伪 EINT/IP 位,\n"
            "         让 xhci.sys ISR 真正消费 Event Ring。\n"
            "         需要 CPU 支持 MTF (Monitor Trap Flag);不支持时勾选会被驱动拒绝。\n"
            "不勾 (默认) = trap 不激活,即使注入 MSI 也只是 EINT=0 的中断;\n"
            "         先不勾测试基础链路,确认稳定后再勾上。\n"
            "如果勾上后系统卡死/无响应,说明 trap 实现有问题 — 重启后保持不勾。"
        )
        self._chk_xhci_trap.toggled.connect(self._on_xhci_trap_toggled)
        trap_row.addWidget(self._chk_xhci_trap)
        self._btn_trap_stats = QPushButton("Trap 诊断")
        self._btn_trap_stats.clicked.connect(self._refresh_xhci_trap_stats)
        trap_row.addWidget(self._btn_trap_stats)
        trap_row.addStretch(1)
        self._body.addLayout(trap_row)

        # 显示 trap 当前状态 + 累计计数器
        self._lbl_xhci_trap = QLabel("")
        self._lbl_xhci_trap.setFont(QFont("Consolas", 9))
        self._lbl_xhci_trap.setTextFormat(Qt.RichText)
        self._lbl_xhci_trap.setWordWrap(True)
        self._lbl_xhci_trap.setVisible(False)
        self._body.addWidget(self._lbl_xhci_trap)

        # ---------------------------------------------------------- Tabs
        self._tabs = QTabWidget()
        self._tabs.addTab(self._build_keyboard_tab(), "键盘")
        self._tabs.addTab(self._build_mouse_tab(),    "鼠标")
        self._body.addWidget(self._tabs, 1)

        # 打字定时器 — 用 QTimer 而不是阻塞 sleep,避免 GUI 卡死
        self._type_timer = QTimer(self)
        self._type_timer.setSingleShot(False)
        self._type_timer.timeout.connect(self._on_type_tick)
        self._type_buffer: str = ""
        self._type_index: int = 0

        self.add_stretch()

    # ============================================================== show event

    def showEvent(self, ev):                         # noqa: N802 — Qt name
        # 第一次切到此页面 (或设备刚 open 后切回) 都自动刷新一次后端状态
        super().showEvent(ev)
        if self.ctx.device_open():
            self._refresh_status()
            self._refresh_xhci_trap_stats()

    # ============================================================== keyboard tab

    def _build_keyboard_tab(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)

        # 多行文本输入
        v.addWidget(QLabel("要打字的内容:"))
        self._kb_text = QPlainTextEdit()
        self._kb_text.setPlaceholderText("hello world\n(只发送 SCANCODE_MAP 里有的字符,其他跳过)")
        self._kb_text.setMinimumHeight(120)
        v.addWidget(self._kb_text, 1)

        # 速度滑块 (键与键之间间隔, ms)
        row = QHBoxLayout()
        row.addWidget(QLabel("按键间隔:"))
        self._kb_speed = QSlider(Qt.Horizontal)
        self._kb_speed.setRange(20, 300)        # ms
        self._kb_speed.setValue(80)
        self._kb_speed.setToolTip("两次按键之间的间隔毫秒数 (driver 端 spinlock 已经做了真随机 jitter,这里是 GUI 排队节奏)")
        self._kb_speed_lbl = QLabel("80 ms")
        self._kb_speed.valueChanged.connect(
            lambda v: self._kb_speed_lbl.setText(f"{v} ms"))
        row.addWidget(self._kb_speed, 1)
        row.addWidget(self._kb_speed_lbl)
        v.addLayout(row)

        # 选项
        opts = QHBoxLayout()
        self._kb_auto_break = QCheckBox("AutoBreak (按下后 30-80ms 自动释放)")
        self._kb_auto_break.setChecked(True)
        self._kb_auto_break.setToolTip(
            "勾选 = make + 自动 break,适合打字;\n"
            "不勾 = 只发 make,需要再手动调释放 (适合游戏蓄力)"
        )
        opts.addWidget(self._kb_auto_break)
        opts.addStretch(1)
        v.addLayout(opts)

        # 控制按钮
        ctl = QHBoxLayout()
        self._btn_type_start = QPushButton("开始打字")
        self._btn_type_stop  = QPushButton("停止")
        self._btn_type_stop.setEnabled(False)
        self._btn_type_start.clicked.connect(self._start_typing)
        self._btn_type_stop.clicked.connect(self._stop_typing)
        ctl.addWidget(self._btn_type_start)
        ctl.addWidget(self._btn_type_stop)
        ctl.addStretch(1)
        v.addLayout(ctl)

        # 进度
        self._kb_progress = QLabel("(idle)")
        self._kb_progress.setFont(QFont("Consolas", 9))
        v.addWidget(self._kb_progress)

        # ---------------- 快捷键 ----------------
        v.addWidget(QLabel("<b>快捷键</b>"))
        for keyset, title in (
            (_QUICK_KEYS_ROW1, "控制键"),
            (_QUICK_KEYS_ROW2, "方向 / 编辑"),
        ):
            v.addWidget(QLabel(title))
            row = QHBoxLayout()
            for label, key in keyset:
                btn = QPushButton(label)
                btn.setMaximumWidth(72)
                btn.clicked.connect(lambda _=False, k=key: self._send_one_key(k))
                row.addWidget(btn)
            row.addStretch(1)
            v.addLayout(row)

        v.addWidget(QLabel("F1 - F12"))
        row = QHBoxLayout()
        for fn in _QUICK_KEYS_FN:
            btn = QPushButton(fn)
            btn.setMaximumWidth(48)
            btn.clicked.connect(lambda _=False, k=fn: self._send_one_key(k))
            row.addWidget(btn)
        row.addStretch(1)
        v.addLayout(row)

        v.addStretch(1)
        return w

    # ============================================================== mouse tab

    def _build_mouse_tab(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)

        v.addWidget(QLabel("一次性发送 (相对位移 + 按钮状态)"))

        row = QHBoxLayout()
        row.addWidget(QLabel("dx:"))
        self._m_dx = QSpinBox()
        self._m_dx.setRange(-2000, 2000)
        self._m_dx.setValue(0)
        row.addWidget(self._m_dx)

        row.addWidget(QLabel("dy:"))
        self._m_dy = QSpinBox()
        self._m_dy.setRange(-2000, 2000)
        self._m_dy.setValue(0)
        row.addWidget(self._m_dy)
        row.addStretch(1)
        v.addLayout(row)

        bopts = QHBoxLayout()
        self._m_l = QCheckBox("Left")
        self._m_r = QCheckBox("Right")
        self._m_m = QCheckBox("Middle")
        bopts.addWidget(self._m_l)
        bopts.addWidget(self._m_r)
        bopts.addWidget(self._m_m)
        self._m_smooth = QCheckBox("Smooth (大位移拆 ≤8 px/frame)")
        self._m_smooth.setChecked(True)
        bopts.addStretch(1)
        bopts.addWidget(self._m_smooth)
        v.addLayout(bopts)

        ctl = QHBoxLayout()
        btn_send  = QPushButton("发送一次")
        btn_click = QPushButton("原地左键单击")
        btn_rclick = QPushButton("原地右键单击")
        btn_send.clicked.connect(self._send_mouse_once)
        btn_click.clicked.connect(lambda: self._click(HV_INPUT_MBUTTON_L))
        btn_rclick.clicked.connect(lambda: self._click(HV_INPUT_MBUTTON_R))
        ctl.addWidget(btn_send)
        ctl.addWidget(btn_click)
        ctl.addWidget(btn_rclick)
        ctl.addStretch(1)
        v.addLayout(ctl)

        v.addWidget(QLabel(
            "<i>提示:PS/2 鼠标包总是上报当前按钮状态。\n"
            "如果你勾了 Left 然后发,光标会按住左键;\n"
            "再发一次但不勾,Windows 才收到 mouse-up,完成一次点击。\n"
            "便捷按钮已经替你做完这个 down/up 配对。</i>"
        ))

        v.addStretch(1)
        return w

    # ============================================================== enable/disable

    def _enable(self) -> None:
        if not self.require_device():
            return
        self.run(self.ctx.client.enable_input,
                 success_msg="INPUT 启用",
                 on_success=lambda _r: self._refresh_status())

    def _disable(self) -> None:
        if not self.require_device():
            return
        # 关闭前先停掉 GUI 端打字 timer,避免继续往一个 disabled 的 driver 发字
        self._stop_typing()
        self.run(self.ctx.client.disable_input,
                 success_msg="INPUT 关闭 (passthrough 模式)",
                 on_success=lambda _r: self._refresh_status())

    def _on_strict_toggled(self, checked: bool) -> None:
        if not self.ctx.device_open():
            # 设备没开 — 不要往 driver 发,但记下用户意图,等设备开了再下推
            self.ctx.log.warn("设备未打开,严格 xHCI 模式设置将在下次连接时生效")
            return
        self.run(self.ctx.client.set_strict_xhci_mode, checked,
                 success_msg=f"严格 xHCI 模式 = {'ON' if checked else 'OFF'}",
                 on_success=lambda _r: self._refresh_status())

    # ============================================================== item 2 EPT 读 trap

    def _on_xhci_trap_toggled(self, checked: bool) -> None:
        if not self.ctx.device_open():
            self.ctx.log.warn("设备未打开,xHCI 读 trap 设置将在下次连接时生效")
            # Revert checkbox without recursive signals
            self._chk_xhci_trap.blockSignals(True)
            self._chk_xhci_trap.setChecked(False)
            self._chk_xhci_trap.blockSignals(False)
            return
        fn = self.ctx.client.xhci_trap_enable if checked else self.ctx.client.xhci_trap_disable
        msg = "xHCI 读 trap = ON (Item 2 启用)" if checked else "xHCI 读 trap = OFF"
        # 调用后总是刷一次状态 — 驱动若拒绝 (MTF 不支持/未 init),_apply_xhci_trap_stats
        # 会把 checkbox 同步回 UserEnabled=0 的真值,自动撤回。
        self.run(fn, success_msg=msg,
                 on_success=lambda _r: self._refresh_xhci_trap_stats())

    def _refresh_xhci_trap_stats(self) -> None:
        if not self.ctx.device_open():
            return
        self.run(self.ctx.client.xhci_trap_get_stats,
                 on_success=self._apply_xhci_trap_stats)

    def _apply_xhci_trap_stats(self, st) -> None:
        # Sync checkbox without recursive signal
        self._chk_xhci_trap.blockSignals(True)
        self._chk_xhci_trap.setChecked(bool(st.UserEnabled))
        self._chk_xhci_trap.blockSignals(False)

        if not st.Initialized:
            self._lbl_xhci_trap.setText(
                "<b style='color:#c44'>Item 2 Trap:</b> 未初始化 "
                "(xHCI Layer 4 没 ready,或 MTF 不支持,或 HvCoreInitialize 没调到)"
            )
        else:
            mtf_str = ("<span style='color:#080'>MTF 支持</span>" if st.MtfSupported
                       else "<span style='color:#c44'>MTF 不支持</span>")
            en_str  = ("<span style='color:#080'>启用</span>" if st.UserEnabled
                       else "<span style='color:#888'>禁用</span>")
            self._lbl_xhci_trap.setText(
                f"<b>Item 2 Trap:</b> {en_str} | {mtf_str} | "
                f"TrapPages={st.TrapPageCount} | PendingReads={st.PendingIsrReads}<br>"
                f"<span style='color:#888' >Arm={st.StatArmCount} "
                f"UsbstsFaked={st.StatUsbstsReadFaked} "
                f"ImanFaked={st.StatImanReadFaked} "
                f"OtherOnPage={st.StatOtherReadOnPage} "
                f"MtfMisses={st.StatMtfMisses}</span>"
            )
        self._lbl_xhci_trap.setVisible(True)

    # ============================================================== status

    def _refresh_status(self) -> None:
        if not self.require_device():
            return
        self.run(self.ctx.client.get_input_status,
                 on_success=self._apply_status)

    def _apply_status(self, st) -> None:
        """Render HvInputStatus into the header labels."""
        backend = HV_INPUT_BACKEND_NAMES.get(st.Backend, f"?({st.Backend})")
        flags = []
        flags.append("Initialized" if st.Initialized else "NotInit")
        flags.append("Enabled"     if st.Enabled     else "Disabled")
        flags.append("KbdReady"    if st.KbdReady    else "KbdMiss")
        flags.append("MouseReady"  if st.MouseReady  else "MouseMiss")
        if st.StrictXhciMode:
            flags.append("StrictXhci")

        # 同步 checkbox 状态 — 拒绝触发 _on_strict_toggled 形成回环
        self._chk_strict.blockSignals(True)
        self._chk_strict.setChecked(bool(st.StrictXhciMode))
        self._chk_strict.blockSignals(False)

        extra = ""
        if st.Backend == HV_INPUT_BACKEND_PS2:
            extra = (f"  KbdVec=0x{st.KbdVector:02X}"
                     f" MouseVec=0x{st.MouseVector:02X}")
        elif st.Backend == HV_INPUT_BACKEND_USB_HID:
            extra = (f"  KbdCb=0x{st.KbdCallback:016X}"
                     f" MouseCb=0x{st.MouseCallback:016X}")

        self._lbl_backend.setText(
            f"<b>Backend:</b> <span style='color:#06c'>{backend}</span>  "
            f"[{' | '.join(flags)}]"
            f"<span style='color:#888'>{extra}</span>"
        )

        # 后端 = xHCI 时显示诊断面板,其他后端隐藏
        self._lbl_xhci_diag.setVisible(st.Backend == HV_INPUT_BACKEND_XHCI)
        if st.Backend == HV_INPUT_BACKEND_XHCI:
            # 自动取一次诊断快照 (用户也能按 [xHCI 诊断] 按钮主动刷)
            self._refresh_xhci_diag()

        if st.Backend == HV_INPUT_BACKEND_PS2:
            self._lbl_warn.setText(
                "<b style='color:#c44'>PS/2 模式:</b> "
                "本机所有 PS/2 端口读取 (0x60 / 0x64) 会经过 hypervisor。"
                "USB HID 设备不受影响;纯 PS/2 设备会引入 ~2μs/读 的额外延迟。"
            )
        elif st.Backend == HV_INPUT_BACKEND_XHCI:
            self._lbl_warn.setText(
                "<b style='color:#06c'>xHCI Layer 4 (VT-透明):</b> "
                "直接给真 xHCI 控制器的 Event Ring 写 Transfer Event TRB,"
                "再用 VT-d IR 解析出来的真 MSI 向量触发 xhci.sys 的 ISR。"
                "数据沿 xhci → kbdhid → kbdclass → win32k 的真硬件路径上行,"
                "从 r0 任何 hook 角度(ClassService、ETW、PG)看都跟物理按键无法区分。"
            )
        elif st.Backend == HV_INPUT_BACKEND_USB_HID:
            self._lbl_warn.setText(
                "<b style='color:#480'>USB HID 模式 (v3 兜底):</b> "
                "在 ring-0 直接调 kbdclass / mouclass 的 ClassService 回调,"
                "不动 VMCS、不动 IDT、不打 hook。数据沿 kbdclass → win32k → "
                "目标窗口 的真路径上行,LLKHF_INJECTED 不会置位。"
                "<i>注:r0 hook ClassService 可观测此路径;若要更深层 VT-透明,"
                "需升级到 xHCI Layer 4 后端。</i>"
            )
        else:
            self._lbl_warn.setText(
                "<b style='color:#c44'>后端未初始化:</b> "
                "PS/2 IOAPIC 发现失败,xHCI Layer 4 探测失败,USB HID 探测也未成功。"
                "本页所有 IOCTL 都会返回 <code>STATUS_DEVICE_NOT_READY</code>。"
                "请检查驱动加载日志。"
            )

    # ============================================================== xHCI diagnostics

    def _refresh_xhci_diag(self) -> None:
        """Pull HvUsbXhciStatus and render counters + ERDP delta.

        Item 1 验证用 — 一次按键应该看到:
            TrbWriteOk +1, InjectAttempts +1, InjectDelivered +1, ErdpAdvanced +1
        如果看到 TrbWriteFailed +1 → producer slot 没找到 (scan-ahead 没救活)
        如果看到 ErdpStalled +1   → 注入了但 xhci.sys ISR 没跑 (MSI 没真触发)
        """
        if not self.ctx.device_open():
            return
        self.run(self.ctx.client.get_xhci_status,
                 on_success=self._apply_xhci_diag)

    def _apply_xhci_diag(self, st) -> None:
        prev = self._xhci_prev

        def _delta(field: str) -> str:
            cur = getattr(st, field)
            if prev is None:
                return f"{cur}"
            d = (cur - getattr(prev, field)) & 0xFFFFFFFF
            sign = "+" if d > 0 else ""
            color = "#080" if d > 0 else "#888"
            return f"{cur} <span style='color:{color}'>({sign}{d})</span>"

        erdp_now = st.CurrentErdp
        erdp_last = st.LastInjectedErdp
        erdp_diff = erdp_now - erdp_last if erdp_last else 0

        ready_str = "ready" if st.Ready else "<b style='color:#c44'>not-ready</b>"
        kbd_str = "yes" if st.HasKeyboard else "no"
        mouse_str = "yes" if st.HasMouse else "no"

        # 健康度判定:Delivered/Attempts 比 + ErdpAdvanced/Delivered 比
        if st.StatInjectAttempts > 0:
            deliver_pct = 100.0 * st.StatInjectDelivered / st.StatInjectAttempts
        else:
            deliver_pct = 0.0
        if st.StatInjectDelivered > 0:
            consume_pct = 100.0 * st.StatErdpAdvanced / st.StatInjectDelivered
        else:
            consume_pct = 0.0

        if consume_pct >= 80:
            health_color = "#080"
            health = "✓ ISR 正常消费"
        elif consume_pct >= 30:
            health_color = "#a60"
            health = "⚠ ISR 部分消费 (检查 IR0 mask)"
        elif st.StatInjectDelivered == 0:
            health_color = "#888"
            health = "(暂无数据)"
        else:
            health_color = "#c44"
            health = "✗ ISR 未消费 (MSI 没到 / fast-bail)"

        text = (
            f"<b style='color:#06c'>xHCI 诊断</b> [{ready_str}] "
            f"kbd={kbd_str} mouse={mouse_str} "
            f"MSI=0x{st.MsiVector:02X} "
            f"PCI=0x{st.PciVendorId:04X}:0x{st.PciDeviceId:04X}"
            f"<br>"
            f"<b>注入:</b> "
            f"Attempts={_delta('StatInjectAttempts')} "
            f"Delivered={_delta('StatInjectDelivered')} "
            f"Deferred={_delta('StatInjectDeferred')} "
            f"<span style='color:#666'>(deliver={deliver_pct:.0f}%)</span>"
            f"<br>"
            f"<b>TRB 写:</b> "
            f"Ok={_delta('StatTrbWriteOk')} "
            f"Failed={_delta('StatTrbWriteFailed')} "
            f"<span style='color:#888'>(scan-ahead Item 1)</span>"
            f"<br>"
            f"<b>ERDP:</b> "
            f"Advanced={_delta('StatErdpAdvanced')} "
            f"Stalled={_delta('StatErdpStalled')} "
            f"<span style='color:#666'>(consume={consume_pct:.0f}%)</span>"
            f"<br>"
            f"<b>ERDP 实时:</b> "
            f"now=0x{erdp_now:016X} last=0x{erdp_last:016X} "
            f"diff={erdp_diff:+d}B"
            f"<br>"
            f"<b style='color:{health_color}'>状态:{health}</b>"
        )
        self._lbl_xhci_diag.setText(text)
        self._xhci_prev = st

    # ============================================================== keyboard actions

    def _send_one_key(self, key: str) -> None:
        if not self.require_device():
            return
        if key not in SCANCODE_MAP:
            self.ctx.log.warn(f"未支持的按键: {key!r}")
            return
        auto_break = self._kb_auto_break.isChecked()
        self.run(self.ctx.client.send_key, key,
                 auto_break=auto_break,
                 success_msg=f"send_key {key} ok (auto_break={auto_break})")

    def _start_typing(self) -> None:
        if not self.require_device():
            return
        text = self._kb_text.toPlainText()
        if not text:
            self.ctx.log.warn("打字内容为空")
            return
        # 过滤一遍只留 SCANCODE_MAP 里有的字符 (大小写忽略)
        filtered = [c for c in text if c.upper() in SCANCODE_MAP]
        if not filtered:
            self.ctx.log.warn("文本里没有可发送的字符 (全都不在 SCANCODE_MAP 表里)")
            return
        skipped = len(text) - len(filtered)
        if skipped:
            self.ctx.log.warn(f"{skipped} 个字符不在扫描码表里,跳过 (例如中文/Unicode)")

        self._type_buffer = "".join(filtered)
        self._type_index = 0
        self._btn_type_start.setEnabled(False)
        self._btn_type_stop.setEnabled(True)
        self._kb_text.setReadOnly(True)
        self.ctx.log.ok(f"开始打字: {len(self._type_buffer)} 个字符, 间隔 {self._kb_speed.value()}ms")
        self._type_timer.start(self._kb_speed.value())
        self._on_type_tick()  # 立即发第一个字符

    def _stop_typing(self) -> None:
        if not self._type_timer.isActive():
            return
        self._type_timer.stop()
        self._btn_type_start.setEnabled(True)
        self._btn_type_stop.setEnabled(False)
        self._kb_text.setReadOnly(False)
        self._kb_progress.setText(f"(stopped at {self._type_index}/{len(self._type_buffer)})")
        self.ctx.log.info(f"打字停止 ({self._type_index}/{len(self._type_buffer)} 完成)")

    def _on_type_tick(self) -> None:
        if self._type_index >= len(self._type_buffer):
            self._type_timer.stop()
            self._btn_type_start.setEnabled(True)
            self._btn_type_stop.setEnabled(False)
            self._kb_text.setReadOnly(False)
            self._kb_progress.setText(f"(done, {len(self._type_buffer)} keys sent)")
            self.ctx.log.ok(f"打字完成 ({len(self._type_buffer)} 个字符)")
            return

        ch = self._type_buffer[self._type_index]
        key = ch.upper()
        self._type_index += 1
        self._kb_progress.setText(
            f"({self._type_index}/{len(self._type_buffer)}) sending {key!r}"
        )
        # send_key 内部会查表,异步,失败不阻塞 timer
        auto_break = self._kb_auto_break.isChecked()
        try:
            self.run(self.ctx.client.send_key, key, auto_break=auto_break)
        except Exception as e:                       # noqa: BLE001
            self.ctx.log.error(f"send_key({key!r}) 调度失败: {e}")

    # ============================================================== mouse actions

    def _collect_buttons(self) -> int:
        b = 0
        if self._m_l.isChecked(): b |= HV_INPUT_MBUTTON_L
        if self._m_r.isChecked(): b |= HV_INPUT_MBUTTON_R
        if self._m_m.isChecked(): b |= HV_INPUT_MBUTTON_M
        return b

    def _send_mouse_once(self) -> None:
        if not self.require_device():
            return
        dx, dy = self._m_dx.value(), self._m_dy.value()
        btn   = self._collect_buttons()
        smooth = self._m_smooth.isChecked()
        self.run(self.ctx.client.send_mouse, dx, dy, btn,
                 smooth=smooth,
                 success_msg=f"send_mouse dx={dx} dy={dy} btn=0x{btn:X} smooth={smooth} ok")

    def _click(self, button: int) -> None:
        if not self.require_device():
            return
        self.run(self.ctx.client.click_mouse, button,
                 success_msg=f"click 0x{button:X} ok")
