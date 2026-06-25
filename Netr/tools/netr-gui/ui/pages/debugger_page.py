"""调试器管理 —— 三个标签页:启动&保护 / 反反调试 / 访问绕过(高危)。

一站式管理:
  [启动 & 保护]  调试白名单 + ADD_DEBUGGER 标志 + 启动并保护 + 活跃会话
  [反反调试]     ANTIANTIDEBUG hook 配置 (NtQueryInformationProcess 等)
  [访问绕过(高危)] NtOpenProcess EPT-hook,让 debugger 能开 PPL/System=4
"""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import time
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QCheckBox, QDialog, QDialogButtonBox, QFileDialog, QFormLayout,
    QGroupBox, QHBoxLayout, QLabel, QLineEdit, QListWidget, QListWidgetItem,
    QPushButton, QTabWidget, QTableWidget, QTableWidgetItem, QVBoxLayout,
    QWidget,
)

from .base import BasePage
from ..context import AppContext
from ..widgets import PidPicker


# ====================================================================== model

@dataclass
class DebuggerEntry:
    path: str
    args: str = ""
    cwd:  str = ""

    @property
    def display_name(self) -> str:
        return os.path.basename(self.path) or self.path


@dataclass
class ActiveSession:
    entry:       DebuggerEntry
    pid:         int
    started_at:  datetime
    process:     subprocess.Popen
    exit_logged: bool = False


# ====================================================================== helpers

def _config_path() -> Path:
    base = os.environ.get("LOCALAPPDATA") or str(Path.home())
    d = Path(base) / "Netr"
    d.mkdir(parents=True, exist_ok=True)
    return d / "debugger_config.json"


def _split_winshell_args(text: str) -> list[str]:
    """Split arg string Windows-style: respects "quoted args", preserves backslashes."""
    text = text.strip()
    if not text:
        return []
    lex = shlex.shlex(text, posix=True)
    lex.whitespace_split = True
    lex.escape = ""              # 不要把 \ 当转义,Windows 路径用得到
    return list(lex)


def _make_help(text: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setWordWrap(True)
    lbl.setStyleSheet("color: #666; padding: 2px 4px;")
    return lbl


def _make_group(title: str, layout: QVBoxLayout | QFormLayout | QHBoxLayout) -> QGroupBox:
    box = QGroupBox(title)
    box.setLayout(layout)
    return box


def _button_row(*buttons: QPushButton) -> QHBoxLayout:
    row = QHBoxLayout()
    for b in buttons:
        row.addWidget(b)
    row.addStretch(1)
    return row


# ====================================================================== entry dialog

class EntryDialog(QDialog):
    def __init__(self, parent, entry: Optional[DebuggerEntry] = None):
        super().__init__(parent)
        self.setWindowTitle("编辑白名单条目" if entry else "添加白名单条目")
        self.resize(580, 0)

        form = QFormLayout(self)

        path_row = QHBoxLayout()
        self._path = QLineEdit(entry.path if entry else "")
        self._path.setPlaceholderText(r"C:\Path\To\app.exe")
        btn_browse = QPushButton("浏览…")
        btn_browse.clicked.connect(self._pick_exe)
        path_row.addWidget(self._path, 1)
        path_row.addWidget(btn_browse)
        form.addRow("可执行文件:", path_row)

        self._args = QLineEdit(entry.args if entry else "")
        self._args.setPlaceholderText(r'例如 -windowed --config "C:\my dir\app.ini"')
        form.addRow("启动参数:", self._args)

        cwd_row = QHBoxLayout()
        self._cwd = QLineEdit(entry.cwd if entry else "")
        self._cwd.setPlaceholderText("(留空 = 使用 exe 所在目录)")
        btn_cwd = QPushButton("浏览…")
        btn_cwd.clicked.connect(self._pick_cwd)
        cwd_row.addWidget(self._cwd, 1)
        cwd_row.addWidget(btn_cwd)
        form.addRow("工作目录:", cwd_row)

        btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        form.addRow(btns)

    def _pick_exe(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "选择可执行文件", "",
            "可执行文件 (*.exe);;所有文件 (*)",
        )
        if path:
            self._path.setText(path)

    def _pick_cwd(self):
        d = QFileDialog.getExistingDirectory(self, "选择工作目录")
        if d:
            self._cwd.setText(d)

    def entry(self) -> Optional[DebuggerEntry]:
        path = self._path.text().strip()
        if not path:
            return None
        return DebuggerEntry(
            path=path,
            args=self._args.text().strip(),
            cwd=self._cwd.text().strip(),
        )


# ====================================================================== page

class DebuggerPage(BasePage):
    title = "调试器管理"

    POLL_INTERVAL_MS = 1500

    def __init__(self, ctx: AppContext, parent=None):
        super().__init__(ctx, parent)

        self._entries:  list[DebuggerEntry]  = []
        self._sessions: list[ActiveSession]  = []

        # 三个 tab 共享同一个数据模型,但 UI 分开。
        self._tabs = QTabWidget()
        self._tabs.addTab(self._build_launch_tab(),  "启动 && 保护")
        self._tabs.addTab(self._build_aad_tab(),     "反反调试")
        self._tabs.addTab(self._build_bypass_tab(),  "访问绕过 (已自动)")
        self._body.addWidget(self._tabs, 1)

        self._load_config()

        self._poll = QTimer(self)
        self._poll.setInterval(self.POLL_INTERVAL_MS)
        self._poll.timeout.connect(self._poll_sessions)
        self._poll.start()

    # ============================================================ TAB 1: launch

    def _build_launch_tab(self) -> QWidget:
        page = QWidget()
        root = QVBoxLayout(page)

        root.addWidget(_make_help(
            "白名单里的 exe 点「启动并保护」会 ADD_DEBUGGER —— 子进程立即获得:\n"
            "  • 对任意 user 进程 (含 PPL/lsass/csrss) 的 OpenProcess 成功\n"
            "  • Nt[R/W]VirtualMemory 自动重定向到 HvPhys 物理直通 (绕 EDR/PG)\n"
            "  • 对 System(PID=4) 只读 kernel VA (写拒绝以避免 BSOD)\n"
            "  • SeDebug 等特权 / 防止终止 / 可选从进程列表隐藏\n"
            "无需配置 target,启动即全权限。所有已启动会话在下方实时刷新。\n"
            "\n"
            "注: 「反反调试」(Tab 2) 不会自动启用 —— 它对游戏反作弊有反效果,"
            "只在调试器自己被反调试 API 探测时手动启用。"
        ))

        # ---- whitelist
        wl_lay = QVBoxLayout()
        self._list = QListWidget()
        self._list.setMinimumHeight(120)
        self._list.itemDoubleClicked.connect(lambda *_: self._edit_entry())
        wl_lay.addWidget(self._list)

        b_add    = QPushButton("添加…")
        b_edit   = QPushButton("编辑…")
        b_del    = QPushButton("删除")
        b_launch = QPushButton("启动并保护")
        b_add.clicked.connect(self._add_entry)
        b_edit.clicked.connect(self._edit_entry)
        b_del.clicked.connect(self._delete_entry)
        b_launch.clicked.connect(self._launch_selected)
        wl_lay.addLayout(_button_row(b_add, b_edit, b_del, b_launch))
        root.addWidget(_make_group(
            "白名单 (持久化到 %LOCALAPPDATA%\\Netr\\debugger_config.json)", wl_lay))

        # ---- flags
        flags_lay = QVBoxLayout()
        flags_lay.addWidget(_make_help(
            "影响所有「启动并保护」按钮 —— 单个条目无单独覆盖。"
        ))
        self._chk_priv = QCheckBox("授予 SeDebug 等特权 (EnablePrivilege)")
        self._chk_term = QCheckBox("禁止被终止 (ProtectFromTerminate)")
        self._chk_hide = QCheckBox("隐藏进程列表 (HideFromList)")
        self._chk_priv.setChecked(True)
        self._chk_term.setChecked(True)
        for chk in (self._chk_priv, self._chk_term, self._chk_hide):
            chk.toggled.connect(lambda _checked: self._save_config())
            flags_lay.addWidget(chk)
        root.addWidget(_make_group("默认 ADD_DEBUGGER 标志", flags_lay))

        # ---- sessions
        sess_lay = QVBoxLayout()
        sess_lay.addWidget(_make_help(
            "本次 GUI 进程启动的子进程列表。退出码会自动捕获;终止前会先 "
            "REMOVE_DEBUGGER,否则 ProtectFromTerminate hook 会拦住 TerminateProcess。"
        ))
        self._sess_tbl = QTableWidget(0, 4)
        self._sess_tbl.setHorizontalHeaderLabels(["PID", "可执行文件", "启动时间", "状态"])
        self._sess_tbl.horizontalHeader().setStretchLastSection(True)
        self._sess_tbl.setSelectionBehavior(QTableWidget.SelectRows)
        self._sess_tbl.setSelectionMode(QTableWidget.SingleSelection)
        self._sess_tbl.setEditTriggers(QTableWidget.NoEditTriggers)
        self._sess_tbl.setMinimumHeight(140)
        sess_lay.addWidget(self._sess_tbl)

        b_detach = QPushButton("解除保护 (REMOVE_DEBUGGER)")
        b_kill   = QPushButton("终止进程")
        b_aad    = QPushButton("对此会话启用反反调试")
        b_clean  = QPushButton("清理已退出")
        b_detach.clicked.connect(self._detach_selected)
        b_kill.clicked.connect(self._kill_selected)
        b_aad.clicked.connect(self._aad_for_selected_session)
        b_clean.clicked.connect(self._clean_exited)
        sess_lay.addLayout(_button_row(b_detach, b_kill, b_aad, b_clean))
        root.addWidget(_make_group("活跃会话", sess_lay))

        root.addStretch(1)
        return page

    # ============================================================ TAB 2: AAD

    def _build_aad_tab(self) -> QWidget:
        page = QWidget()
        root = QVBoxLayout(page)

        warn = QLabel(
            "<b style='color:#c0392b'>⚠ 默认关闭,手动启用 — 对游戏反作弊有反效果</b><br>"
            "AAD 改变 NtQueryInformationProcess / NtClose / NtQueryObject 等系统 API "
            "的返回值。<b>游戏反作弊主动探测这些 API 的行为差异</b>,启用 AAD 后启动"
            "游戏极易触发 \"检测到黑客工具\" 类告警。<br><br>"
            "只在以下场景启用:<br>"
            "&nbsp;&nbsp;• 调试器自己用 IsDebuggerPresent / OllyDbg / ProcessExplorer "
            "检查自己时,想看到\"没附加调试器\"<br>"
            "&nbsp;&nbsp;• 已知目标程序不带商用反作弊 (BattlEye/EAC/Vanguard/nProtect)<br><br>"
            "调试器全权限 (OpenProcess + Read/Write 物理直通) 由「启动并保护」自动启用,"
            "<b>不需要</b>同时开 AAD。"
        )
        warn.setWordWrap(True)
        warn.setStyleSheet("padding: 8px; background: #fdf2f0; border: 1px solid #e6a8a0;")
        root.addWidget(warn)

        root.addWidget(_make_help(
            "在目标进程内 hook 反调试 API,让它的探测返回「无调试器」。"
            "勾哪个 hook 哪个;TargetPid 留空 = 全局应用。下面 3 个默认勾选的"
            "是反调试最常查的;NtClose 和 NtQueryObject **默认关掉** —— 这俩"
            "对游戏反作弊副作用最大。"
        ))

        cfg_lay = QFormLayout()
        self._aad_pid = PidPicker(default_self=False, allow_zero=True,
                                  zero_label="(全局, pid=0)")
        cfg_lay.addRow("TargetPid:", self._aad_pid)
        root.addWidget(_make_group("目标进程", cfg_lay))

        hooks_lay = QVBoxLayout()
        self._aad_c1 = QCheckBox("NtQueryInformationProcess "
                                 "— 拦 ProcessDebugPort/Object/Flags 等查询")
        self._aad_c1.setChecked(True)
        self._aad_c2 = QCheckBox("NtQuerySystemInformation "
                                 "— 拦 KernelDebuggerInformation 等系统级探测")
        self._aad_c2.setChecked(True)
        self._aad_c3 = QCheckBox("NtSetInformationThread "
                                 "— 拦 ThreadHideFromDebugger 反向探测")
        self._aad_c3.setChecked(True)
        self._aad_c4 = QCheckBox("NtClose — 拦无效 handle 异常探测 (偶尔有用,默认关)")
        self._aad_c5 = QCheckBox("NtQueryObject — 拦 ObjectTypesInformation/DebugObject 探测")
        for c in (self._aad_c1, self._aad_c2, self._aad_c3, self._aad_c4, self._aad_c5):
            hooks_lay.addWidget(c)
        root.addWidget(_make_group("Hook 项", hooks_lay))

        b_e = QPushButton("启用反反调试")
        b_d = QPushButton("禁用反反调试")
        b_e.clicked.connect(self._aad_enable)
        b_d.clicked.connect(self._aad_disable)
        root.addLayout(_button_row(b_e, b_d))

        root.addStretch(1)
        return page

    # ============================================================ TAB 3: bypass (应急)

    def _build_bypass_tab(self) -> QWidget:
        page = QWidget()
        root = QVBoxLayout(page)

        info = QLabel(
            "<b style='color:#27ae60'>✓ 已自动启用</b><br>"
            "「启动并保护」会通过 ADD_DEBUGGER 自动装上 NtOpenProcess bypass +"
            " Nt[R/W]VirtualMemory 重定向。注册的 debugger 进程对任意 target 即时全权限,"
            "<b>无需在此手动配置</b>。"
        )
        info.setWordWrap(True)
        info.setStyleSheet("padding: 8px; background: #eafaf1; border: 1px solid #abdbb6;")
        root.addWidget(info)

        root.addWidget(_make_help(
            "下面两个按钮是应急开关,只在以下场景使用:\n"
            "  • 怀疑 hook 装载失败(看 DbgView 没出现 NtOpenProcess hooked at ...)\n"
            "  • 想临时关掉 EPT-hook 跑空载基准对比\n"
            "正常工作流不需要碰这里。EPT-hook 在最后一个 debugger REMOVE_DEBUGGER 时\n"
            "自动卸载,无残留。\n"
            "\n"
            "实现:EPT-hook NtOpenProcess + 临时把 EPROCESS.Protection 抹零 < 1μs 立即恢复,"
            "PG-immune。Ob callback 不动 —— KernelMode + ObOpenObjectByPointer 天然绕开。"
        ))

        b_on  = QPushButton("应急启用 NtOpenProcess bypass")
        b_off = QPushButton("应急关闭")
        b_on.clicked.connect(self._bypass_on)
        b_off.clicked.connect(self._bypass_off)
        root.addLayout(_button_row(b_on, b_off))

        root.addStretch(1)
        return page

    # ============================================================ config

    def _load_config(self) -> None:
        p = _config_path()
        if not p.exists():
            return
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except Exception as e:                          # noqa: BLE001
            self.ctx.log.warn(f"加载调试器配置失败: {e}")
            return

        flags = data.get("default_flags", {})
        for chk, key, default in (
            (self._chk_priv, "enable_privilege",        True),
            (self._chk_term, "protect_from_terminate",  True),
            (self._chk_hide, "hide_from_list",          False),
        ):
            chk.blockSignals(True)
            chk.setChecked(bool(flags.get(key, default)))
            chk.blockSignals(False)

        self._entries = []
        for raw in data.get("entries", []):
            try:
                self._entries.append(DebuggerEntry(
                    path=str(raw.get("path", "")),
                    args=str(raw.get("args", "")),
                    cwd=str(raw.get("cwd", "")),
                ))
            except Exception:                           # noqa: BLE001
                pass
        self._refresh_list()

    def _save_config(self) -> None:
        data = {
            "version": 1,
            "default_flags": {
                "enable_privilege":       self._chk_priv.isChecked(),
                "protect_from_terminate": self._chk_term.isChecked(),
                "hide_from_list":         self._chk_hide.isChecked(),
            },
            "entries": [asdict(e) for e in self._entries],
        }
        try:
            _config_path().write_text(
                json.dumps(data, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        except Exception as e:                          # noqa: BLE001
            self.ctx.log.warn(f"保存调试器配置失败: {e}")

    # ============================================================ list ops

    def _refresh_list(self) -> None:
        self._list.clear()
        for e in self._entries:
            label = e.display_name
            if e.args:
                label += f"   {e.args}"
            it = QListWidgetItem(label)
            it.setToolTip(
                f"{e.path}\n参数: {e.args or '(无)'}\n"
                f"工作目录: {e.cwd or '(默认: exe 所在)'}"
            )
            self._list.addItem(it)

    def _add_entry(self) -> None:
        dlg = EntryDialog(self)
        if dlg.exec() != QDialog.Accepted:
            return
        e = dlg.entry()
        if e is None:
            self.ctx.log.warn("路径不能为空")
            return
        self._entries.append(e)
        self._save_config()
        self._refresh_list()
        self._list.setCurrentRow(len(self._entries) - 1)

    def _edit_entry(self) -> None:
        row = self._list.currentRow()
        if row < 0:
            return
        dlg = EntryDialog(self, self._entries[row])
        if dlg.exec() != QDialog.Accepted:
            return
        e = dlg.entry()
        if e is None:
            self.ctx.log.warn("路径不能为空")
            return
        self._entries[row] = e
        self._save_config()
        self._refresh_list()
        self._list.setCurrentRow(row)

    def _delete_entry(self) -> None:
        row = self._list.currentRow()
        if row < 0:
            return
        del self._entries[row]
        self._save_config()
        self._refresh_list()

    # ============================================================ launch

    def _launch_selected(self) -> None:
        row = self._list.currentRow()
        if row < 0:
            self.ctx.log.warn("请先选中一个白名单条目")
            return
        if not self.require_device():
            return
        entry = self._entries[row]
        flags = (
            self._chk_priv.isChecked(),
            self._chk_term.isChecked(),
            self._chk_hide.isChecked(),
        )

        def do_launch():
            args = _split_winshell_args(entry.args)
            cmd  = [entry.path] + args
            cwd  = entry.cwd or (os.path.dirname(entry.path) or None)
            proc = subprocess.Popen(cmd, cwd=cwd)
            # 给 ~150ms 让明显的早期失败(DLL 解析、入口点错误)冒出来
            time.sleep(0.15)
            rc = proc.poll()
            if rc is not None:
                raise RuntimeError(f"进程立即退出 (code={rc})")
            self.ctx.client.add_debugger(proc.pid, "", *flags)
            return proc

        def on_ok(proc: subprocess.Popen):
            sess = ActiveSession(entry, proc.pid, datetime.now(), proc)
            self._sessions.append(sess)
            self._refresh_sessions()
            self.ctx.log.ok(f"启动并保护 pid={proc.pid}  {entry.display_name}")

        self.run(do_launch, on_success=on_ok)

    # ============================================================ sessions

    def _refresh_sessions(self) -> None:
        self._sess_tbl.setRowCount(len(self._sessions))
        for row, sess in enumerate(self._sessions):
            ec = sess.process.poll()
            status = "运行中" if ec is None else f"已退出 (code={ec})"
            cells = (
                str(sess.pid),
                sess.entry.display_name,
                sess.started_at.strftime("%H:%M:%S"),
                status,
            )
            for col, text in enumerate(cells):
                item = QTableWidgetItem(text)
                if col == 1:
                    item.setToolTip(sess.entry.path)
                if ec is not None:
                    item.setForeground(Qt.gray)
                self._sess_tbl.setItem(row, col, item)

    def _poll_sessions(self) -> None:
        dirty = False
        for sess in self._sessions:
            ec = sess.process.poll()
            if ec is not None and not sess.exit_logged:
                sess.exit_logged = True
                self.ctx.log.info(
                    f"会话退出 pid={sess.pid} code={ec}  {sess.entry.display_name}"
                )
                dirty = True
        if dirty:
            self._refresh_sessions()

    def _selected_session(self) -> Optional[ActiveSession]:
        row = self._sess_tbl.currentRow()
        if row < 0 or row >= len(self._sessions):
            return None
        return self._sessions[row]

    def _detach_selected(self) -> None:
        sess = self._selected_session()
        if sess is None:
            self.ctx.log.warn("请先选中活跃会话")
            return
        if not self.require_device():
            return
        self.run(self.ctx.client.remove_debugger, sess.pid, "",
                 success_msg=f"REMOVE_DEBUGGER ok (pid={sess.pid})")

    def _kill_selected(self) -> None:
        sess = self._selected_session()
        if sess is None:
            self.ctx.log.warn("请先选中活跃会话")
            return
        if sess.process.poll() is not None:
            self.ctx.log.warn(f"pid={sess.pid} 已退出")
            return

        def do_kill():
            # ProtectFromTerminate hook 会拦 TerminateProcess,先 REMOVE_DEBUGGER
            try:
                if self.ctx.device_open():
                    self.ctx.client.remove_debugger(sess.pid, "")
            except Exception as e:                      # noqa: BLE001
                self.ctx.log.warn(f"REMOVE_DEBUGGER 失败 (继续 kill): {e}")
            sess.process.kill()
            return sess.pid

        def on_ok(pid):
            self.ctx.log.ok(f"已终止 pid={pid}")
            self._refresh_sessions()

        self.run(do_kill, on_success=on_ok)

    def _aad_for_selected_session(self) -> None:
        """便捷:把活跃会话的 PID 填到 AAD TargetPid 并切到反反调试 tab。"""
        sess = self._selected_session()
        if sess is None:
            self.ctx.log.warn("请先选中活跃会话")
            return
        self._aad_pid.set_pid(sess.pid, sess.entry.display_name)
        self._tabs.setCurrentIndex(1)         # 切到 AAD tab,提示用户检查 hooks 后启用
        self.ctx.log.info(
            f"已切到「反反调试」并把 TargetPid 设为 {sess.pid};"
            f"勾选所需 hook 后点「启用反反调试」。"
        )

    def _clean_exited(self) -> None:
        before = len(self._sessions)
        self._sessions = [s for s in self._sessions if s.process.poll() is None]
        removed = before - len(self._sessions)
        if removed:
            self.ctx.log.info(f"已清理 {removed} 个已退出会话")
        self._refresh_sessions()

    # ============================================================ AAD

    def _aad_enable(self):
        if not self.require_device():
            return
        self.run(self.ctx.client.enable_anti_anti_debug,
                 self._aad_pid.value(),
                 self._aad_c1.isChecked(), self._aad_c2.isChecked(),
                 self._aad_c3.isChecked(), self._aad_c4.isChecked(),
                 self._aad_c5.isChecked(),
                 success_msg=f"ENABLE_ANTIANTIDEBUG sent (pid={self._aad_pid.value()})")

    def _aad_disable(self):
        if not self.require_device():
            return
        self.run(self.ctx.client.disable_anti_anti_debug,
                 success_msg="DISABLE_ANTIANTIDEBUG sent")

    # ============================================================ bypass

    def _bypass_on(self):
        if not self.require_device():
            return
        self.run(self.ctx.client.enable_access_bypass,
                 success_msg="ENABLE_ACCESS_BYPASS ok (NtOpenProcess EPT-hook armed)")

    def _bypass_off(self):
        if not self.require_device():
            return
        self.run(self.ctx.client.disable_access_bypass,
                 success_msg="DISABLE_ACCESS_BYPASS ok")
