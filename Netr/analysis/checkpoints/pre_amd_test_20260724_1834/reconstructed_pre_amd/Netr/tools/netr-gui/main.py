"""Netr GUI — Qt entry point.

Run from the ``tools/netr-gui`` directory with administrator privileges:

    python main.py

Requires Python 3.10+ and PySide6 (see requirements.txt).
"""

from __future__ import annotations

import sys
import traceback
from pathlib import Path

# Ensure local packages resolve when launched via "python main.py"
sys.path.insert(0, str(Path(__file__).resolve().parent))

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QMessageBox

from netr.privilege import enable_privilege, is_admin
from netr.ioctl import resolve_device_path
from ui.main_window import MainWindow


def _enable_load_driver_privilege() -> str | None:
    """Try to enable SeLoadDriverPrivilege. Returns error string on failure."""
    try:
        enable_privilege("SeLoadDriverPrivilege")
        return None
    except Exception as e:                                # noqa: BLE001
        return f"{type(e).__name__}: {e}"


def _excepthook(exc_type, exc_value, exc_tb):
    """Show unhandled exceptions in a dialog instead of crashing silently."""
    msg = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
    sys.stderr.write(msg)
    try:
        QMessageBox.critical(None, "Netr GUI — 未处理异常", msg)
    except Exception:
        pass


def main() -> int:
    sys.excepthook = _excepthook

    # Qt may complain about a missing AA_ShareOpenGLContexts attribute on some
    # plugins; setting it before creating the QApplication avoids the warning.
    QApplication.setAttribute(Qt.AA_ShareOpenGLContexts, True)

    app = QApplication(sys.argv)
    app.setApplicationName("Netr GUI")
    app.setOrganizationName("Netr")

    if not is_admin():
        QMessageBox.warning(
            None, "需要管理员权限",
            "未以管理员身份启动。\n\n"
            f"驱动加载、卸载以及打开 {resolve_device_path()} 都会失败。\n"
            "请右键 → 以管理员身份运行后重试。"
        )
    else:
        err = _enable_load_driver_privilege()
        if err is not None:
            QMessageBox.warning(
                None, "SeLoadDriverPrivilege 提权失败",
                f"无法启用 SeLoadDriverPrivilege:\n{err}\n\n"
                "驱动加载可能会失败。"
            )

    win = MainWindow()
    win.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
