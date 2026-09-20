"""密码保险箱 —— 程序入口。

用法：
    python main.py                 正常启动
    pythonw main.py                无控制台启动（推荐，见随附的 VBS 脚本）
"""

from __future__ import annotations

import sys
from pathlib import Path

# 允许直接从源码目录运行
sys.path.insert(0, str(Path(__file__).resolve().parent))

from PySide6.QtCore import QEvent, QObject, Qt, QTimer  # noqa: E402
from PySide6.QtWidgets import QApplication, QDialog, QMessageBox  # noqa: E402

from psvault import __app_name__, __version__  # noqa: E402
from psvault.ui import icons  # noqa: E402
from psvault.ui.main_window import MainWindow  # noqa: E402
from psvault.ui.single_instance import VaultLock  # noqa: E402
from psvault.ui.theme import Theme  # noqa: E402
from psvault.ui.unlock_dialog import UnlockDialog  # noqa: E402

# 会被记录为空闲打断的事件类型
ACTIVITY_EVENTS = {
    QEvent.MouseButtonPress,
    QEvent.MouseButtonDblClick,
    QEvent.MouseMove,
    QEvent.KeyPress,
    QEvent.Wheel,
    QEvent.TouchBegin,
}


class ActivityMonitor(QObject):
    """全局事件过滤器：把用户活动时间告诉主窗口，用于空闲自动锁定。"""

    def __init__(self, window: MainWindow) -> None:
        super().__init__(window)
        self.window = window

    def eventFilter(self, obj, event) -> bool:  # noqa: N802 - Qt 命名
        if event.type() in ACTIVITY_EVENTS:
            self.window.note_activity()
        return False


def main() -> int:
    """程序主流程。"""
    QApplication.setApplicationName(__app_name__)
    QApplication.setApplicationVersion(__version__)
    QApplication.setOrganizationName("PSVault")
    QApplication.setAttribute(Qt.AA_DontShowIconsInMenus, False)

    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(True)

    theme = Theme.instance()
    theme.apply(app)
    app.setWindowIcon(icons.app_icon())

    # 第一步：解锁或创建保险箱
    unlock = UnlockDialog()
    if unlock.exec() != QDialog.Accepted or unlock.vault is None:
        return 0

    vault = unlock.vault
    theme.set_theme(vault.settings.theme)
    theme.apply(app)

    # 独占锁：同一份保险箱同时只允许一个进程编辑。
    # 两个窗口各自读到旧数据、又各自写回时，后写的会静默覆盖先写的；
    # 单靠原子替换（os.replace）只能保证"文件不损坏"，挡不住这种丢数据。
    vault_lock = VaultLock()

    if not vault_lock.acquire(vault.path):
        QMessageBox.warning(
            None, "这个保险箱已经打开了",
            f"「{vault.name}」正在被另一个密码保险箱窗口使用。\n\n"
            "两个窗口同时编辑会互相覆盖，所以这里不再继续。\n"
            "请切换到已经打开的那个窗口，或先把它关掉再试。")
        return 1

    vault.cleanup_temp_files()      # 清掉上次崩溃可能留下的临时文件

    window = MainWindow(vault)
    monitor = ActivityMonitor(window)
    app.installEventFilter(monitor)

    def handle_lock(reason: str) -> None:
        """锁定后重新弹解锁窗口；取消则退出程序。"""
        window.hide()
        again = UnlockDialog(path=window.vault.path)
        if again.exec() == QDialog.Accepted and again.vault is not None:
            if not vault_lock.acquire(again.vault.path):
                QMessageBox.warning(
                    None, "这个保险箱已经打开了",
                    f"「{again.vault.name}」正在被另一个窗口使用，无法在这里打开。")
                app.quit()
                return
            window.vault = again.vault
            window.selected_id = ""
            theme.set_theme(window.vault.settings.theme)
            theme.apply(app)
            window.rebuild_for_theme()
            window.showNormal()
            window.raise_()
            window.activateWindow()
            window.note_activity()
            if reason:
                window.toast.show_message(reason)
        else:
            app.quit()

    window.lock_requested.connect(handle_lock)

    def handle_theme(_name: str) -> None:
        theme.apply(app)
        window.rebuild_for_theme()

    theme.changed.connect(handle_theme)

    window.show()
    QTimer.singleShot(0, lambda: window.search_box.setFocus())
    return app.exec()


if __name__ == "__main__":
    # 隐藏参数：用于打包后排查"双击没反应"的问题
    if "--selftest" in sys.argv:
        from psvault.selftest import run_selftest

        sys.exit(run_selftest(sys.argv))

    try:
        sys.exit(main())
    except Exception as exc:  # noqa: BLE001 - 顶层兜底，避免闪退无提示
        import traceback

        # 打包成无控制台程序后 sys.stdout/stderr 可能是 None，打印要容错
        detail = traceback.format_exc()
        try:
            if sys.stderr is not None:
                sys.stderr.write(detail)
        except (OSError, ValueError, AttributeError):
            pass
        try:
            from psvault.core.storage import application_root

            crash_log = application_root() / "crash.log"
            crash_log.write_text(detail, encoding="utf-8")
        except Exception:  # noqa: BLE001
            pass
        try:
            app = QApplication.instance() or QApplication(sys.argv)
            QMessageBox.critical(None, "密码保险箱启动失败",
                                 f"程序遇到未处理的错误：\n\n{exc}")
        except Exception:  # noqa: BLE001
            pass
        sys.exit(1)
