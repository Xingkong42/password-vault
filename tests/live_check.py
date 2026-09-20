"""真实图形平台下的启动自检：确认窗口能在真实环境创建与渲染。

与 smoke_ui.py（offscreen）不同，本脚本使用系统默认平台，运行时会短暂
弹出窗口后自动关闭。运行：python tests/live_check.py
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

for stream in (sys.stdout, sys.stderr):
    try:
        stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from PySide6.QtCore import QTimer  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from psvault.core.models import Entry  # noqa: E402
from psvault.core.storage import Vault  # noqa: E402
from psvault.ui import icons  # noqa: E402
from psvault.ui.main_window import MainWindow  # noqa: E402
from psvault.ui.theme import Theme  # noqa: E402
from psvault.ui.unlock_dialog import UnlockDialog  # noqa: E402


def main() -> int:
    app = QApplication(sys.argv)
    theme = Theme.instance()
    theme.apply(app)
    app.setWindowIcon(icons.app_icon())

    tmp = Path(tempfile.mkdtemp(prefix="psvault-live-"))
    path = tmp / "v.psvault"
    vault = Vault.create(path, "LiveCheck#2024")
    vault.settings.backup_external_dir = str(tmp / "external-backup")
    vault.add_entry(Entry(title="真实平台自检", username="tester",
                          password="Live#Check2024", url="https://example.com",
                          category="开发", tags=["自检"],
                          totp_secret="JBSWY3DPEHPK3PXP"))

    unlock = UnlockDialog(path=path)
    unlock.show()
    window = MainWindow(vault)
    window.resize(1180, 760)
    window.select_entry(vault.active_entries()[0].id)
    window.show()

    app.processEvents()
    print("平台插件:", app.platformName())
    print("窗口可见:", window.isVisible(), "尺寸:", window.width(), "×", window.height())
    print("详情密码标签:", window.password_label.text())
    print("动态口令:", window.totp_label.text())

    failures: list[str] = []

    def verify() -> None:
        if not window.isVisible():
            failures.append("主窗口不可见")
        if window.totp_label.text() in ("—", ""):
            failures.append("动态口令未生成")

        def sample_backgrounds(tag: str) -> None:
            """面板背景必须来自设计配色。

            样式表覆盖不到的部件（典型是滚动区域的 viewport）会退回调色板，
            在真实系统配色下露出一块与周围明显不同的底色。
            """
            image = window.grab().toImage()
            ratio = image.width() / max(window.width(), 1)   # 真实环境可能有 DPI 缩放
            palette = Theme.instance().palette
            for name, (x, y, expected) in {
                "侧栏": (110, 420, palette.surface_alt),
                "列表栏": (300, 700, palette.surface),
                "详情栏": (900, 700, palette.canvas),
            }.items():
                actual = image.pixelColor(int(x * ratio), int(y * ratio)).name().upper()
                if actual != expected.upper():
                    failures.append(f"[{tag}]{name}背景 {actual} ≠ {expected.upper()}")
                else:
                    print(f"  [{tag}] {name}背景: {actual} ✓")

        theme = Theme.instance()
        sample_backgrounds("浅色")
        theme.set_theme("dark")
        theme.apply(app)
        window.rebuild_for_theme()
        for _ in range(3):
            app.processEvents()
        sample_backgrounds("深色")
        theme.set_theme("light")
        theme.apply(app)

        unlock.close()
        window.hide()
        app.quit()

    QTimer.singleShot(1200, verify)
    app.exec()

    if failures:
        print("自检失败:", failures)
        return 1
    print("真实平台自检通过。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
