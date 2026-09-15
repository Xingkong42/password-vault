"""界面冒烟测试：在无头（offscreen）模式下构建所有窗口并截图。

运行：python tests/smoke_ui.py
截图输出到 tests/shots/，用于人工核对视觉细节。
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
# offscreen 平台不会自动枚举系统字体，显式指定字体目录才能渲染出中文
if sys.platform == "win32":
    os.environ.setdefault("QT_QPA_FONTDIR", "C:/Windows/Fonts")

# Windows 控制台默认 GBK，中文与符号输出会报错，统一切到 UTF-8
for stream in (sys.stdout, sys.stderr):
    try:
        stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from PySide6.QtWidgets import QApplication  # noqa: E402

from psvault.core.models import Entry  # noqa: E402
from psvault.core.storage import Vault  # noqa: E402
from psvault.ui import icons  # noqa: E402
from psvault.ui.audit_dialog import AuditDialog  # noqa: E402
from psvault.ui.entry_dialog import EntryDialog  # noqa: E402
from psvault.ui.generator_dialog import GeneratorDialog  # noqa: E402
from psvault.ui.main_window import MainWindow  # noqa: E402
from psvault.ui.settings_dialog import SettingsDialog  # noqa: E402
from psvault.ui.theme import Theme  # noqa: E402
from psvault.ui.unlock_dialog import UnlockDialog  # noqa: E402

SHOTS = ROOT / "tests" / "shots"

SAMPLE = [
    Entry(title="GitHub", username="xingkong42", password="Xk7#mQ2!vL9$pR4@",
          url="https://github.com", category="开发", tags=["工作", "代码"],
          favorite=True, totp_secret="JBSWY3DPEHPK3PXP",
          notes="开启了两步验证，恢复码存放在离线笔记中。"),
    Entry(title="招商银行", username="6214 **** 8823", password="Bank@2024#safe",
          url="https://www.cmbchina.com", category="金融", tags=["重要"]),
    Entry(title="知乎", username="sophon@example.com", password="zhihu123",
          url="https://www.zhihu.com", category="社交"),
    Entry(title="淘宝", username="shop_account", password="taobao888",
          url="https://taobao.com", category="购物", tags=["购物"]),
    Entry(title="企业邮箱", username="me@company.com", password="Mail!2024#Strong",
          url="https://mail.company.com", category="邮箱", favorite=True),
    Entry(title="路由器管理", username="admin", password="admin123",
          url="http://192.168.1.1", category="开发"),
    Entry(title="某论坛", username="reader", password="taobao888",
          url="https://forum.example.com", category="社交"),
    Entry(title="临时注册", username="temp", password="", category="未分类",
          notes="还没有设置密码"),
]


def build_vault() -> Vault:
    """在临时目录里造一个带样例数据的保险箱。"""
    tmp = Path(tempfile.mkdtemp(prefix="psvault-smoke-"))
    path = tmp / "vault.psvault"
    vault = Vault.create(path, "SmokeTest#2024")
    for entry in SAMPLE:
        vault.add_entry(entry)
    vault.save()
    return vault


def shot(widget, name: str, app: QApplication) -> None:
    """把控件渲染成 PNG。"""
    widget.show()
    for _ in range(4):
        app.processEvents()
    SHOTS.mkdir(parents=True, exist_ok=True)
    target = SHOTS / f"{name}.png"
    pixmap = widget.grab()
    if not pixmap.save(str(target), "PNG"):
        raise RuntimeError(f"截图保存失败：{target}")
    print(f"  ✓ {target.relative_to(ROOT)}  ({pixmap.width()}×{pixmap.height()})")


def main() -> int:
    app = QApplication(sys.argv)
    theme = Theme.instance()
    theme.apply(app)
    app.setWindowIcon(icons.app_icon())
    print("渲染界面…")
    for mode in ("light", "dark"):
        theme.set_theme(mode)
        theme.apply(app)
        vault = build_vault()      # 每个模式用独立保险箱，避免窗口关闭时被锁定

        window = MainWindow(vault)
        window.resize(1180, 760)
        window.select_entry(vault.active_entries()[0].id)
        shot(window, f"main-{mode}", app)

        unlock = UnlockDialog(path=vault.path)
        shot(unlock, f"unlock-{mode}", app)

        generator = GeneratorDialog(window)
        shot(generator, f"generator-{mode}", app)

        settings = SettingsDialog(window, vault)
        shot(settings, f"settings-{mode}", app)

        audit = AuditDialog(window, vault)
        shot(audit, f"audit-{mode}", app)

        editor = EntryDialog(window, vault, vault.active_entries()[0])
        shot(editor, f"editor-{mode}", app)

        for widget in (window, unlock, generator, settings, audit, editor):
            widget.hide()
            widget.deleteLater()
        app.processEvents()

    print("界面冒烟测试通过。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
