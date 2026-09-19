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

from PySide6.QtWidgets import QApplication, QTabWidget  # noqa: E402

from psvault.core.models import Entry  # noqa: E402
from psvault.core.storage import Vault  # noqa: E402
from psvault.ui import icons  # noqa: E402
from psvault.ui.category_dialog import CategoryDialog  # noqa: E402
from psvault.ui.entry_dialog import EntryDialog  # noqa: E402
from psvault.ui.generator_dialog import GeneratorDialog  # noqa: E402
from psvault.ui.main_window import MainWindow  # noqa: E402
from psvault.ui.settings_dialog import SettingsDialog  # noqa: E402
from psvault.ui.theme import Theme  # noqa: E402
from psvault.ui.unlock_dialog import UnlockDialog  # noqa: E402

SHOTS = ROOT / "tests" / "shots"

SAMPLE = [
    Entry(title="GitHub", username="xingkong42", password="Xk7#mQ2!vL9$pR4@",
          phone="138 0000 0000", email="backup@example.com",
          url="https://github.com", category="开发", tags=["工作", "代码"],
          favorite=True, totp_secret="JBSWY3DPEHPK3PXP",
          notes="开启了两步验证，恢复码存放在离线笔记中。"),
    Entry(title="招商银行", username="6214 **** 8823", password="Bank@2024#safe",
          phone="95555", email="card@example.com",
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
    Entry(title="老论坛", username="olduser88", password="OldUser88#2024x",
          url="http://bbs.old-forum.example.com", category="社交"),
    Entry(title="临时注册", username="temp", password="", category="未分类",
          notes="还没有设置密码"),
]


def build_vault() -> Vault:
    """在临时目录里造一个带样例数据的保险箱。"""
    tmp = Path(tempfile.mkdtemp(prefix="psvault-smoke-"))
    path = tmp / "vault.psvault"
    vault = Vault.create(path, "SmokeTest#2024", name="我的密码库")
    # 外部备份指向临时目录，别把测试数据写进真实的「文档」目录
    vault.settings.backup_external_dir = str(tmp / "external-backup")
    for entry in SAMPLE:
        vault.add_entry(entry)
    # 造一条"已忽略"记录，好让审计报告展示已忽略区块
    for entry in vault.entries:
        if entry.title == "淘宝":
            vault.ignore_issue(entry.id, "reused")
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

        creator = UnlockDialog(path=vault.path.with_name("新建保险箱.psvault"))
        creator.name_edit.setText("我的密码库")
        shot(creator, f"create-{mode}", app)

        categories = CategoryDialog(window, vault)
        shot(categories, f"category-{mode}", app)

        generator = GeneratorDialog(window)
        shot(generator, f"generator-{mode}", app)

        settings = SettingsDialog(window, vault)
        shot(settings, f"settings-{mode}", app)
        tabs = settings.findChild(QTabWidget)
        if tabs is not None:                    # 数据页：备份与恢复
            vault.backup_manager().backup(force=True)
            tabs.setCurrentIndex(2)
            settings._refresh_backup_list()
            shot(settings, f"settings-data-{mode}", app)
            settings.resize(620, 1000)      # 拉高一次看全（含备份列表）
            shot(settings, f"settings-data-full-{mode}", app)
            settings.resize(620, 660)

        # 安全审计视图：右侧是完整的风险报告，而不是记录详情
        window.set_filter("audit")
        shot(window, f"audit-{mode}", app)

        # 滚到底部，看"已忽略的提示"区块
        bar = window.detail_scroll.verticalScrollBar()
        bar.setValue(bar.maximum())
        shot(window, f"audit-bottom-{mode}", app)
        bar.setValue(0)

        # 审计视图下点进某条记录：详情页顶部出现具体风险说明
        risky = [e for e in vault.active_entries() if not e.password or e.password == "taobao888"]
        if risky:
            window.select_entry(risky[0].id)
            shot(window, f"audit-entry-{mode}", app)
        window.set_filter("all")
        window.select_entry(vault.active_entries()[0].id)

        editor = EntryDialog(window, vault, vault.active_entries()[0])
        shot(editor, f"editor-{mode}", app)

        for widget in (window, unlock, creator, categories, generator,
                       settings, editor):
            widget.hide()
            widget.deleteLater()
        app.processEvents()

    print("界面冒烟测试通过。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
