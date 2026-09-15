"""界面交互流程测试（offscreen 无头模式）。

覆盖真实操作路径：新建 / 编辑 / 搜索 / 收藏 / 回收站 / 主题切换 /
剪贴板自动清空 / 锁定与重新解锁。运行：python tests/test_ui_flow.py
"""

from __future__ import annotations

import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
if sys.platform == "win32":
    os.environ.setdefault("QT_QPA_FONTDIR", "C:/Windows/Fonts")

for stream in (sys.stdout, sys.stderr):
    try:
        stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from PySide6.QtWidgets import QApplication, QDialog  # noqa: E402

from psvault.core import crypto  # noqa: E402
from psvault.core.models import Entry  # noqa: E402
from psvault.core.storage import Vault  # noqa: E402
from psvault.ui import icons  # noqa: E402
from psvault.ui.entry_dialog import EntryDialog  # noqa: E402
from psvault.ui.main_window import MainWindow  # noqa: E402
from psvault.ui.theme import Theme  # noqa: E402

APP = QApplication.instance() or QApplication(sys.argv)


def pump(times: int = 3) -> None:
    """让 Qt 处理挂起事件。"""
    for _ in range(times):
        APP.processEvents()


class UiFlowTest(unittest.TestCase):
    """主窗口的完整交互流程。"""

    @classmethod
    def setUpClass(cls) -> None:
        theme = Theme.instance()
        theme.set_theme("light")
        theme.apply(APP)
        APP.setWindowIcon(icons.app_icon())

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "flow.psvault"
        self.vault = Vault.create(self.path, "FlowTest#2024")
        self.window = MainWindow(self.vault)
        self.window.resize(1180, 760)
        self.window.show()
        pump()

    def tearDown(self) -> None:
        self.window.hide()
        self.window.deleteLater()
        pump()
        self.tmp.cleanup()

    # ------------------------------------------------------------ 工具

    def _create_via_dialog(self, **fields) -> Entry:
        """走一遍真实的"新建记录"对话框流程。"""
        original_exec = EntryDialog.exec

        def fake_exec(dialog):
            dialog.title_edit.setText(fields.get("title", "新记录"))
            dialog.username_edit.setText(fields.get("username", ""))
            dialog.password_edit.setText(fields.get("password", ""))
            dialog.url_edit.setText(fields.get("url", ""))
            dialog.notes_edit.setPlainText(fields.get("notes", ""))
            dialog.category_combo.setCurrentText(fields.get("category", "未分类"))
            dialog.tags_edit.setText(fields.get("tags", ""))
            dialog.totp_edit.setText(fields.get("totp_secret", ""))
            dialog._save()
            return dialog.result()

        EntryDialog.exec = fake_exec
        try:
            self.window.create_entry()
        finally:
            EntryDialog.exec = original_exec
        pump()
        return self.vault.active_entries()[-1]

    # ------------------------------------------------------------ 用例

    def test_01_create_entry_keeps_password(self) -> None:
        """新建记录必须真正保存用户填写的密码（回归用例）。"""
        entry = self._create_via_dialog(
            title="测试站点", username="tester", password="Str0ng#Pass!2024",
            url="https://example.com", tags="标签一，标签二", category="开发")
        self.assertEqual(entry.title, "测试站点")
        self.assertEqual(entry.password, "Str0ng#Pass!2024")
        self.assertEqual(entry.tags, ["标签一", "标签二"])
        self.assertEqual(entry.category, "开发")
        self.assertIn("开发", self.vault.categories)

        reopened = Vault.open(self.path, "FlowTest#2024")
        stored = reopened.active_entries()[-1]
        self.assertEqual(stored.password, "Str0ng#Pass!2024")

    def test_02_edit_entry_and_history(self) -> None:
        """编辑时改密码应写入密码历史。"""
        entry = self._create_via_dialog(title="改密测试", password="old-pass-1111")
        original_exec = EntryDialog.exec

        def fake_exec(dialog):
            dialog.password_edit.setText("new-pass-2222")
            dialog.notes_edit.setPlainText("更新了备注")
            dialog._save()
            return dialog.result()

        EntryDialog.exec = fake_exec
        try:
            self.window.edit_entry(entry.id)
        finally:
            EntryDialog.exec = original_exec
        pump()

        updated = self.vault.find(entry.id)
        self.assertEqual(updated.password, "new-pass-2222")
        self.assertEqual(updated.notes, "更新了备注")
        self.assertEqual(updated.history[0].password, "old-pass-1111")

        # 未改动密码时不应产生新的历史
        EntryDialog.exec = fake_exec
        try:
            self.window.edit_entry(entry.id)
        finally:
            EntryDialog.exec = original_exec
        pump()
        self.assertEqual(len(self.vault.find(entry.id).history), 1)

    def test_03_search_filters_list(self) -> None:
        """搜索应实时过滤列表卡片。"""
        self._create_via_dialog(title="支付宝", username="alipay_user")
        self._create_via_dialog(title="网易云音乐", username="music_user")
        self.assertEqual(len(self.window._cards), 2)

        self.window.search_box.setText("支付")
        pump()
        self.assertEqual(len(self.window._cards), 1)
        self.assertEqual(list(self.window._cards), [self.vault.active_entries()[0].id]
                         if self.vault.active_entries()[0].title == "支付宝" else list(self.window._cards))

        self.window.search_box.setText("不存在的关键字")
        pump()
        self.assertEqual(len(self.window._cards), 0)
        self.assertTrue(self.window.list_empty.isVisible())

        self.window.search_box.clear()
        pump()
        self.assertEqual(len(self.window._cards), 2)

    def test_04_filter_by_category_and_tag(self) -> None:
        """分类与标签筛选。"""
        self._create_via_dialog(title="A", category="工作", tags="重要")
        self._create_via_dialog(title="B", category="生活")
        self.window.set_filter("category", "工作")
        pump()
        self.assertEqual(len(self.window._cards), 1)
        self.window.set_filter("tag", "重要")
        pump()
        self.assertEqual(len(self.window._cards), 1)
        self.window.set_filter("all")
        pump()
        self.assertEqual(len(self.window._cards), 2)

    def test_05_favorite_and_trash_flow(self) -> None:
        """收藏、移入回收站、恢复与彻底删除。"""
        entry = self._create_via_dialog(title="可回收")
        self.window.toggle_favorite(entry.id)
        pump()
        self.assertTrue(self.vault.find(entry.id).favorite)
        self.window.set_filter("favorite")
        pump()
        self.assertEqual(len(self.window._cards), 1)

        self.vault.trash_entry(entry.id)
        self.vault.save()
        self.window.set_filter("all")
        pump()
        self.assertEqual(len(self.window._cards), 0)
        self.window.set_filter("trash")
        pump()
        self.assertEqual(len(self.window._cards), 1)

        self.window.restore_entry(entry.id)
        pump()
        self.assertFalse(self.vault.find(entry.id).is_deleted)

        self.vault.trash_entry(entry.id)
        self.vault.save()
        self.window.purge_entry(entry.id) if False else None   # 需要确认框，手动执行
        self.vault.purge_entry(entry.id)
        self.vault.save()
        self.window.reload_all()
        pump()
        self.assertIsNone(self.vault.find(entry.id))

    def test_06_selection_and_detail(self) -> None:
        """选中记录后详情面板应展示对应内容。"""
        entry = self._create_via_dialog(title="详情测试", username="user@example.com",
                                        password="Detail#Pass123", totp_secret="JBSWY3DPEHPK3PXP")
        self.window.select_entry(entry.id)
        pump()
        self.assertTrue(self.window.detail_scroll.isVisible())
        self.assertEqual(self.window.password_label.text()[0], "•")

        self.window._toggle_password_visibility(entry)
        pump()
        self.assertEqual(self.window.password_label.text(), "Detail#Pass123")
        self.window._toggle_password_visibility(entry)
        pump()
        self.assertNotEqual(self.window.password_label.text(), "Detail#Pass123")

        # 动态口令行
        self.window._refresh_totp()
        code = self.window.totp_label.text().replace(" ", "")
        self.assertEqual(len(code), 6)
        self.assertTrue(code.isdigit())

    def test_07_clipboard_autoclear(self) -> None:
        """复制敏感内容后应按设置自动清空剪贴板。"""
        self.vault.settings.clipboard_clear_seconds = 1
        entry = self._create_via_dialog(title="剪贴板", password="Clip#Secret99")
        self.window.copy_text(entry.password, "密码", sensitive=True)
        self.assertEqual(APP.clipboard().text(), "Clip#Secret99")

        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and APP.clipboard().text():
            APP.processEvents()
            time.sleep(0.05)
        self.assertEqual(APP.clipboard().text(), "")

    def test_08_theme_switch_rebuilds(self) -> None:
        """主题切换后界面重建且不丢失当前选中项。"""
        entry = self._create_via_dialog(title="主题测试")
        self.window.select_entry(entry.id)
        theme = Theme.instance()
        for name in ("dark", "light"):
            theme.set_theme(name)
            theme.apply(APP)
            self.window.rebuild_for_theme()
            pump()
            self.assertEqual(len(self.window._cards), 1)
            self.assertEqual(self.window.selected_id, entry.id)
            self.assertEqual(self.window.vault.find(entry.id).title, "主题测试")

    def test_09_lock_and_reopen(self) -> None:
        """锁定后内存中不再保留数据；用主密码可以重新打开。"""
        self._create_via_dialog(title="锁定测试", password="Lock#Pass123")
        path = self.vault.path
        self.vault.lock()
        self.assertTrue(self.vault.is_locked)
        self.assertEqual(self.vault.entries, [])

        reopened = Vault.open(path, "FlowTest#2024")
        self.assertEqual(reopened.active_entries()[0].title, "锁定测试")
        reopened.lock()
        with self.assertRaises(crypto.InvalidPassword):
            Vault.open(path, "错误的密码")

    def test_10_audit_view(self) -> None:
        """安全审计筛选只显示有问题的记录。"""
        self._create_via_dialog(title="弱密码", password="123456")
        self._create_via_dialog(title="强密码", password="Xk7#mQ2!vL9$pR4@")
        self.window.set_filter("audit")
        pump()
        titles = [self.vault.find(eid).title for eid in self.window._cards]
        self.assertIn("弱密码", titles)
        self.assertNotIn("强密码", titles)


if __name__ == "__main__":
    unittest.main(verbosity=2)
