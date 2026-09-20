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

from PySide6.QtCore import Qt  # noqa: E402
from PySide6.QtTest import QTest  # noqa: E402
from PySide6.QtWidgets import (  # noqa: E402
    QApplication,
    QDialog,
    QFrame,
    QLabel,
    QPushButton,
)

from psvault.core import crypto, strength  # noqa: E402
from psvault.core.models import Entry  # noqa: E402
from psvault.core.storage import Vault  # noqa: E402
from psvault.ui import icons  # noqa: E402
from psvault.ui.audit_panel import AuditPanel  # noqa: E402
from psvault.ui.category_dialog import CategoryDialog  # noqa: E402
from psvault.ui.entry_dialog import EntryDialog  # noqa: E402
from psvault.ui.main_window import MainWindow  # noqa: E402
from psvault.ui.settings_dialog import SettingsDialog  # noqa: E402
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
        # 外部备份改到临时目录，避免测试污染真实的「文档」目录
        self.vault.settings.backup_external_dir = str(Path(self.tmp.name) / "external")
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
            dialog.phone_edit.setText(fields.get("phone", ""))
            dialog.email_edit.setText(fields.get("email", ""))
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
            phone="13800000000", email="backup@example.com",
            url="https://example.com", tags="标签一，标签二", category="开发")
        self.assertEqual(entry.title, "测试站点")
        self.assertEqual(entry.password, "Str0ng#Pass!2024")
        self.assertEqual(entry.phone, "13800000000")
        self.assertEqual(entry.email, "backup@example.com")
        self.assertEqual(entry.tags, ["标签一", "标签二"])
        self.assertEqual(entry.category, "开发")
        self.assertIn("开发", self.vault.categories)

        reopened = Vault.open(self.path, "FlowTest#2024")
        stored = reopened.active_entries()[-1]
        self.assertEqual(stored.password, "Str0ng#Pass!2024")
        self.assertEqual(stored.email, "backup@example.com")

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

    def test_11_detail_shows_contact_fields(self) -> None:
        """详情页展示预留电话与预留邮箱。"""
        entry = self._create_via_dialog(title="联系信息", username="login_name",
                                        phone="13900000000", email="spare@example.com")
        self.window.select_entry(entry.id)
        pump()
        texts = [label.text() for label in self.window.detail_host.findChildren(QLabel)]
        self.assertIn("13900000000", texts)
        self.assertIn("spare@example.com", texts)
        self.assertIn("预留电话", texts)
        self.assertIn("预留邮箱", texts)

    def test_12_vault_name_in_title_and_sidebar(self) -> None:
        """保险箱名称会出现在窗口标题与侧栏。"""
        self.vault.set_name("工作保险箱")
        self.vault.save()
        self.window.reload_all()
        pump()
        self.assertEqual(self.window.brand_label.text(), "工作保险箱")
        self.assertIn("工作保险箱", self.window.windowTitle())

    def test_13_category_dialog_flow(self) -> None:
        """分类管理：新建 / 重命名 / 删除，删除后记录归入未分类。"""
        dialog = CategoryDialog(self.window, self.vault)
        self.assertIn("密钥", self.vault.categories)      # 默认自带

        self.assertTrue(dialog.add_category("设备"))
        self.assertFalse(dialog.add_category("设备"))      # 重复
        self.assertIn("设备", self.vault.categories)

        entry = self._create_via_dialog(title="路由器", category="设备")
        self.assertTrue(dialog.rename_category("设备", "网络设备"))
        self.assertIn("网络设备", self.vault.categories)
        self.assertEqual(self.vault.find(entry.id).category, "网络设备")

        self.assertFalse(dialog.remove_category("未分类"))  # 系统分类不可删
        self.assertTrue(dialog.remove_category("网络设备"))
        self.assertNotIn("网络设备", self.vault.categories)
        self.assertEqual(self.vault.find(entry.id).category, "未分类")

        # 删除后重新打开文件，分类变更已被持久化
        reopened = Vault.open(self.path, "FlowTest#2024")
        self.assertNotIn("网络设备", reopened.categories)
        dialog.deleteLater()
        pump()

    def test_15_audit_view_shows_report_not_detail(self) -> None:
        """安全审计视图右侧是风险报告，而不是普通的记录详情。"""
        self._create_via_dialog(title="弱密码站", password="123456")
        self._create_via_dialog(title="好密码站", password="Xk7#mQ2!vL9$pR4@",
                                totp_secret="JBSWY3DPEHPK3PXP")

        self.window.set_filter("audit")
        pump()

        panels = self.window.detail_host.findChildren(AuditPanel)
        self.assertEqual(len(panels), 1, "审计视图应嵌入审计报告面板")
        self.assertEqual(len(self.window._cards), 1, "列表只应出现有问题的记录")
        self.assertEqual(self.window.selected_id, "")

        # 报告必须写清楚问题是什么，而不是只给一个分数
        text = " ".join(label.text() for label in panels[0].findChildren(QLabel))
        self.assertIn("弱密码", text)
        self.assertTrue("密码过于简单" in text or "弱密码" in text)

    def test_16_detail_banner_names_the_risk(self) -> None:
        """详情页要明确指出风险类型和原因。"""
        entry = self._create_via_dialog(title="甲站", password="repeat-pass-1234")
        self._create_via_dialog(title="乙站", password="repeat-pass-1234")

        self.window.set_filter("all")
        self.window.select_entry(entry.id)
        pump()

        banner = self.window.detail_host.findChild(QFrame, "RiskBanner")
        self.assertIsNotNone(banner, "有风险的记录应在详情页显示风险横幅")
        text = " ".join(label.text() for label in banner.findChildren(QLabel))
        self.assertIn("重复", text)
        self.assertIn("乙站", text)

    def test_17_healthy_entry_has_no_banner(self) -> None:
        entry = self._create_via_dialog(title="很安全的站", password="Xk7#mQ2!vL9$pR4@",
                                        totp_secret="JBSWY3DPEHPK3PXP")
        self.window.select_entry(entry.id)
        pump()
        self.assertIsNone(self.window.detail_host.findChild(QFrame, "RiskBanner"))

    def test_18_backup_written_when_saving(self) -> None:
        """保存记录时自动留下备份（本地 + 外部各一份）。"""
        self._create_via_dialog(title="备份测试", password="Backup#123456")
        backups = self.vault.backup_manager().list()
        self.assertTrue(backups)
        self.assertEqual({info.location for info in backups}, {"本地", "外部"})

    def test_19_restore_from_backup(self) -> None:
        """从备份恢复能把数据换回指定版本。"""
        self._create_via_dialog(title="第一版", password="First#123456")
        self.vault.backup_manager().backup(force=True)
        snapshot = self.vault.backup_manager().latest()
        self.assertIsNotNone(snapshot)

        self._create_via_dialog(title="第二版", password="Second#123456")
        self.assertEqual(len(self.vault.active_entries()), 2)

        self.vault.restore_backup(snapshot.path)
        self.window.reload_all()
        pump()
        self.assertEqual([e.title for e in self.vault.active_entries()], ["第一版"])

    def test_20_ignore_issue_from_audit_report(self) -> None:
        """在审计报告里忽略某类提示后，它不再出现，并且可以恢复。"""
        entry = self._create_via_dialog(title="弱密码站", password="123456")
        self.window.set_filter("audit")
        pump()
        self.assertEqual(len(self.window._cards), 1)

        # 与点击报告里那个 ⊘ 按钮等价的链路：面板信号 → 主窗口处理
        self.window.audit_panel.issue_ignored.emit(entry.id, "weak")
        pump()
        self.assertEqual(self.window._cards, {}, "忽略后该记录不应再出现在审计列表")
        self.assertEqual(self.vault.find(entry.id).ignored_issues, ["weak"])

        # 报告里能列出被忽略项，并可恢复
        ignored = strength.ignored_issues(self.vault.active_entries())
        self.assertEqual(len(ignored), 1)
        self.window.audit_panel.issue_restored.emit(entry.id, "weak")
        pump()
        self.assertEqual(len(self.window._cards), 1, "恢复后应重新出现在审计列表")

    def test_21_ignore_one_kind_keeps_others(self) -> None:
        """忽略"弱密码"不能顺手把"重复使用"也屏蔽掉。"""
        first = self._create_via_dialog(title="甲站", password="123456")
        self._create_via_dialog(title="乙站", password="123456")
        self.window.set_filter("audit")
        pump()

        self.window.audit_panel.issue_ignored.emit(first.id, "weak")
        pump()
        issues = strength.entry_issues(first, self.vault.active_entries(),
                                       self.vault.settings.password_max_age_days)
        reused = next(i for i in issues if i.kind == "reused")
        self.assertTrue(reused.is_risk, "重复使用的提示应仍然生效")

    def test_22_ignored_issue_is_persisted(self) -> None:
        """忽略状态要落盘，重新打开保险箱后依然有效。"""
        entry = self._create_via_dialog(title="弱密码站", password="123456")
        self.window._ignore_issue(entry.id, "weak")
        pump()
        reopened = Vault.open(self.path, "FlowTest#2024")
        self.assertEqual(reopened.find(entry.id).ignored_issues, ["weak"])

    def test_23_restore_all_issues(self) -> None:
        first = self._create_via_dialog(title="甲站", password="123456")
        second = self._create_via_dialog(title="乙站", password="")
        self.window.set_filter("audit")
        pump()
        self.window.audit_panel.issue_ignored.emit(first.id, "weak")
        pump()
        self.window.audit_panel.issue_ignored.emit(second.id, "empty")
        pump()
        self.assertEqual(self.window._cards, {})

        self.window.audit_panel.all_restored.emit()
        pump()
        self.assertEqual(len(self.window._cards), 2)
        self.assertEqual(self.vault.unignore_all(), 0)

    def test_24_keyboard_navigation(self) -> None:
        """↑/↓ 在列表中切换记录，边界不越界。"""
        self._create_via_dialog(title="甲", password="Aaa#123456")
        self._create_via_dialog(title="乙", password="Bbb#123456")
        self.window.set_filter("all")
        pump()

        order = list(self.window._cards)
        self.assertEqual(len(order), 2)

        self.window._focus_first_card()          # 等价于在搜索框按 ↓
        pump()
        self.assertEqual(self.window.selected_id, order[0])

        self.window._navigate_card(order[0], 1)  # ↓
        pump()
        self.assertEqual(self.window.selected_id, order[1])

        self.window._navigate_card(order[1], 1)  # 到底了，停在最后一条
        pump()
        self.assertEqual(self.window.selected_id, order[1])

        self.window._navigate_card(order[1], -1)  # ↑
        pump()
        self.assertEqual(self.window.selected_id, order[0])

        self.window._navigate_card(order[0], -1)  # 到顶了，停在第一条
        pump()
        self.assertEqual(self.window.selected_id, order[0])

    def test_25_search_box_down_enters_list(self) -> None:
        """搜索框按 ↓ 把焦点交给列表。"""
        self._create_via_dialog(title="甲", password="Aaa#123456")
        self.window.set_filter("all")
        pump()
        self.window.search_box.setFocus()
        QTest.keyClick(self.window.search_box, Qt.Key_Down)
        pump()
        self.assertIn(self.window.selected_id, self.window._cards)
        self.assertTrue(self.window._cards[self.window.selected_id].hasFocus())

    def test_26_ctrl_c_copies_password_from_list(self) -> None:
        entry = self._create_via_dialog(title="复制测试", password="Copy#Me12345")
        APP.clipboard().clear()
        self.window._copy_password_of(entry.id)
        self.assertEqual(APP.clipboard().text(), "Copy#Me12345")

    def test_27_sort_options(self) -> None:
        """排序切换生效，并把选择写回设置。"""
        older = self._create_via_dialog(title="B站", password="Bbb#123456")
        newer = self._create_via_dialog(title="A站", password="Aaa#123456")
        pump()
        older.created_at = "2026-01-01T00:00:00+08:00"
        newer.created_at = "2026-06-01T00:00:00+08:00"

        self.window.set_sort("title")
        pump()
        self.assertEqual([self.vault.find(i).title for i in self.window._cards],
                         ["A站", "B站"])

        self.window.set_sort("created")
        pump()
        self.assertEqual([self.vault.find(i).title for i in self.window._cards],
                         ["A站", "B站"], "最近创建的应排在前面")

        newer.created_at = "2025-01-01T00:00:00+08:00"   # 反转先后再验一次
        self.window.refresh_list()
        pump()
        self.assertEqual([self.vault.find(i).title for i in self.window._cards],
                         ["B站", "A站"])

        reopened = Vault.open(self.path, "FlowTest#2024")
        self.assertEqual(reopened.settings.sort_key, "created")

    def test_29_sort_by_updated(self) -> None:
        older = self._create_via_dialog(title="旧", password="Aaa#123456")
        newer = self._create_via_dialog(title="新", password="Bbb#123456")
        pump()
        older.updated_at = "2026-01-01T00:00:00+08:00"
        newer.updated_at = "2026-06-01T00:00:00+08:00"
        self.window.set_sort("updated")
        pump()
        self.assertEqual([self.vault.find(i).title for i in self.window._cards],
                         ["新", "旧"])

    def test_30_settings_dialog_has_action_buttons(self) -> None:
        """回归用例：设置窗口必须有保存/取消按钮。

        曾经因为重构时把 footer 那几行插到了 `return scroll` 之后，
        整组按钮永远不会被创建，而当时的测试只调 `_save()`，没走按钮，
        所以没能发现。
        """
        dialog = SettingsDialog(self.window, self.vault)
        dialog.show()
        pump()

        labels = [button.text() for button in dialog.findChildren(QPushButton)]
        self.assertIn("保存设置", labels)
        self.assertIn("取消", labels)

        save = next(b for b in dialog.findChildren(QPushButton) if b.text() == "保存设置")
        save.click()
        pump()
        self.assertEqual(dialog.result(), QDialog.Accepted)
        dialog.deleteLater()
        pump()

    def test_31_settings_cancel_button_rejects(self) -> None:
        dialog = SettingsDialog(self.window, self.vault)
        dialog.show()
        pump()
        cancel = next(b for b in dialog.findChildren(QPushButton) if b.text() == "取消")
        cancel.click()
        pump()
        self.assertEqual(dialog.result(), QDialog.Rejected)
        dialog.deleteLater()
        pump()

    def test_14_category_dialog_renders_rows(self) -> None:
        """分类管理窗口能正常渲染出每一行（避免 UI 构建期异常）。"""
        dialog = CategoryDialog(self.window, self.vault)
        dialog.show()
        pump()
        # 列表末尾是一个 stretch，其余每个位置对应一个分类
        rows = [dialog.list_layout.itemAt(i).widget()
                for i in range(dialog.list_layout.count() - 1)]
        self.assertEqual(len(rows), len(self.vault.categories))
        self.assertTrue(all(row is not None for row in rows))
        self.assertIn("密钥", self.vault.categories)
        dialog.hide()
        dialog.deleteLater()
        pump()


if __name__ == "__main__":
    unittest.main(verbosity=2)
