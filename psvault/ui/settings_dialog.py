"""设置窗口：外观、安全策略、数据导入导出与主密码维护。"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QUrl, Qt, Signal
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QApplication,
    QButtonGroup,
    QCheckBox,
    QDialog,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QScrollArea,
    QPushButton,
    QSpinBox,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from .. import __version__
from ..core import crypto, porting
from ..core.storage import Vault
from . import icons, widgets
from .theme import Theme
from .widgets import SecretLineEdit, text_button


class SettingsDialog(QDialog):
    """设置对话框。接受后由主窗口统一保存并刷新。"""

    data_changed = Signal()

    def __init__(self, parent: QWidget | None, vault: Vault) -> None:
        super().__init__(parent)
        self.vault = vault
        self.setWindowTitle("设置")
        self.setWindowIcon(icons.app_icon())
        self.setMinimumSize(600, 620)
        self.resize(620, 660)
        self.setModal(True)
        self._build_ui()

    # ------------------------------------------------------------ 界面

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(22, 20, 22, 16)
        root.setSpacing(14)

        title = QLabel("设置")
        title.setObjectName("PageTitle")
        root.addWidget(title)

        tabs = QTabWidget()
        tabs.addTab(self._scrollable(self._build_general_tab()), "常规")
        tabs.addTab(self._scrollable(self._build_security_tab()), "安全")
        tabs.addTab(self._scrollable(self._build_data_tab()), "数据")
        tabs.addTab(self._scrollable(self._build_about_tab()), "关于")
        root.addWidget(tabs, 1)

    def _scrollable(self, page: QWidget) -> QWidget:
        """给设置页套一层滚动区域。

        选项多起来之后内容会超过窗口高度，没有滚动区时 Qt 会把卡片压扁，
        出现文字与按钮互相重叠的情况。
        """
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setWidget(page)
        return scroll

        footer = QHBoxLayout()
        footer.addStretch(1)
        cancel = text_button("取消")
        cancel.clicked.connect(self.reject)
        footer.addWidget(cancel)
        save = text_button("保存设置", kind="Primary", icon_name="check",
                           token="accent_text", size=16)
        save.clicked.connect(self._save)
        footer.addWidget(save)
        root.addLayout(footer)

    def _card(self, caption: str = "") -> tuple[QFrame, QVBoxLayout]:
        """创建一个带可选标题的设置卡片。"""
        card = QFrame()
        card.setObjectName("Card")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(10)
        if caption:
            layout.addWidget(widgets.section_title(caption))
        return card, layout

    def _row(self, caption: str, widget: QWidget, description: str = "") -> QVBoxLayout:
        """一行设置：标题 + 控件 + 说明。"""
        layout = QVBoxLayout()
        layout.setSpacing(5)
        label = QLabel(caption)
        label.setObjectName("FieldLabel")
        layout.addWidget(label)
        layout.addWidget(widget)
        if description:
            layout.addWidget(widgets.hint_label(description))
        return layout

    # ------------------------------------------------------------ 常规

    def _build_general_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(4, 12, 4, 12)
        layout.setSpacing(14)

        # 保险箱名称
        card, card_layout = self._card("保险箱")
        self.vault_name_edit = QLineEdit()
        self.vault_name_edit.setMinimumHeight(36)
        self.vault_name_edit.setPlaceholderText("例如：我的密码库")
        self.vault_name_edit.setText(str(self.vault.meta.get("name") or ""))
        self.vault_name_edit.setClearButtonEnabled(True)
        card_layout.addLayout(self._row(
            "名称", self.vault_name_edit,
            "显示在窗口标题与侧栏，用于区分多个保险箱；留空则使用文件名。"))
        card_layout.addWidget(widgets.hint_label(f"当前文件：{self.vault.path}"))
        layout.addWidget(card)

        # 主题
        card, card_layout = self._card("外观")
        segment_bar = QFrame()
        segment_bar.setObjectName("SegmentBar")
        segment_layout = QHBoxLayout(segment_bar)
        segment_layout.setContentsMargins(4, 4, 4, 4)
        segment_layout.setSpacing(4)
        self.theme_group = QButtonGroup(self)
        for index, (key, label) in enumerate((("light", "浅色"), ("dark", "深色"))):
            button = QPushButton(label)
            button.setObjectName("Segment")
            button.setCheckable(True)
            button.setCursor(Qt.PointingHandCursor)
            button.setChecked(self.vault.settings.theme == key)
            self.theme_group.addButton(button, index)
            segment_layout.addWidget(button)
        self.theme_group.idClicked.connect(self._on_theme_clicked)
        card_layout.addWidget(segment_bar)
        card_layout.addWidget(widgets.hint_label(
            "两套主题均按同一套设计规范制作，切换后界面立即生效。"))
        layout.addWidget(card)

        # 自动锁定
        card, card_layout = self._card("自动锁定")
        self.auto_lock_spin = QSpinBox()
        self.auto_lock_spin.setRange(0, 120)
        self.auto_lock_spin.setSuffix(" 分钟")
        self.auto_lock_spin.setValue(self.vault.settings.auto_lock_minutes)
        self.auto_lock_spin.setSpecialValueText("不自动锁定")
        card_layout.addLayout(self._row(
            "空闲多久后自动锁定", self.auto_lock_spin,
            "锁定后需要重新输入主密码；设为 0 表示不自动锁定。"))

        self.lock_minimize_check = QCheckBox("窗口最小化时立即锁定")
        self.lock_minimize_check.setChecked(self.vault.settings.lock_on_minimize)
        card_layout.addWidget(self.lock_minimize_check)

        self.clipboard_spin = QSpinBox()
        self.clipboard_spin.setRange(0, 300)
        self.clipboard_spin.setSuffix(" 秒")
        self.clipboard_spin.setValue(self.vault.settings.clipboard_clear_seconds)
        self.clipboard_spin.setSpecialValueText("不清空")
        card_layout.addLayout(self._row(
            "复制密码后自动清空剪贴板", self.clipboard_spin,
            "避免密码长期停留在剪贴板中被其他程序读取。"))
        layout.addWidget(card)

        layout.addStretch(1)
        return page

    def _on_theme_clicked(self, index: int) -> None:
        """主题切换即时预览。"""
        name = "light" if index == 0 else "dark"
        theme = Theme.instance()
        if theme.palette.name != name:
            theme.set_theme(name)
            app = QApplication.instance()
            if app is not None:
                theme.apply(app)
        self.vault.settings.theme = name

    # ------------------------------------------------------------ 安全

    def _build_security_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(4, 12, 4, 12)
        layout.setSpacing(14)

        card, card_layout = self._card("密码老化提醒")
        self.age_spin = QSpinBox()
        self.age_spin.setRange(0, 3650)
        self.age_spin.setSuffix(" 天")
        self.age_spin.setValue(self.vault.settings.password_max_age_days)
        self.age_spin.setSpecialValueText("不提醒")
        card_layout.addLayout(self._row(
            "超过该天数未修改的密码视为过期", self.age_spin,
            "过期密码会出现在「安全审计」中，提醒你及时更换。"))
        self.history_spin = QSpinBox()
        self.history_spin.setRange(0, 50)
        self.history_spin.setSuffix(" 条")
        self.history_spin.setValue(self.vault.settings.history_limit)
        card_layout.addLayout(self._row(
            "每条记录保留的历史密码数量", self.history_spin,
            "修改密码时旧密码会自动存入历史，方便找回。"))
        layout.addWidget(card)

        # 修改主密码
        card, card_layout = self._card("修改主密码")
        self.current_password = SecretLineEdit()
        self.current_password.setPlaceholderText("当前主密码")
        self.new_password = SecretLineEdit()
        self.new_password.setPlaceholderText("新主密码（至少 8 位）")
        self.confirm_password = SecretLineEdit()
        self.confirm_password.setPlaceholderText("再次输入新主密码")
        for edit in (self.current_password, self.new_password, self.confirm_password):
            edit.setMinimumHeight(36)
            card_layout.addWidget(edit)
        self.password_message = QLabel("")
        self.password_message.setObjectName("Faint")
        self.password_message.setWordWrap(True)
        card_layout.addWidget(self.password_message)

        change_row = QHBoxLayout()
        change_row.addStretch(1)
        change_button = text_button("修改主密码", icon_name="key", size=15)
        change_button.clicked.connect(self._change_master_password)
        change_row.addWidget(change_button)
        card_layout.addLayout(change_row)
        card_layout.addWidget(widgets.hint_label(
            "修改主密码会用新的密钥重新加密整个文件，数据不会丢失。"))
        layout.addWidget(card)

        layout.addStretch(1)
        return page

    def _change_master_password(self) -> None:
        current = self.current_password.text()
        new = self.new_password.text()
        confirm = self.confirm_password.text()
        if not current or not new:
            self._password_msg("请填写当前主密码与新主密码", danger=True)
            return
        if len(new) < 8:
            self._password_msg("新主密码至少需要 8 位", danger=True)
            return
        if new != confirm:
            self._password_msg("两次输入的新密码不一致", danger=True)
            return
        try:
            Vault.open(self.vault.path, current)   # 验证当前主密码
        except crypto.InvalidPassword:
            self._password_msg("当前主密码不正确", danger=True)
            return
        except crypto.VaultError as exc:
            self._password_msg(str(exc), danger=True)
            return

        self.vault.change_master_password(new)
        self.current_password.clear()
        self.new_password.clear()
        self.confirm_password.clear()
        self._password_msg("✓  主密码已更新，下次解锁请使用新密码", danger=False)

    def _password_msg(self, text: str, *, danger: bool) -> None:
        self.password_message.setText(text)
        self.password_message.setObjectName("Danger" if danger else "Success")
        widgets.restyle(self.password_message)

    # ------------------------------------------------------------ 数据

    def _build_data_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(4, 12, 4, 12)
        layout.setSpacing(14)

        card, card_layout = self._card("备份与导出")
        encrypted = text_button("导出加密备份…", icon_name="shield-check", size=15)
        encrypted.clicked.connect(self._export_encrypted)
        card_layout.addWidget(encrypted)
        card_layout.addWidget(widgets.hint_label(
            "备份文件同样是加密的，可以安全地存放到网盘或 U 盘。"))

        plain = text_button("导出 CSV（明文）…", icon_name="download", size=15)
        plain.clicked.connect(self._export_csv)
        card_layout.addWidget(plain)
        card_layout.addWidget(widgets.hint_label(
            "CSV 是明文格式，便于导入其他密码管理器，请勿长期留存。"))
        layout.addWidget(card)

        card, card_layout = self._card("导入")
        import_button = text_button("从 CSV / JSON 导入…", icon_name="upload", size=15)
        import_button.clicked.connect(self._import_data)
        card_layout.addWidget(import_button)
        card_layout.addWidget(widgets.hint_label(
            "支持 Chrome、Edge、Bitwarden、LastPass 等导出的 CSV，"
            "以及本程序导出的 JSON；同名同账号的记录会自动跳过。"))
        layout.addWidget(card)

        layout.addWidget(self._build_backup_card())

        card, card_layout = self._card("数据文件")
        path_label = QLabel(str(self.vault.path))
        path_label.setObjectName("Mono")
        path_label.setWordWrap(True)
        path_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        card_layout.addWidget(path_label)
        open_dir = text_button("打开所在文件夹", icon_name="folder", size=15)
        open_dir.clicked.connect(self._open_folder)
        card_layout.addWidget(open_dir)
        layout.addWidget(card)

        layout.addStretch(1)
        return page

    def _build_backup_card(self) -> QFrame:
        """备份与恢复：自动备份策略 + 备份列表 + 一键恢复。"""
        card, card_layout = self._card("备份与恢复")

        self.backup_check = QCheckBox("每次保存前自动留一份历史备份")
        self.backup_check.setChecked(self.vault.settings.auto_backup)
        card_layout.addWidget(self.backup_check)

        self.backup_keep_spin = QSpinBox()
        self.backup_keep_spin.setRange(1, 50)
        self.backup_keep_spin.setSuffix(" 份")
        self.backup_keep_spin.setValue(self.vault.settings.backup_keep)
        card_layout.addLayout(self._row(
            "每个位置保留", self.backup_keep_spin,
            "超出份数的旧备份会自动清理，不会无限占用磁盘。"))

        self.external_check = QCheckBox("同时在「文档」目录保留一份（推荐）")
        self.external_check.setChecked(self.vault.settings.backup_external_enabled)
        self.external_check.stateChanged.connect(self._on_external_toggled)
        card_layout.addWidget(self.external_check)

        self.external_label = QLabel(self._external_dir_text())
        self.external_label.setObjectName("Faint")
        self.external_label.setWordWrap(True)
        card_layout.addWidget(self.external_label)

        external_row = QHBoxLayout()
        external_row.setSpacing(8)
        open_external = text_button("打开该文件夹", icon_name="folder", size=15)
        open_external.clicked.connect(self._open_external_dir)
        external_row.addWidget(open_external)
        choose_external = text_button("更改位置…", icon_name="pencil", size=15)
        choose_external.clicked.connect(self._choose_external_dir)
        external_row.addWidget(choose_external)
        external_row.addStretch(1)
        card_layout.addLayout(external_row)

        card_layout.addWidget(widgets.hint_label(
            "程序目录和文档目录各存一份：即使整个程序文件夹被误删，"
            "文档里的备份仍然可以恢复数据。备份文件同样是加密的。"))

        card_layout.addWidget(widgets.divider())
        card_layout.addWidget(widgets.section_title("历史备份"))

        self.backup_list = QListWidget()
        self.backup_list.setFixedHeight(118)
        card_layout.addWidget(self.backup_list)

        action_row = QHBoxLayout()
        action_row.setSpacing(8)
        backup_now = text_button("立即备份", icon_name="shield-check", size=15)
        backup_now.clicked.connect(self._backup_now)
        action_row.addWidget(backup_now)
        self.restore_button = text_button("恢复选中备份", kind="Danger",
                                          icon_name="restore", token="danger", size=15)
        self.restore_button.clicked.connect(self._restore_selected)
        action_row.addWidget(self.restore_button)
        action_row.addStretch(1)
        card_layout.addLayout(action_row)

        self._refresh_backup_list()
        return card

    def _external_dir_text(self) -> str:
        manager = self.vault.backup_manager()
        if manager.external_dir is None:
            return "外部备份：已关闭"
        return f"外部备份位置：{manager.external_dir}"

    def _refresh_backup_list(self) -> None:
        """刷新备份列表（本地 + 外部，按时间倒序）。"""
        self.backup_list.clear()
        backups = self.vault.backup_manager().list()
        if not backups:
            item = QListWidgetItem("还没有备份——保存一次记录后就会出现")
            item.setFlags(Qt.NoItemFlags)
            self.backup_list.addItem(item)
            self.restore_button.setEnabled(False)
            return

        self.restore_button.setEnabled(True)
        for info in backups[:30]:
            entry = QListWidgetItem(
                f"{info.location}　{info.display_time()}　{info.display_size()}")
            entry.setData(Qt.UserRole, str(info.path))
            entry.setToolTip(str(info.path))
            self.backup_list.addItem(entry)
        self.backup_list.setCurrentRow(0)

    def _on_external_toggled(self) -> None:
        self.external_label.setText(
            self._external_dir_text() if self.external_check.isChecked()
            else "外部备份：已关闭")

    def _open_external_dir(self) -> None:
        manager = self.vault.backup_manager()
        target = manager.external_dir
        if target is None:
            QMessageBox.information(self, "外部备份已关闭", "请先勾选上方的选项。")
            return
        target.mkdir(parents=True, exist_ok=True)
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(target)))

    def _choose_external_dir(self) -> None:
        selected = QFileDialog.getExistingDirectory(
            self, "选择外部备份目录", str(self.vault.backup_manager().external_dir
                                          or self.vault.path.parent))
        if not selected:
            return
        self.vault.settings.backup_external_dir = selected
        self.vault.settings.backup_external_enabled = True
        self.external_check.setChecked(True)
        self.external_label.setText(self._external_dir_text())

    def _apply_backup_settings(self) -> None:
        """把界面上的备份选项写回设置。"""
        settings = self.vault.settings
        settings.auto_backup = self.backup_check.isChecked()
        settings.backup_keep = self.backup_keep_spin.value()
        settings.backup_external_enabled = self.external_check.isChecked()

    def _backup_now(self) -> None:
        self._apply_backup_settings()
        self.vault.save()
        written = self.vault.backup_manager().backup(force=True)
        self._refresh_backup_list()
        if written:
            QMessageBox.information(
                self, "备份完成",
                "已生成 %d 份备份：\n%s" % (len(written), "\n".join(str(p) for p in written)))
        else:
            QMessageBox.warning(self, "备份失败", "没有写出任何备份文件，请检查目录权限。")

    def _restore_selected(self) -> None:
        item = self.backup_list.currentItem()
        if item is None:
            return
        source = item.data(Qt.UserRole)
        if not source:
            return
        answer = QMessageBox.warning(
            self, "从备份恢复",
            "将用这份备份覆盖当前保险箱，当前内容会先自动另存一份。\n\n"
            f"{source}\n\n确定继续吗？",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if answer != QMessageBox.Yes:
            return
        try:
            self.vault.restore_backup(source)
        except crypto.InvalidPassword:
            QMessageBox.warning(
                self, "无法直接恢复",
                "这份备份是用**旧的主密码**加密的，本程序无法自动读取。\n\n"
                "文件已经覆盖回去了，请关闭程序后用那份备份对应的主密码重新打开。")
            self.data_changed.emit()
            self.accept()
            return
        except (OSError, crypto.VaultError, ValueError) as exc:
            QMessageBox.critical(self, "恢复失败", str(exc))
            return
        self.data_changed.emit()
        QMessageBox.information(self, "恢复完成", "已从备份恢复，界面将刷新为备份中的数据。")
        self.accept()

    def _export_encrypted(self) -> None:
        default = str(self.vault.path.with_name(
            self.vault.path.stem + "-备份" + self.vault.path.suffix))
        selected, _ = QFileDialog.getSaveFileName(
            self, "导出加密备份", default, "密码保险箱 (*.psvault)")
        if not selected:
            return
        target = Path(selected)
        if target.suffix.lower() != crypto.VAULT_EXTENSION:
            target = target.with_suffix(crypto.VAULT_EXTENSION)
        try:
            self.vault.export_encrypted(target)
        except OSError as exc:
            QMessageBox.critical(self, "导出失败", str(exc))
            return
        QMessageBox.information(self, "导出成功",
                                f"已导出加密备份：\n{target}\n\n使用当前主密码即可打开。")

    def _export_csv(self) -> None:
        answer = QMessageBox.warning(
            self, "导出为明文 CSV",
            "CSV 文件中的密码是完全明文的，任何拿到该文件的人都能直接看到。\n\n"
            "确定要继续吗？",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if answer != QMessageBox.Yes:
            return
        selected, _ = QFileDialog.getSaveFileName(
            self, "导出 CSV", str(self.vault.path.with_suffix(".csv")), "CSV 文件 (*.csv)")
        if not selected:
            return
        try:
            count = porting.export_csv(self.vault.active_entries(), selected)
        except OSError as exc:
            QMessageBox.critical(self, "导出失败", str(exc))
            return
        QMessageBox.information(self, "导出成功", f"已导出 {count} 条记录到：\n{selected}")

    def _import_data(self) -> None:
        selected, _ = QFileDialog.getOpenFileName(
            self, "导入数据", str(self.vault.path.parent),
            "支持的文件 (*.csv *.json);;CSV 文件 (*.csv);;JSON 文件 (*.json);;所有文件 (*)")
        if not selected:
            return
        try:
            entries = porting.import_file(selected)
        except (OSError, ValueError) as exc:
            QMessageBox.critical(self, "导入失败", str(exc))
            return
        except Exception as exc:  # noqa: BLE001 - 解析异常统一提示
            QMessageBox.critical(self, "导入失败", f"文件解析失败：{exc}")
            return

        if not entries:
            QMessageBox.information(self, "没有可导入的内容", "未在该文件中找到记录。")
            return
        answer = QMessageBox.question(
            self, "确认导入", f"解析到 {len(entries)} 条记录，是否导入？\n同名同账号的记录会被跳过。",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)
        if answer != QMessageBox.Yes:
            return
        added = self.vault.import_entries(entries)
        self.vault.save()
        self.data_changed.emit()
        QMessageBox.information(self, "导入完成",
                                f"成功导入 {added} 条记录，跳过 {len(entries) - added} 条重复记录。")

    def _open_folder(self) -> None:
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.vault.path.parent)))

    # ------------------------------------------------------------ 关于

    def _build_about_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(4, 12, 4, 12)
        layout.setSpacing(14)

        card, card_layout = self._card("")
        header = QHBoxLayout()
        logo = QLabel()
        logo.setPixmap(icons.build_logo(Theme.instance().hex("accent"), 40))
        header.addWidget(logo)
        text = QVBoxLayout()
        text.setSpacing(2)
        name = QLabel("密码保险箱")
        name.setObjectName("PageTitle")
        text.addWidget(name)
        version = QLabel(f"版本 {__version__}　·　本地加密，无网络传输")
        version.setObjectName("Faint")
        text.addWidget(version)
        header.addLayout(text)
        header.addStretch(1)
        card_layout.addLayout(header)
        layout.addWidget(card)

        card, card_layout = self._card("加密方案")
        details = [
            ("密钥派生", "scrypt（N=32768, r=8, p=1，加盐），主密码不落盘"),
            ("数据加密", "AES-256-GCM 认证加密，头部参数参与完整性校验"),
            ("存储位置", "仅保存在本机文件，程序不会发起任何网络请求"),
            ("剪贴板", "复制的密码可按设置自动清空"),
        ]
        for caption, value in details:
            row = QHBoxLayout()
            row.setSpacing(10)
            label = QLabel(caption)
            label.setObjectName("FieldLabel")
            label.setFixedWidth(72)
            row.addWidget(label)
            value_label = QLabel(value)
            value_label.setWordWrap(True)
            row.addWidget(value_label, 1)
            card_layout.addLayout(row)
        layout.addWidget(card)

        card, card_layout = self._card("忘记主密码怎么办")
        card_layout.addWidget(widgets.hint_label(
            "主密码是解密数据的唯一钥匙，程序没有保存它的任何副本，因此无法找回。"
            "请务必牢记，并定期导出加密备份。"))
        layout.addWidget(card)

        layout.addStretch(1)
        return page

    # ------------------------------------------------------------ 保存

    def _save(self) -> None:
        self.vault.set_name(self.vault_name_edit.text())
        settings = self.vault.settings
        settings.auto_lock_minutes = self.auto_lock_spin.value()
        settings.clipboard_clear_seconds = self.clipboard_spin.value()
        settings.lock_on_minimize = self.lock_minimize_check.isChecked()
        settings.password_max_age_days = self.age_spin.value()
        settings.history_limit = self.history_spin.value()
        settings.theme = "light" if self.theme_group.checkedId() == 0 else "dark"
        self._apply_backup_settings()
        try:
            self.vault.save()
        except (OSError, crypto.VaultError) as exc:
            QMessageBox.critical(self, "保存失败", str(exc))
            return
        self.accept()
