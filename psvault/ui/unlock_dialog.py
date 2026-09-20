"""解锁 / 创建保险箱窗口：程序启动后的第一屏。"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QSettings, Qt, QTimer
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QVBoxLayout,
    QWidget,
)

from ..core import crypto, strength
from ..core.backup import BackupManager, default_external_dir
from ..core.storage import (
    DEFAULT_DATA_DIR,
    Vault,
    default_vault_path,
    sanitize_filename,
)
from . import icons, widgets
from .theme import Theme
from .widgets import SecretLineEdit, StrengthMeter, text_button

SETTINGS_ORG = "PSVault"
SETTINGS_APP = "密码保险箱"
MIN_MASTER_LENGTH = 8


def shorten_path(text: str, limit: int = 44) -> str:
    """长路径折叠中间层级，保留盘符与最后两级目录。"""
    if len(text) <= limit:
        return text
    parts = [p for p in text.replace("/", "\\").split("\\") if p]
    if len(parts) < 3:
        return text
    driver = parts[0] if parts[0].endswith(":") else ""
    tail = "\\".join(parts[-2:])
    return f"{driver}\\…\\{tail}" if driver else f"…\\{tail}"


def last_vault_path() -> Path:
    """读取上次使用的保险箱路径。"""
    settings = QSettings(SETTINGS_ORG, SETTINGS_APP)
    stored = settings.value("vault_path", "", type=str)
    if stored:
        return Path(stored)
    return default_vault_path()


def remember_vault_path(path: Path) -> None:
    """记住保险箱路径，下次启动自动定位。"""
    QSettings(SETTINGS_ORG, SETTINGS_APP).setValue("vault_path", str(path))


class UnlockDialog(QDialog):
    """主密码解锁窗口，同时承担首次创建保险箱的职责。"""

    def __init__(self, parent: QWidget | None = None, path: Path | None = None) -> None:
        super().__init__(parent)
        self.vault: Vault | None = None
        self.path = Path(path) if path else last_vault_path()
        self.mode = "unlock" if self.path.exists() else "create"
        self._path_touched = path is not None    # 用户是否已手动指定过文件位置

        self.setWindowTitle("密码保险箱")
        self.setWindowIcon(icons.app_icon())
        self.setFixedWidth(460)
        self.setModal(True)
        self._build_ui()
        self._apply_mode()
        QTimer.singleShot(120, self.password_edit.setFocus)

    # ------------------------------------------------------------ 界面搭建

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(28, 28, 28, 24)
        root.setSpacing(0)
        root.addStretch(1)

        card = QFrame()
        card.setObjectName("Card")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(34, 34, 34, 28)
        card_layout.setSpacing(0)

        # 标志与标题
        self.logo_label = QLabel()
        self.logo_label.setPixmap(icons.build_logo(Theme.instance().hex("accent"), 42))
        self.logo_label.setAlignment(Qt.AlignCenter)
        card_layout.addWidget(self.logo_label)
        card_layout.addSpacing(16)

        self.title_label = QLabel("解锁保险箱")
        self.title_label.setObjectName("PageTitle")
        self.title_label.setAlignment(Qt.AlignCenter)
        card_layout.addWidget(self.title_label)

        self.subtitle_label = QLabel("输入主密码以访问你的账号数据")
        self.subtitle_label.setObjectName("Faint")
        self.subtitle_label.setAlignment(Qt.AlignCenter)
        self.subtitle_label.setWordWrap(True)
        card_layout.addSpacing(6)
        card_layout.addWidget(self.subtitle_label)
        card_layout.addSpacing(24)

        # 保险箱名称（仅创建模式显示）
        self.name_caption = QLabel("保险箱名称")
        self.name_caption.setObjectName("FieldLabel")
        card_layout.addWidget(self.name_caption)
        card_layout.addSpacing(6)
        self.name_edit = QLineEdit()
        self.name_edit.setMinimumHeight(40)
        self.name_edit.setPlaceholderText("例如：我的密码库（留空则使用文件名）")
        self.name_edit.setClearButtonEnabled(True)
        self.name_edit.textChanged.connect(self._on_name_changed)
        card_layout.addWidget(self.name_edit)
        card_layout.addSpacing(14)

        # 主密码
        password_caption = QLabel("主密码")
        password_caption.setObjectName("FieldLabel")
        card_layout.addWidget(password_caption)
        card_layout.addSpacing(6)
        self.password_edit = SecretLineEdit()
        self.password_edit.setMinimumHeight(40)
        self.password_edit.setPlaceholderText("请输入主密码")
        self.password_edit.returnPressed.connect(self._submit)
        self.password_edit.textChanged.connect(self._on_text_changed)
        card_layout.addWidget(self.password_edit)

        # 确认密码（仅创建模式）
        self.confirm_caption = QLabel("确认主密码")
        self.confirm_caption.setObjectName("FieldLabel")
        self.confirm_edit = SecretLineEdit()
        self.confirm_edit.setMinimumHeight(40)
        self.confirm_edit.setPlaceholderText("请再次输入")
        self.confirm_edit.returnPressed.connect(self._submit)
        self.confirm_edit.textChanged.connect(self._on_text_changed)
        card_layout.addSpacing(14)
        card_layout.addWidget(self.confirm_caption)
        card_layout.addSpacing(6)
        card_layout.addWidget(self.confirm_edit)

        # 强度条（仅创建模式）
        self.strength_meter = StrengthMeter()
        self.strength_hint = QLabel("")
        self.strength_hint.setObjectName("Faint")
        card_layout.addSpacing(10)
        card_layout.addWidget(self.strength_meter)
        card_layout.addSpacing(6)
        card_layout.addWidget(self.strength_hint)

        # 错误提示（固定高度占位，出错时不会引起布局跳动）
        self.error_label = QLabel("")
        self.error_label.setObjectName("Danger")
        self.error_label.setWordWrap(True)
        self.error_label.setMinimumHeight(18)
        card_layout.addSpacing(8)
        card_layout.addWidget(self.error_label)

        card_layout.addSpacing(4)
        self.primary_button = text_button("解锁", kind="Primary", icon_name="unlock",
                                          token="accent_text", size=17)
        self.primary_button.setMinimumHeight(40)
        self.primary_button.clicked.connect(self._submit)
        card_layout.addWidget(self.primary_button)

        card_layout.addSpacing(16)
        card_layout.addWidget(widgets.divider())
        card_layout.addSpacing(14)

        # 底部：路径与切换操作
        self.path_label = QLabel()
        self.path_label.setObjectName("Faint")
        self.path_label.setWordWrap(True)
        self.path_label.setAlignment(Qt.AlignCenter)
        card_layout.addWidget(self.path_label)

        # 备份状态 + 恢复入口：文件万一被改动或误删，这里能救回来
        backup_row = QHBoxLayout()
        backup_row.setSpacing(6)
        backup_row.addStretch(1)
        self.backup_label = QLabel("")
        self.backup_label.setObjectName("Faint")
        backup_row.addWidget(self.backup_label)
        self.restore_link = text_button("从备份恢复…", kind="Link")
        self.restore_link.clicked.connect(self._restore_from_backup)
        backup_row.addWidget(self.restore_link)
        backup_row.addStretch(1)
        card_layout.addSpacing(4)
        card_layout.addLayout(backup_row)

        switch_row = QHBoxLayout()
        switch_row.setSpacing(14)
        switch_row.addStretch(1)
        self.switch_button = text_button("", kind="Link")
        self.switch_button.clicked.connect(self._toggle_mode)
        switch_row.addWidget(self.switch_button)
        separator = QLabel("·")
        separator.setObjectName("Faint")
        switch_row.addWidget(separator)
        self.browse_button = text_button("选择其他保险箱…", kind="Link")
        self.browse_button.clicked.connect(self._browse)
        switch_row.addWidget(self.browse_button)
        switch_row.addStretch(1)
        card_layout.addSpacing(6)
        card_layout.addLayout(switch_row)

        root.addWidget(card)
        root.addStretch(1)

        # 底部声明
        notice = QLabel("所有数据仅以加密形式保存在本机，主密码不会以任何形式存储")
        notice.setObjectName("Faint")
        notice.setAlignment(Qt.AlignCenter)
        notice.setWordWrap(True)
        root.addWidget(notice)

    def _fit_height(self) -> None:
        """按当前模式的内容量调整窗口高度，避免留下大片空白。"""
        self.layout().activate()
        height = max(400, min(660, self.sizeHint().height()))
        self.setFixedHeight(height)
        self._center()

    def _center(self) -> None:
        screen = QGuiApplication.primaryScreen()
        if screen is None:
            return
        geometry = screen.availableGeometry()
        self.move(geometry.center().x() - self.width() // 2,
                  geometry.center().y() - self.height() // 2)

    # ------------------------------------------------------------ 状态切换

    def _apply_mode(self) -> None:
        """根据当前模式调整文案与可见控件。"""
        creating = self.mode == "create"

        self.title_label.setText("创建保险箱" if creating else "解锁保险箱")
        if creating:
            self.subtitle_label.setText("给保险箱起个名字，再设置一个只属于你的主密码")
            self.primary_button.setText("创建保险箱")
            self.primary_button.setIcon(icons.icon("shield-check", "accent_text", 17))
            self.switch_button.setText("已有保险箱？改为解锁")
            self.password_edit.setPlaceholderText("设置主密码（至少 8 位）")
        else:
            self.subtitle_label.setText("输入主密码以访问你的账号数据")
            self.primary_button.setText("解锁")
            self.primary_button.setIcon(icons.icon("unlock", "accent_text", 17))
            self.switch_button.setText("新建一个保险箱")

        for widget in (self.name_caption, self.name_edit, self.confirm_caption,
                       self.confirm_edit, self.strength_meter, self.strength_hint):
            widget.setVisible(creating)
        self.layout().invalidate()      # 让隐藏/显示后的尺寸重新参与计算

        self._update_path_label()
        self.error_label.setText("")
        self.password_edit.clear()
        self.confirm_edit.clear()
        self.strength_meter.set_state(0, "")
        self.strength_hint.setText("")
        self._fit_height()
        if creating:
            self.name_edit.setFocus()
        else:
            self.password_edit.setFocus()

    def _update_path_label(self) -> None:
        """刷新底部的数据文件显示。"""
        is_default_dir = self.path.parent == DEFAULT_DATA_DIR
        location = "默认位置" if is_default_dir else shorten_path(str(self.path.parent))
        self.path_label.setText(f"数据文件：{self.path.name}\n{location}")
        self.path_label.setToolTip(str(self.path))
        self._refresh_backup_hint()

    # ------------------------------------------------------------ 备份

    def _backup_manager(self) -> BackupManager:
        """解锁阶段还读不到保险箱内的设置，外部备份目录取默认位置。"""
        return BackupManager(self.path, external_dir=default_external_dir())

    def _refresh_backup_hint(self) -> None:
        """在解锁界面显示备份状况，让用户知道数据有兜底。"""
        if not self.path.exists():
            self.backup_label.setText("")
            self.restore_link.hide()
            self._fit_height()
            return

        backups = self._backup_manager().list()
        if not backups:
            self.backup_label.setText("尚无备份")
            self.restore_link.hide()
        else:
            self.backup_label.setText(
                f"备份 {len(backups)} 份　·　最近 {backups[0].display_time()}")
            self.restore_link.show()
        self._fit_height()

    def _restore_from_backup(self) -> None:
        """从备份恢复损坏 / 丢失的保险箱文件。"""
        manager = self._backup_manager()
        backups = manager.list()
        if not backups:
            QMessageBox.information(self, "没有备份", "没有找到可用的备份文件。")
            return

        labels = [f"{info.location}　{info.display_time()}　{info.display_size()}"
                  for info in backups]
        label, ok = QInputDialog.getItem(
            self, "从备份恢复", "选择要恢复的备份：", labels, 0, False)
        if not ok:
            return
        info = backups[labels.index(label)]

        answer = QMessageBox.warning(
            self, "确认恢复",
            f"将用这份备份覆盖当前保险箱文件：\n{info.path}\n\n"
            "当前文件会先自动另存一份，确定继续吗？",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if answer != QMessageBox.Yes:
            return

        try:
            manager.restore(info.path)
        except OSError as exc:
            QMessageBox.critical(self, "恢复失败", str(exc))
            return

        QMessageBox.information(
            self, "恢复完成",
            "已从备份恢复。\n\n请输入这份备份对应的主密码解锁"
            "（如果后来改过主密码，请用改之前的那个）。")
        self.error_label.setText("")
        self.password_edit.clear()
        self._refresh_backup_hint()
        self.password_edit.setFocus()

    def _on_name_changed(self, text: str) -> None:
        """创建时按名称推荐同名的默认文件名（用户手动选过位置则不再改动）。"""
        self.error_label.setText("")
        if self.mode != "create" or self._path_touched:
            return
        name = text.strip()
        if name:
            self.path = DEFAULT_DATA_DIR / f"{sanitize_filename(name)}{crypto.VAULT_EXTENSION}"
        else:
            self.path = default_vault_path()
        self._update_path_label()

    def _toggle_mode(self) -> None:
        if self.mode == "unlock":
            self.mode = "create"
            if self.path.exists():
                # 新建时避免覆盖已有文件，自动另取名
                self.path = self.path.with_name("vault-新建" + self.path.suffix)
        else:
            self.mode = "unlock" if self.path.exists() else "create"
        self._apply_mode()

    def _browse(self) -> None:
        """选择或新建保险箱文件。"""
        start = str(self.path if self.path.exists() else self.path.parent)
        selected, _ = QFileDialog.getOpenFileName(
            self, "选择保险箱文件", start, "密码保险箱 (*.psvault);;所有文件 (*)"
        )
        if selected:
            self.path = Path(selected)
            self.mode = "unlock"
            self._path_touched = True
            remember_vault_path(self.path)
            self._apply_mode()
            return
        # 没有现成文件时，允许新建
        selected, _ = QFileDialog.getSaveFileName(
            self, "新建保险箱文件", str(self.path), "密码保险箱 (*.psvault)"
        )
        if selected:
            target = Path(selected)
            if target.suffix.lower() != crypto.VAULT_EXTENSION:
                target = target.with_suffix(crypto.VAULT_EXTENSION)
            self.path = target
            self.mode = "create"
            self._path_touched = True
            self._apply_mode()

    # ------------------------------------------------------------ 输入反馈

    def _on_text_changed(self) -> None:
        self.error_label.setText("")
        if self.mode != "create":
            return
        report = strength.evaluate(self.password_edit.text())
        if not self.password_edit.text():
            self.strength_meter.set_state(0, "")
            self.strength_hint.setText("")
        else:
            self.strength_meter.set_state(report.score, report.label)
            self.strength_hint.setText(f"强度：{report.label}　·　约 {report.entropy_bits:.0f} 位熵")

    def _show_error(self, message: str) -> None:
        self.error_label.setText("⚠  " + message)

    def _set_busy(self, busy: bool, text: str = "") -> None:
        self.primary_button.setEnabled(not busy)
        if busy:
            self.primary_button.setText(text)
            QApplication.processEvents()
        else:
            self._apply_button_text()

    def _apply_button_text(self) -> None:
        creating = self.mode == "create"
        self.primary_button.setText("创建保险箱" if creating else "解锁")
        self.primary_button.setIcon(icons.icon(
            "shield-check" if creating else "unlock", "accent_text", 17))

    # ------------------------------------------------------------ 提交

    def _submit(self) -> None:
        password = self.password_edit.text()
        if self.mode == "unlock":
            self._do_unlock(password)
        else:
            self._do_create(password)

    def _do_unlock(self, password: str) -> None:
        if not password:
            self._show_error("请输入主密码")
            return
        self._set_busy(True, "正在验证…")
        try:
            vault = Vault.open(self.path, password)
        except crypto.InvalidPassword:
            # 认证失败有两种可能：密码输错，或文件被改动过（GCM 会一并报错）。
            # 有备份时把恢复入口指出来，避免用户以为数据已经没了。
            self._set_busy(False)
            backups = self._backup_manager().list()
            if backups:
                self._show_error(
                    f"主密码错误。如果确认密码无误，文件可能已被改动——"
                    f"可点下方「从备份恢复」找回（最近 {backups[0].display_time()}）")
            else:
                self._show_error("主密码错误，请重试")
            self.password_edit.selectAll()
            self.password_edit.setFocus()
            return
        except crypto.VaultError as exc:
            self._set_busy(False)
            backups = self._backup_manager().list()
            if backups:
                self._show_error(f"{exc}（检测到 {len(backups)} 份备份，可点下方「从备份恢复」）")
            else:
                self._show_error(str(exc))
            return
        except OSError as exc:
            self._set_busy(False)
            self._show_error(f"文件读取失败：{exc}")
            return

        # 这里不再人为 sleep：scrypt 本身要 0.1~0.3 秒，不可能"过快返回"，
        # 那段延时既不会触发、又会白白阻塞界面。
        self.vault = vault
        remember_vault_path(self.path)
        self.accept()

    def _do_create(self, password: str) -> None:
        confirm = self.confirm_edit.text()
        if len(password) < MIN_MASTER_LENGTH:
            self._show_error(f"主密码至少需要 {MIN_MASTER_LENGTH} 位")
            return
        if password != confirm:
            self._show_error("两次输入的密码不一致")
            self.confirm_edit.setFocus()
            return
        report = strength.evaluate(password)
        if report.score <= 1:
            self._show_error("这个主密码太弱了，建议至少 12 位并混合大小写、数字与符号")
            return
        if self.path.exists():
            self._show_error("该位置已存在保险箱文件，请换一个名称或文件名")
            return

        self._set_busy(True, "正在创建…")
        try:
            vault = Vault.create(self.path, password, name=self.name_edit.text().strip())
        except OSError as exc:
            self._set_busy(False)
            self._show_error(f"创建失败：{exc}")
            return
        self.vault = vault
        remember_vault_path(self.path)
        self.accept()
