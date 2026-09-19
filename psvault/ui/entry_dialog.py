"""新增 / 编辑账号记录对话框。"""

from __future__ import annotations

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from ..core import strength, totp
from ..core.models import DEFAULT_CATEGORY, Entry
from ..core.storage import Vault
from . import clipboard as clipboard_utils
from . import icons, widgets
from .generator_dialog import GeneratorDialog
from .widgets import IconButton, SecretLineEdit, StrengthMeter, text_button


class EntryDialog(QDialog):
    """编辑一条记录。`data` 为保存时交给调用方写入保险箱的字段字典。"""

    def __init__(self, parent: QWidget | None, vault: Vault, entry: Entry | None = None,
                 default_category: str = DEFAULT_CATEGORY,
                 default_tags: list[str] | None = None) -> None:
        super().__init__(parent)
        self.vault = vault
        self.entry = entry
        self.is_new = entry is None
        self.data: dict = {}
        self.new_password: str | None = None
        self._original_password = entry.password if entry else ""

        self.setWindowTitle("新建记录" if self.is_new else "编辑记录")
        self.setWindowIcon(icons.app_icon())
        self.setMinimumSize(560, 620)
        self.resize(580, 700)
        self.setModal(True)

        self._build_ui(default_category, default_tags or [])
        self._load_entry()
        QTimer.singleShot(80, self.title_edit.setFocus)

    # ------------------------------------------------------------ 界面

    def _build_ui(self, default_category: str, default_tags: list[str]) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        header = QWidget()
        header_layout = QVBoxLayout(header)
        header_layout.setContentsMargins(24, 20, 24, 12)
        header_layout.setSpacing(4)
        title = QLabel("新建记录" if self.is_new else "编辑记录")
        title.setObjectName("PageTitle")
        header_layout.addWidget(title)
        subtitle = QLabel("所有字段都会加密保存在本机；只有标题是必填项")
        subtitle.setObjectName("Faint")
        header_layout.addWidget(subtitle)
        root.addWidget(header)

        # 表单区（可滚动）
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.NoFrame)
        form_host = QWidget()
        form = QVBoxLayout(form_host)
        form.setContentsMargins(24, 4, 24, 8)
        form.setSpacing(14)

        # 标题
        self.title_edit = self._line_edit("例如：GitHub、招商银行")
        form.addLayout(self._field("标题 *", self.title_edit))

        # 用户名
        self.username_edit = self._line_edit("登录账号、邮箱或手机号")
        copy_user = IconButton("copy", "复制用户名", box=30, size=15)
        copy_user.clicked.connect(lambda: self._copy(self.username_edit.text(), "用户名"))
        form.addLayout(self._field("用户名", self.username_edit, trailing=[copy_user]))

        # 密码
        self.password_edit = SecretLineEdit()
        self.password_edit.setMinimumHeight(36)
        self.password_edit.setPlaceholderText("留空表示不记录密码")
        self.password_edit.textChanged.connect(self._on_password_changed)

        generate_button = IconButton("sparkles", "打开密码生成器", token="accent", box=30, size=16)
        generate_button.clicked.connect(self._open_generator)
        copy_password = IconButton("copy", "复制密码", box=30, size=15)
        copy_password.clicked.connect(
            lambda: self._copy(self.password_edit.text(), "密码", sensitive=True))

        password_column = QVBoxLayout()
        password_column.setSpacing(8)
        password_column.addLayout(self._field("密码", self.password_edit,
                                              trailing=[generate_button, copy_password]))
        self.strength_meter = StrengthMeter()
        self.strength_label = QLabel("")
        self.strength_label.setObjectName("Faint")
        password_column.addWidget(self.strength_meter)
        password_column.addWidget(self.strength_label)
        form.addLayout(password_column)

        # 历史密码
        self.history_toggle = text_button("", kind="Link")
        self.history_toggle.clicked.connect(self._toggle_history)
        self.history_box = QWidget()
        self.history_layout = QVBoxLayout(self.history_box)
        self.history_layout.setContentsMargins(0, 0, 0, 0)
        self.history_layout.setSpacing(6)
        self.history_box.hide()
        form.addWidget(self.history_toggle)
        form.addWidget(self.history_box)

        # 预留电话 / 预留邮箱（找回账号时常用）
        self.phone_edit = self._line_edit("例如：138 0000 0000")
        copy_phone = IconButton("copy", "复制预留电话", box=30, size=15)
        copy_phone.clicked.connect(lambda: self._copy(self.phone_edit.text(), "预留电话"))
        form.addLayout(self._field("预留电话", self.phone_edit, trailing=[copy_phone]))

        self.email_edit = self._line_edit("例如：backup@example.com")
        copy_email = IconButton("copy", "复制预留邮箱", box=30, size=15)
        copy_email.clicked.connect(lambda: self._copy(self.email_edit.text(), "预留邮箱"))
        form.addLayout(self._field("预留邮箱", self.email_edit, trailing=[copy_email]))

        # 网址
        self.url_edit = self._line_edit("https://example.com")
        form.addLayout(self._field("网址", self.url_edit))

        # 分类与标签
        self.category_combo = QComboBox()
        self.category_combo.setEditable(True)
        self.category_combo.addItems(self.vault.categories)
        self.category_combo.setCurrentText(default_category)
        self.category_combo.setMinimumHeight(36)
        tag_hint = "、".join(default_tags)
        self.tags_edit = self._line_edit("多个标签用逗号分隔" + (f"，如：{tag_hint}" if tag_hint else ""))
        form.addLayout(self._field("分类", self.category_combo))
        form.addLayout(self._field("标签", self.tags_edit))

        # 两步验证
        self.totp_edit = self._line_edit("粘贴密钥或 otpauth:// 链接（可留空）")
        self.totp_edit.textChanged.connect(self._on_totp_changed)
        self.totp_status = QLabel("")
        self.totp_status.setObjectName("Faint")
        totp_column = QVBoxLayout()
        totp_column.setSpacing(6)
        totp_column.addLayout(self._field("两步验证密钥", self.totp_edit))
        totp_column.addWidget(self.totp_status)
        form.addLayout(totp_column)

        # 备注
        self.notes_edit = QPlainTextEdit()
        self.notes_edit.setPlaceholderText("安全问题答案、备用邮箱、恢复码等")
        self.notes_edit.setMinimumHeight(96)
        form.addLayout(self._field("备注", self.notes_edit))

        # 收藏
        self.favorite_check = QCheckBox("加入收藏")
        form.addWidget(self.favorite_check)

        form.addStretch(1)
        scroll.setWidget(form_host)
        root.addWidget(scroll, 1)

        # 底部按钮
        root.addWidget(widgets.divider())
        footer = QWidget()
        footer_layout = QHBoxLayout(footer)
        footer_layout.setContentsMargins(24, 12, 24, 16)
        footer_layout.setSpacing(10)

        if not self.is_new:
            delete_button = text_button("删除", kind="Danger", icon_name="trash",
                                        token="danger", size=15)
            delete_button.clicked.connect(self._delete)
            footer_layout.addWidget(delete_button)
        footer_layout.addStretch(1)

        cancel_button = text_button("取消")
        cancel_button.clicked.connect(self.reject)
        footer_layout.addWidget(cancel_button)

        save_button = text_button("保存", kind="Primary", icon_name="check",
                                  token="accent_text", size=16)
        save_button.setMinimumWidth(96)
        save_button.clicked.connect(self._save)
        footer_layout.addWidget(save_button)
        root.addWidget(footer)

    def _line_edit(self, placeholder: str) -> QLineEdit:
        edit = QLineEdit()
        edit.setPlaceholderText(placeholder)
        edit.setMinimumHeight(36)
        return edit

    def _field(self, caption: str, widget: QWidget, trailing: list[QWidget] | None = None):
        """构造"标签 + 输入控件 + 尾部按钮"的一组。"""
        layout = QVBoxLayout()
        layout.setSpacing(6)
        label = QLabel(caption)
        label.setObjectName("FieldLabel")
        layout.addWidget(label)

        row = QHBoxLayout()
        row.setSpacing(8)
        row.addWidget(widget, 1)
        for extra in trailing or []:
            row.addWidget(extra)
        layout.addLayout(row)
        return layout

    # ------------------------------------------------------------ 数据

    def _load_entry(self) -> None:
        """编辑模式下载入原始数据。"""
        if self.entry is None:
            return
        self.title_edit.setText(self.entry.title)
        self.username_edit.setText(self.entry.username)
        self.password_edit.setText(self.entry.password)
        self.phone_edit.setText(self.entry.phone)
        self.email_edit.setText(self.entry.email)
        self.url_edit.setText(self.entry.url)
        self.tags_edit.setText("，".join(self.entry.tags) if self.entry.tags else "")
        self.category_combo.setCurrentText(self.entry.category)
        self.notes_edit.setPlainText(self.entry.notes)
        self.favorite_check.setChecked(self.entry.favorite)
        if self.entry.totp_secret:
            self.totp_edit.setText(self.entry.totp_secret)
        self._render_history()

    def _render_history(self) -> None:
        """渲染历史密码列表。"""
        while self.history_layout.count():
            item = self.history_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()

        history = self.entry.history if self.entry else []
        if not history:
            self.history_toggle.hide()
            self.history_box.hide()
            return
        self.history_toggle.show()
        self.history_toggle.setText(f"历史密码（{len(history)}）")
        for item in history[:10]:
            row = QWidget()
            row_layout = QHBoxLayout(row)
            row_layout.setContentsMargins(10, 4, 4, 4)
            row_layout.setSpacing(8)

            changed = (item.changed_at or "")[:19].replace("T", " ")
            label = QLabel(f"{changed}　·　{'•' * min(len(item.password), 12)}")
            label.setObjectName("Faint")
            row_layout.addWidget(label, 1)

            copy_button = IconButton("copy", "复制这条历史密码", box=26, size=14)
            copy_button.clicked.connect(
                lambda _=False, p=item.password: self._copy(p, "历史密码", sensitive=True))
            row_layout.addWidget(copy_button)
            row.setStyleSheet("border: 1px solid transparent;")
            self.history_layout.addWidget(row)

    def _toggle_history(self) -> None:
        self.history_box.setVisible(not self.history_box.isVisible())

    # ------------------------------------------------------------ 交互

    def _copy(self, text: str, what: str, *, sensitive: bool = False) -> None:
        """复制字段内容；密码类内容不会被记进剪贴板历史。"""
        if text:
            clipboard_utils.put_text(text, sensitive=sensitive)

    def _on_password_changed(self) -> None:
        password = self.password_edit.text()
        if not password:
            self.strength_meter.set_state(0, "")
            self.strength_label.setText("")
            return
        report = strength.evaluate(password)
        self.strength_meter.set_state(report.score, report.label)
        text = f"强度：{report.label}"
        if report.suggestions:
            text += "　·　" + report.suggestions[0]
        self.strength_label.setText(text)

    def _on_totp_changed(self) -> None:
        text = self.totp_edit.text().strip()
        if not text:
            self.totp_status.setText("")
            return
        config = totp.parse_secret_input(text)
        if config is None:
            self.totp_status.setText("⚠  密钥格式无法识别，应为 base32 字符串或 otpauth:// 链接")
            self.totp_status.setObjectName("Danger")
        else:
            preview = totp.format_code(totp.generate_code(
                config.secret, digits=config.digits, period=config.period,
                algorithm=config.algorithm))
            self.totp_status.setText(f"✓  校验通过，当前口令：{preview}（{config.period} 秒刷新）")
            self.totp_status.setObjectName("Success")
        widgets.restyle(self.totp_status)

    def _open_generator(self) -> None:
        current = self.password_edit.text()
        length = max(len(current), 18)
        password = GeneratorDialog.get_password(self, length)
        if password:
            self.password_edit.setText(password)

    def _delete(self) -> None:
        """把条目移入回收站并关闭对话框。"""
        from PySide6.QtWidgets import QMessageBox
        answer = QMessageBox.question(
            self, "删除记录",
            f"确定把「{self.entry.title}」移入回收站吗？\n可以在回收站中恢复。",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        )
        if answer == QMessageBox.Yes:
            self.done(2)   # 2 = 请求删除

    def _save(self) -> None:
        title = self.title_edit.text().strip()
        if not title:
            self.title_edit.setFocus()
            widgets.restyle(self.title_edit)
            self.title_edit.setPlaceholderText("请填写标题后再保存")
            return

        totp_text = self.totp_edit.text().strip()
        if totp_text and totp.parse_secret_input(totp_text) is None:
            self.totp_edit.setFocus()
            return

        tags_raw = self.tags_edit.text().replace("，", ",").replace("、", ",")
        tags = [t.strip() for t in tags_raw.split(",") if t.strip()]

        config = totp.parse_secret_input(totp_text)
        self.data = {
            "title": title,
            "username": self.username_edit.text().strip(),
            "phone": self.phone_edit.text().strip(),
            "email": self.email_edit.text().strip(),
            "url": self.url_edit.text().strip(),
            "notes": self.notes_edit.toPlainText().strip(),
            "category": self.category_combo.currentText().strip() or DEFAULT_CATEGORY,
            "tags": tags,
            "favorite": self.favorite_check.isChecked(),
            "totp_secret": config.secret if config else "",
        }
        password = self.password_edit.text()
        self.new_password = password if password != self._original_password else None
        self.accept()
