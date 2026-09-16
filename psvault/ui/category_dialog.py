"""分类管理窗口：集中完成分类的新建、重命名与删除。"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from ..core.models import DEFAULT_CATEGORY
from ..core.storage import Vault
from . import icons, widgets
from .widgets import Badge, IconButton, text_button


class CategoryDialog(QDialog):
    """分类管理。所有修改立即写入保险箱。"""

    data_changed = Signal()

    def __init__(self, parent: QWidget | None, vault: Vault) -> None:
        super().__init__(parent)
        self.vault = vault
        self.setWindowTitle("分类管理")
        self.setWindowIcon(icons.app_icon())
        self.setMinimumSize(460, 520)
        self.resize(480, 560)
        self.setModal(True)
        self._build_ui()
        self._refresh()

    # ------------------------------------------------------------ 界面

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(22, 20, 22, 16)
        root.setSpacing(12)

        title = QLabel("分类管理")
        title.setObjectName("PageTitle")
        root.addWidget(title)
        root.addWidget(widgets.hint_label(
            "分类用于归类记录。删除分类不会删除记录，其中的记录会移动到「未分类」。"))

        # 新建分类
        create_card = QFrame()
        create_card.setObjectName("Card")
        create_layout = QHBoxLayout(create_card)
        create_layout.setContentsMargins(14, 12, 14, 12)
        create_layout.setSpacing(8)
        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText("输入新分类名称，例如：密钥")
        self.name_edit.setMinimumHeight(36)
        self.name_edit.returnPressed.connect(self._add)
        create_layout.addWidget(self.name_edit, 1)
        add_button = text_button("添加", kind="Primary", icon_name="plus",
                                 token="accent_text", size=15)
        add_button.clicked.connect(self._add)
        create_layout.addWidget(add_button)
        root.addWidget(create_card)

        # 分类列表
        root.addWidget(widgets.section_title("现有分类"))
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.NoFrame)
        self.list_host = QWidget()
        self.list_layout = QVBoxLayout(self.list_host)
        self.list_layout.setContentsMargins(0, 0, 6, 0)
        self.list_layout.setSpacing(6)
        self.list_layout.addStretch(1)
        scroll.setWidget(self.list_host)
        root.addWidget(scroll, 1)

        footer = QHBoxLayout()
        self.count_label = QLabel("")
        self.count_label.setObjectName("Faint")
        footer.addWidget(self.count_label)
        footer.addStretch(1)
        close_button = text_button("完成", kind="Primary", icon_name="check",
                                   token="accent_text", size=16)
        close_button.clicked.connect(self.accept)
        footer.addWidget(close_button)
        root.addLayout(footer)

    def _clear(self) -> None:
        while self.list_layout.count() > 1:
            item = self.list_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()

    def _refresh(self) -> None:
        """重建分类列表。"""
        self._clear()
        counts = self.vault.category_counts()
        for name in self.vault.categories:
            self.list_layout.insertWidget(self.list_layout.count() - 1, self._row(name, counts))

        total = len(self.vault.categories)
        self.count_label.setText(f"共 {total} 个分类　·　「{DEFAULT_CATEGORY}」为系统分类，不可删除")

    def _row(self, name: str, counts: dict[str, int]) -> QWidget:
        """一行分类：名称 + 记录数 + 重命名 / 删除。"""
        row = QFrame()
        row.setObjectName("FieldRow")
        row.setFixedHeight(46)
        layout = QHBoxLayout(row)
        layout.setContentsMargins(14, 6, 8, 6)
        layout.setSpacing(8)

        icon_label = QLabel()
        icon_label.setPixmap(icons.colored_pixmap(
            "key" if name == "密钥" else "folder", "text_faint", 16))
        icon_label.setFixedWidth(18)
        layout.addWidget(icon_label)

        label = QLabel(name)
        label.setObjectName("FieldValue")
        layout.addWidget(label)
        layout.addStretch(1)

        layout.addWidget(Badge(f"{counts.get(name, 0)} 条", "plain"))

        rename_button = IconButton("pencil", "重命名", box=28, size=15)
        rename_button.clicked.connect(lambda _=False, n=name: self._rename(n))
        layout.addWidget(rename_button)

        if name != DEFAULT_CATEGORY:
            delete_button = IconButton("trash", "删除", token="danger", box=28, size=15)
            delete_button.clicked.connect(lambda _=False, n=name: self._remove(n))
            layout.addWidget(delete_button)
        return row

    # ------------------------------------------------------------ 操作

    # 下面三个方法只做数据改动（不弹窗），界面回调与测试都可以直接调用

    def add_category(self, name: str) -> bool:
        """新建分类，成功返回 True。"""
        if not self.vault.add_category(name.strip()):
            return False
        self.vault.save()
        self.name_edit.clear()
        self._refresh()
        self.data_changed.emit()
        return True

    def rename_category(self, name: str, new_name: str) -> bool:
        """重命名分类，成功返回 True。"""
        new_name = new_name.strip()
        if not new_name or new_name == name:
            return False
        if not self.vault.rename_category(name, new_name):
            return False
        self.vault.save()
        self._refresh()
        self.data_changed.emit()
        return True

    def remove_category(self, name: str) -> bool:
        """删除分类（记录归入「未分类」），成功返回 True。"""
        if not self.vault.remove_category(name):
            return False
        self.vault.save()
        self._refresh()
        self.data_changed.emit()
        return True

    # ------------------------------------------------------------ 界面回调

    def _add(self) -> None:
        name = self.name_edit.text().strip()
        if not name:
            self.name_edit.setFocus()
            return
        if not self.add_category(name):
            QMessageBox.information(self, "无法添加", f"分类「{name}」已经存在。")

    def _rename(self, name: str) -> None:
        new_name, ok = QInputDialog.getText(self, "重命名分类", "新的名称：", text=name)
        if ok and not self.rename_category(name, new_name):
            QMessageBox.information(self, "无法重命名", f"分类「{new_name.strip()}」已经存在。")

    def _remove(self, name: str) -> None:
        answer = QMessageBox.question(
            self, "删除分类",
            f"删除分类「{name}」？\n其中的记录会移动到「{DEFAULT_CATEGORY}」，不会被删除。",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if answer == QMessageBox.Yes:
            self.remove_category(name)
