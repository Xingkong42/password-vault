"""主窗口：侧栏导航 + 记录列表 + 详情面板的三栏布局。"""

from __future__ import annotations

import time
from datetime import datetime

from PySide6.QtCore import QEvent, QPoint, Qt, QTimer, QUrl, Signal
from PySide6.QtGui import QDesktopServices, QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QMenu,
    QMessageBox,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from ..core import crypto, strength, totp
from ..core.models import DEFAULT_CATEGORY, SORT_KEYS, SORT_LABELS, Entry
from ..core.storage import Vault
from . import icons, widgets
from . import clipboard as clipboard_utils
from .audit_panel import AuditPanel
from .category_dialog import CategoryDialog
from .entry_dialog import EntryDialog
from .generator_dialog import GeneratorDialog
from .settings_dialog import SettingsDialog
from .theme import Theme
from .widgets import (
    Avatar,
    Badge,
    EmptyState,
    FieldRow,
    IconButton,
    NavItem,
    SearchBox,
    TagChip,
    Toast,
    restyle,
    text_button,
)

SIDEBAR_WIDTH = 218
LIST_WIDTH = 306
TOTP_REFRESH_MS = 1000
AUTO_SAVE_DELAY_MS = 400


# ---------------------------------------------------------------- 列表卡片

class EntryCard(QFrame):
    """列表中的一条记录卡片。支持用键盘操作。"""

    clicked = Signal(str)
    activated = Signal(str)
    menu_requested = Signal(str, QPoint)
    navigate = Signal(str, int)          # (记录 id, -1 上 / +1 下)
    copy_requested = Signal(str)
    delete_requested = Signal(str)

    def __init__(self, entry: Entry, selected: bool = False,
                 issues: list | None = None,
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.entry_id = entry.id
        self.setObjectName("EntryCard")
        self.setCursor(Qt.PointingHandCursor)
        self.setProperty("selected", "true" if selected else "false")
        self.setFixedHeight(58)
        self.setFocusPolicy(Qt.StrongFocus)      # 允许 Tab / 方向键落进来

        risks = [i for i in (issues or []) if i.is_risk]

        layout = QHBoxLayout(self)
        layout.setContentsMargins(10, 6, 10, 6)
        layout.setSpacing(11)

        self.avatar = Avatar(entry.title or "?", 34)
        layout.addWidget(self.avatar)

        column = QVBoxLayout()
        column.setSpacing(2)
        column.setContentsMargins(0, 0, 0, 0)
        title = QLabel(widgets.elide(entry.title, 16 if risks else 22))
        title.setObjectName("EntryTitle")
        column.addWidget(title)
        subtitle = QLabel(widgets.elide(entry.subtitle(), 20 if risks else 26))
        subtitle.setObjectName("Faint")
        column.addWidget(subtitle)
        layout.addLayout(column, 1)

        # 审计视图下用紧凑标签直接点名问题，与"全部记录"一眼可分
        if risks:
            badge = QLabel(risks[0].short_label)
            badge.setObjectName("BadgeDanger" if risks[0].severity == "high" else "BadgeWarning")
            badge.setToolTip(risks[0].title + "：" + risks[0].detail)
            layout.addWidget(badge, 0, Qt.AlignVCenter)
            if len(risks) > 1:
                more = QLabel(f"+{len(risks) - 1}")
                more.setObjectName("Badge")
                more.setToolTip("；".join(f"{i.title}：{i.detail}" for i in risks[1:]))
                layout.addWidget(more, 0, Qt.AlignVCenter)

        if entry.totp_secret:
            marker = QLabel()
            marker.setPixmap(icons.colored_pixmap("shield-check", "text_faint", 14))
            marker.setToolTip("已启用两步验证")
            layout.addWidget(marker, 0, Qt.AlignVCenter)
        if entry.favorite:
            star = QLabel()
            star.setPixmap(icons.colored_pixmap("star-filled", "warning", 14))
            star.setToolTip("已收藏")
            layout.addWidget(star, 0, Qt.AlignVCenter)

    def set_selected(self, selected: bool) -> None:
        self.setProperty("selected", "true" if selected else "false")
        restyle(self)

    def mousePressEvent(self, event) -> None:  # noqa: N802 - Qt 命名
        if event.button() == Qt.LeftButton:
            self.clicked.emit(self.entry_id)
        super().mousePressEvent(event)

    def mouseDoubleClickEvent(self, event) -> None:  # noqa: N802 - Qt 命名
        self.activated.emit(self.entry_id)

    def contextMenuEvent(self, event) -> None:  # noqa: N802 - Qt 命名
        self.menu_requested.emit(self.entry_id, event.globalPos())

    def keyPressEvent(self, event) -> None:  # noqa: N802 - Qt 命名
        """键盘操作：上下切换、回车编辑、Ctrl+C 复制密码、Delete 删除。"""
        key = event.key()
        if key == Qt.Key_Up:
            self.navigate.emit(self.entry_id, -1)
            return
        if key == Qt.Key_Down:
            self.navigate.emit(self.entry_id, 1)
            return
        if key in (Qt.Key_Return, Qt.Key_Enter):
            self.activated.emit(self.entry_id)
            return
        if key == Qt.Key_Delete:
            self.delete_requested.emit(self.entry_id)
            return
        if key == Qt.Key_C and event.modifiers() & Qt.ControlModifier:
            self.copy_requested.emit(self.entry_id)
            return
        super().keyPressEvent(event)


# ---------------------------------------------------------------- 主窗口

class MainWindow(QWidget):
    """密码保险箱主界面（独立顶层窗口，便于在锁定后整体替换）。"""

    lock_requested = Signal(str)

    def __init__(self, vault: Vault) -> None:
        super().__init__()
        self.vault = vault
        self.filter_kind = "all"          # all | favorite | audit | trash | category | tag
        self.filter_value = ""
        self.search_text = ""
        self.selected_id = ""
        self.sort_key = vault.settings.sort_key
        self._cards: dict[str, EntryCard] = {}
        self._last_activity = time.monotonic()
        self._clipboard_timer: QTimer | None = None
        self._totp_state: tuple | None = None
        self.totp_label: QLabel | None = None

        self.setWindowTitle(f"密码保险箱 — {vault.path.name}")
        self.setWindowIcon(icons.app_icon())
        self.resize(1180, 760)
        self.setMinimumSize(980, 620)

        self._build_ui()
        self._install_shortcuts()
        self._start_timers()
        self.vault.ensure_backup_dir()      # 首次使用时确定外部备份位置
        self.reload_all()
        if self.vault.dirty:                # 迁移或首次初始化过，落盘固化
            self._save_vault()

    # ============================================================ 构建界面

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        body = QHBoxLayout()
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(0)
        body.addWidget(self._build_sidebar())
        body.addWidget(self._build_list_pane())
        body.addWidget(self._build_detail_pane(), 1)
        root.addLayout(body, 1)

        root.addWidget(self._build_status_bar())

        self.toast = Toast(self)

    # ------------------------------------------------------------ 侧栏

    def _build_sidebar(self) -> QWidget:
        sidebar = QFrame()
        sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(SIDEBAR_WIDTH)
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(14, 18, 14, 12)
        layout.setSpacing(6)

        # 品牌
        brand = QHBoxLayout()
        brand.setSpacing(9)
        logo = QLabel()
        logo.setPixmap(icons.build_logo(Theme.instance().hex("accent"), 26))
        brand.addWidget(logo)
        self.brand_label = QLabel(self.vault.name)
        self.brand_label.setObjectName("AppTitle")
        self.brand_label.setToolTip(f"保险箱：{self.vault.name}\n文件：{self.vault.path}")
        brand.addWidget(self.brand_label, 1)
        layout.addLayout(brand)
        layout.addSpacing(14)

        # 主导航
        self.nav_items: dict[str, NavItem] = {}
        nav_specs = [
            ("all", "全部记录", "grid"),
            ("favorite", "收藏", "star"),
            ("audit", "安全审计", "shield-check"),
            ("trash", "回收站", "trash"),
        ]
        for key, label, icon_name in nav_specs:
            item = NavItem(label, icon_name)
            item.clicked.connect(lambda _=False, k=key: self.set_filter(k))
            layout.addWidget(item)
            self.nav_items[key] = item

        layout.addSpacing(14)

        # 分类
        category_header = QHBoxLayout()
        category_header.setContentsMargins(4, 0, 0, 0)
        category_header.addWidget(widgets.section_title("分类"))
        category_header.addStretch(1)
        manage_category = IconButton("settings", "管理分类（新建 / 重命名 / 删除）", box=24, size=14)
        manage_category.clicked.connect(self.manage_categories)
        category_header.addWidget(manage_category)
        add_category = IconButton("plus", "新建分类", box=24, size=14)
        add_category.clicked.connect(self._add_category)
        category_header.addWidget(add_category)
        layout.addLayout(category_header)
        layout.addSpacing(2)

        self.category_container = QWidget()
        self.category_layout = QVBoxLayout(self.category_container)
        self.category_layout.setContentsMargins(0, 0, 0, 0)
        self.category_layout.setSpacing(2)
        layout.addWidget(self.category_container)

        # 标签
        self.tag_header = widgets.section_title("标签")
        layout.addSpacing(10)
        layout.addWidget(self.tag_header)
        self.tag_container = QWidget()
        self.tag_layout = QVBoxLayout(self.tag_container)
        self.tag_layout.setContentsMargins(0, 0, 0, 0)
        self.tag_layout.setSpacing(4)
        layout.addWidget(self.tag_container)

        layout.addStretch(1)

        # 底部操作
        lock_button = text_button("锁定保险箱", kind="Ghost", icon_name="lock",
                                  token="text_muted", size=16)
        lock_button.clicked.connect(lambda: self.lock("手动锁定"))
        lock_button.setMinimumHeight(34)
        layout.addWidget(lock_button)

        bottom_row = QHBoxLayout()
        bottom_row.setSpacing(6)
        self.theme_button = IconButton("moon" if not Theme.instance().is_dark else "sun",
                                       "切换深色 / 浅色主题", box=32, size=17)
        self.theme_button.clicked.connect(self._toggle_theme)
        bottom_row.addWidget(self.theme_button)

        settings_button = text_button("设置", kind="Ghost", icon_name="settings",
                                      token="text_muted", size=16)
        settings_button.clicked.connect(self.open_settings)
        settings_button.setMinimumHeight(32)
        bottom_row.addWidget(settings_button, 1)
        layout.addLayout(bottom_row)
        return sidebar

    # ------------------------------------------------------------ 列表栏

    def _build_list_pane(self) -> QWidget:
        pane = QFrame()
        pane.setObjectName("ListPane")
        pane.setFixedWidth(LIST_WIDTH)
        layout = QVBoxLayout(pane)
        layout.setContentsMargins(14, 18, 10, 12)
        layout.setSpacing(10)

        top_row = QHBoxLayout()
        top_row.setSpacing(8)
        self.search_box = SearchBox("搜索标题、账号、备注…")
        self.search_box.textChanged.connect(self._on_search_changed)
        self.search_box.enter_list.connect(self._focus_first_card)
        top_row.addWidget(self.search_box, 1)

        self.new_button = IconButton("plus", "新建记录 (Ctrl+N)", token="accent_text", box=34, size=18)
        self.new_button.setObjectName("Primary")
        self.new_button.setStyleSheet(
            f"QToolButton {{ background: {Theme.instance().hex('accent')};"
            f" border-radius: 8px; }}"
            f"QToolButton:hover {{ background: {Theme.instance().hex('accent_hover')}; }}"
        )
        self.new_button.clicked.connect(self.create_entry)
        top_row.addWidget(self.new_button)
        layout.addLayout(top_row)

        caption_row = QHBoxLayout()
        caption_row.setSpacing(6)
        self.list_caption = QLabel("")
        self.list_caption.setObjectName("Faint")
        caption_row.addWidget(self.list_caption, 1)

        self.sort_button = IconButton("sort", "排序方式", box=26, size=15)
        self.sort_button.clicked.connect(self._show_sort_menu)
        caption_row.addWidget(self.sort_button)
        layout.addLayout(caption_row)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.list_host = QWidget()
        self.list_layout = QVBoxLayout(self.list_host)
        self.list_layout.setContentsMargins(2, 0, 4, 0)
        self.list_layout.setSpacing(4)
        self.list_layout.addStretch(1)
        scroll.setWidget(self.list_host)
        self.list_scroll = scroll
        layout.addWidget(scroll, 1)

        self.list_empty = EmptyState("search", "没有匹配的记录", "换个关键词，或新建一条记录")
        layout.addWidget(self.list_empty, 1)
        self.list_empty.hide()
        return pane

    # ------------------------------------------------------------ 详情栏

    def _build_detail_pane(self) -> QWidget:
        pane = QFrame()
        pane.setObjectName("DetailPane")
        layout = QVBoxLayout(pane)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.NoFrame)
        self.detail_host = QWidget()
        self.detail_layout = QVBoxLayout(self.detail_host)
        self.detail_layout.setContentsMargins(28, 24, 28, 24)
        self.detail_layout.setSpacing(14)
        scroll.setWidget(self.detail_host)
        self.detail_scroll = scroll
        layout.addWidget(scroll)

        self.detail_empty = EmptyState(
            "key", "从左侧选择一条记录", "也可以按 Ctrl+N 新建，或按 Ctrl+G 生成一个强密码")
        layout.addWidget(self.detail_empty, 1)
        return pane

    # ------------------------------------------------------------ 状态栏

    def _build_status_bar(self) -> QWidget:
        bar = QFrame()
        bar.setObjectName("Surface")
        bar.setFixedHeight(30)
        bar.setStyleSheet(
            f"#Surface {{ background: {Theme.instance().hex('surface_alt')};"
            f" border: none; border-top: 1px solid {Theme.instance().hex('border')};"
            f" border-radius: 0; }}"
        )
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(16, 0, 16, 0)
        layout.setSpacing(10)
        self.status_left = QLabel("")
        self.status_left.setObjectName("Faint")
        layout.addWidget(self.status_left)
        layout.addStretch(1)
        self.status_right = QLabel("")
        self.status_right.setObjectName("Faint")
        layout.addWidget(self.status_right)
        return bar

    # ------------------------------------------------------------ 快捷键

    def _install_shortcuts(self) -> None:
        bindings = [
            ("Ctrl+N", self.create_entry),
            ("Ctrl+F", lambda: self.search_box.setFocus()),
            ("Ctrl+L", lambda: self.lock("手动锁定")),
            ("Ctrl+G", self.open_generator),
            ("Ctrl+E", lambda: self.edit_selected()),
            ("Ctrl+D", lambda: self.toggle_favorite(self.selected_id)),
            ("Ctrl+Comma", self.open_settings),
            ("Escape", self._clear_search),
        ]
        # 注意：这里刻意不绑定 Delete 键——全局快捷键会在搜索框输入时误触发删除。
        for keys, slot in bindings:
            shortcut = QShortcut(QKeySequence(keys), self)
            shortcut.activated.connect(slot)

    # ============================================================ 数据刷新

    def reload_all(self) -> None:
        """重建侧栏、列表与详情。"""
        self._refresh_title()
        self._refresh_sidebar()
        self.refresh_list()
        self.refresh_detail()
        self._refresh_status()

    def _refresh_title(self) -> None:
        """窗口标题与侧栏名称跟随保险箱名称。"""
        name = self.vault.name
        self.setWindowTitle(f"{name} — 密码保险箱")
        if getattr(self, "brand_label", None) is not None:
            self.brand_label.setText(name)
            self.brand_label.setToolTip(f"保险箱：{name}\n文件：{self.vault.path}")

    def _refresh_sidebar(self) -> None:
        stats = self.vault.statistics()
        self.nav_items["all"].set_count(stats["total"])
        self.nav_items["favorite"].set_count(stats["favorite"])
        self.nav_items["trash"].set_count(stats["trash"])
        issue_count = len(strength.risk_entries(
            self.vault.active_entries(), self.vault.settings.password_max_age_days))
        self.nav_items["audit"].set_count(issue_count)

        for key, item in self.nav_items.items():
            item.setChecked(self.filter_kind == key)

        # 分类
        while self.category_layout.count():
            child = self.category_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()
        counts = self.vault.category_counts()
        for name in self.vault.categories:
            item = NavItem(name, "folder")
            item.set_count(counts.get(name, 0))
            item.setChecked(self.filter_kind == "category" and self.filter_value == name)
            item.clicked.connect(lambda _=False, n=name: self.set_filter("category", n))
            item.setContextMenuPolicy(Qt.CustomContextMenu)
            item.customContextMenuRequested.connect(
                lambda pos, n=name, w=item: self._category_menu(n, w.mapToGlobal(pos)))
            self.category_layout.addWidget(item)

        # 标签
        tags = self.vault.all_tags()
        while self.tag_layout.count():
            child = self.tag_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()
        if not tags:
            self.tag_header.hide()
            self.tag_container.hide()
        else:
            self.tag_header.show()
            self.tag_container.show()
            row = None
            per_row = 2
            for index, tag in enumerate(tags[:12]):
                if index % per_row == 0:
                    row = QHBoxLayout()
                    row.setSpacing(4)
                    row.setContentsMargins(0, 0, 0, 0)
                    self.tag_layout.addLayout(row)
                chip = TagChip(tag, active=(self.filter_kind == "tag" and self.filter_value == tag))
                chip.clicked.connect(lambda _=False, t=tag: self.set_filter("tag", t))
                row.addWidget(chip)
            if row is not None:
                row.addStretch(1)

    def _visible_entries(self) -> list[Entry]:
        """按当前筛选条件与关键字取出条目。"""
        if self.filter_kind == "trash":
            entries = self.vault.trashed_entries()
        else:
            entries = self.vault.active_entries()

        if self.filter_kind == "favorite":
            entries = [e for e in entries if e.favorite]
        elif self.filter_kind == "category":
            entries = [e for e in entries if e.category == self.filter_value]
        elif self.filter_kind == "tag":
            entries = [e for e in entries if self.filter_value in e.tags]
        elif self.filter_kind == "audit":
            entries = strength.risk_entries(
                entries, self.vault.settings.password_max_age_days)

        if self.search_text:
            entries = [e for e in entries if e.matches(self.search_text)]

        return self._sort_entries(entries)

    def _sort_entries(self, entries: list[Entry]) -> list[Entry]:
        """按当前选择的方式排序。"""
        if self.sort_key == "updated":
            return sorted(entries, key=lambda e: e.updated_at or "", reverse=True)
        if self.sort_key == "created":
            return sorted(entries, key=lambda e: e.created_at or "", reverse=True)
        # 默认：收藏优先，再按名称
        return sorted(entries, key=lambda e: (not e.favorite, e.title.lower()))

    def _show_sort_menu(self) -> None:
        """选择排序方式。"""
        menu = QMenu(self)
        for key in SORT_KEYS:
            action = menu.addAction(SORT_LABELS[key])
            action.setCheckable(True)
            action.setChecked(key == self.sort_key)
            action.triggered.connect(lambda _=False, k=key: self.set_sort(k))
        menu.exec(self.sort_button.mapToGlobal(
            QPoint(0, self.sort_button.height())))

    def set_sort(self, key: str) -> None:
        """切换排序方式并记住选择。"""
        if key not in SORT_KEYS or key == self.sort_key:
            return
        self.sort_key = key
        self.vault.settings.sort_key = key
        self._save_vault()
        self.refresh_list()

    def refresh_list(self) -> None:
        """重建列表卡片。"""
        entries = self._visible_entries()

        while self.list_layout.count() > 1:      # 末尾保留 stretch
            item = self.list_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
        self._cards.clear()

        if not entries:
            self.list_empty.show()
            self.list_scroll.hide()
        else:
            self.list_empty.hide()
            self.list_scroll.show()
            # 审计视图下把每条记录的具体问题直接标在卡片上（批量算一次）
            show_issues = self.filter_kind == "audit"
            analyzed: dict[str, list] = {}
            if show_issues:
                analyzed = strength.analyze_entries(
                    self.vault.active_entries(),
                    self.vault.settings.password_max_age_days)
            for entry in entries:
                issues = analyzed.get(entry.id) if show_issues else None
                card = EntryCard(entry, selected=(entry.id == self.selected_id),
                                 issues=issues)
                card.clicked.connect(self.select_entry)
                card.activated.connect(self.edit_entry)
                card.menu_requested.connect(self._show_entry_menu)
                card.navigate.connect(self._navigate_card)
                card.copy_requested.connect(self._copy_password_of)
                card.delete_requested.connect(self.delete_entry)
                self.list_layout.insertWidget(self.list_layout.count() - 1, card)
                self._cards[entry.id] = card

        caption = {
            "all": "全部记录", "favorite": "收藏", "audit": "待处理的安全问题",
            "trash": "回收站（可恢复）",
        }.get(self.filter_kind, "")
        if self.filter_kind == "category":
            caption = f"分类 · {self.filter_value}"
        elif self.filter_kind == "tag":
            caption = f"标签 · {self.filter_value}"
        if self.search_text:
            caption += f"　搜索「{self.search_text}」"
        self.list_caption.setText(f"{caption}　·　{len(entries)} 条")
        self.sort_button.setToolTip(
            f"排序方式：{SORT_LABELS.get(self.sort_key, '名称')}（点击切换）")

    # ------------------------------------------------------------ 详情

    def refresh_detail(self) -> None:
        """重建详情面板。"""
        self._clear_layout(self.detail_layout)
        self._totp_state = None
        self.totp_label = None          # 上一条记录的 TOTP 控件已随面板销毁
        # 换内容后回到顶部，否则会停在上一条记录的滚动位置
        self.detail_scroll.verticalScrollBar().setValue(0)

        entry = self.vault.find(self.selected_id) if self.selected_id else None
        if entry is not None and entry.is_deleted and self.filter_kind != "trash":
            entry = None

        # 审计视图：没有选中记录时，右侧显示完整的风险报告——
        # 这样"安全审计"和"全部记录"在界面上一眼就能区分开。
        if self.filter_kind == "audit" and entry is None:
            self.detail_empty.hide()
            self.detail_scroll.show()
            self._build_audit_view()
            return

        if entry is None:
            self.detail_scroll.hide()
            self.detail_empty.show()
            return

        self.detail_empty.hide()
        self.detail_scroll.show()

        if entry.is_deleted:
            self._build_trash_detail(entry)
        else:
            self._build_entry_detail(entry)

    def _build_audit_view(self) -> None:
        """在详情区嵌入安全审计报告。"""
        panel = AuditPanel(self.detail_host, self.vault)
        panel.entry_selected.connect(self._jump_to_entry)
        panel.issue_ignored.connect(self._ignore_issue)
        panel.issue_restored.connect(self._restore_issue)
        panel.all_restored.connect(self._restore_all_issues)
        self.detail_layout.addWidget(panel)
        self.audit_panel = panel

    def _clear_layout(self, layout) -> None:
        """清空布局（先摘父控件再 deleteLater，避免重建时出现残影）。"""
        widgets.clear_layout(layout)

    def _build_trash_detail(self, entry: Entry) -> None:
        """回收站条目的简化详情。"""
        card = QFrame()
        card.setObjectName("Card")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(22, 20, 22, 20)
        layout.setSpacing(12)

        title = QLabel(entry.title)
        title.setObjectName("PageTitle")
        layout.addWidget(title)

        info = QLabel(f"删除于 {(entry.deleted_at or '')[:19].replace('T', ' ')}")
        info.setObjectName("Faint")
        layout.addWidget(info)

        layout.addWidget(widgets.hint_label("这条记录在回收站中，可以恢复或彻底删除。"))
        layout.addSpacing(6)

        row = QHBoxLayout()
        restore = text_button("恢复", kind="Primary", icon_name="restore",
                              token="accent_text", size=16)
        restore.clicked.connect(lambda: self.restore_entry(entry.id))
        row.addWidget(restore)
        purge = text_button("彻底删除", kind="Danger", icon_name="trash", token="danger", size=15)
        purge.clicked.connect(lambda: self.purge_entry(entry.id))
        row.addWidget(purge)
        row.addStretch(1)
        layout.addLayout(row)

        self.detail_layout.addWidget(card)
        self.detail_layout.addStretch(1)

    def _build_entry_detail(self, entry: Entry) -> None:
        """完整详情：标题区 + 字段卡片 + 元信息。"""
        # 从审计报告点进来的，给一条回到报告的路径
        if self.filter_kind == "audit":
            back_row = QHBoxLayout()
            back_button = text_button("‹  返回审计报告", kind="Link")
            back_button.clicked.connect(self._back_to_audit)
            back_row.addWidget(back_button)
            back_row.addStretch(1)
            self.detail_layout.addLayout(back_row)

        # 标题区
        header = QHBoxLayout()
        header.setSpacing(14)
        avatar = Avatar(entry.title or "?", 46)
        header.addWidget(avatar)

        title_column = QVBoxLayout()
        title_column.setSpacing(4)
        title = QLabel(entry.title)
        title.setObjectName("PageTitle")
        title.setWordWrap(True)
        title_column.addWidget(title)

        badges = QHBoxLayout()
        badges.setSpacing(6)
        badges.addWidget(Badge(entry.category, "plain"))
        report = strength.evaluate(entry.password)
        if entry.password:
            kind = "success" if report.score >= 3 else ("warning" if report.score == 2 else "danger")
            badges.addWidget(Badge(f"密码{report.label}", kind))
        if entry.totp_secret:
            badges.addWidget(Badge("两步验证", "accent"))
        if entry.favorite:
            badges.addWidget(Badge("已收藏", "warning"))
        badges.addStretch(1)
        title_column.addLayout(badges)
        header.addLayout(title_column, 1)

        actions = QHBoxLayout()
        actions.setSpacing(6)
        self.favorite_button = IconButton(
            "star-filled" if entry.favorite else "star",
            "取消收藏 (Ctrl+D)" if entry.favorite else "加入收藏 (Ctrl+D)",
            token="warning" if entry.favorite else "text_muted", box=32, size=17)
        self.favorite_button.clicked.connect(lambda: self.toggle_favorite(entry.id))
        actions.addWidget(self.favorite_button)

        edit_button = text_button("编辑", kind="Primary", icon_name="pencil",
                                  token="accent_text", size=15)
        edit_button.clicked.connect(lambda: self.edit_entry(entry.id))
        actions.addWidget(edit_button)

        more_button = IconButton("more", "更多操作", box=32, size=17)
        more_button.clicked.connect(lambda: self._show_entry_menu(entry.id, more_button.mapToGlobal(QPoint(0, more_button.height()))))
        actions.addWidget(more_button)
        header.addLayout(actions)
        self.detail_layout.addLayout(header)

        # 风险提示：明确写出这条记录的问题出在哪
        banner = self._build_risk_banner(entry)
        if banner is not None:
            self.detail_layout.addWidget(banner)
        self.detail_layout.addSpacing(4)

        # 字段卡片
        if entry.username:
            row = FieldRow("用户名", entry.username, "user",
                           [("copy", "复制用户名", lambda: self.copy_text(entry.username, "用户名"))])
            self.detail_layout.addWidget(row)
        if entry.password:
            self._password_row = self._build_password_row(entry)
            self.detail_layout.addWidget(self._password_row)
        if entry.phone:
            row = FieldRow("预留电话", entry.phone, "phone",
                           [("copy", "复制预留电话", lambda: self.copy_text(entry.phone, "预留电话"))])
            self.detail_layout.addWidget(row)
        if entry.email:
            row = FieldRow("预留邮箱", entry.email, "mail",
                           [("copy", "复制预留邮箱", lambda: self.copy_text(entry.email, "预留邮箱"))])
            self.detail_layout.addWidget(row)
        if entry.url:
            row = FieldRow("网址", entry.url, "globe", [
                ("link", "在浏览器中打开", lambda: QDesktopServices.openUrl(QUrl(self._normalize_url(entry.url)))),
                ("copy", "复制网址", lambda: self.copy_text(entry.url, "网址")),
            ])
            self.detail_layout.addWidget(row)
        if entry.totp_secret:
            self.detail_layout.addWidget(self._build_totp_row(entry))
        if entry.notes:
            row = FieldRow("备注", entry.notes, "note",
                           [("copy", "复制备注", lambda: self.copy_text(entry.notes, "备注"))])
            row.value_label.setWordWrap(True)
            row.setMinimumHeight(60)
            self.detail_layout.addWidget(row)
        if entry.tags:
            tag_row = QFrame()
            tag_row.setObjectName("FieldRow")
            tag_layout = QHBoxLayout(tag_row)
            tag_layout.setContentsMargins(14, 10, 14, 10)
            tag_layout.setSpacing(6)
            caption = QLabel("标签")
            caption.setObjectName("FieldLabel")
            tag_layout.addWidget(caption)
            tag_layout.addSpacing(6)
            for tag in entry.tags:
                chip = TagChip(tag)
                chip.clicked.connect(lambda _=False, t=tag: self.set_filter("tag", t))
                tag_layout.addWidget(chip)
            tag_layout.addStretch(1)
            self.detail_layout.addWidget(tag_row)

        # 历史密码
        if entry.history:
            self.detail_layout.addWidget(self._build_history_section(entry))

        # 元信息
        meta = QFrame()
        meta.setObjectName("FieldRow")
        meta_layout = QVBoxLayout(meta)
        meta_layout.setContentsMargins(14, 10, 14, 10)
        meta_layout.setSpacing(4)
        created = QLabel(f"创建时间　{self._format_time(entry.created_at)}")
        created.setObjectName("Faint")
        updated = QLabel(f"更新时间　{self._format_time(entry.updated_at)}　（{entry.age_days()} 天前）")
        updated.setObjectName("Faint")
        meta_layout.addWidget(created)
        meta_layout.addWidget(updated)
        self.detail_layout.addWidget(meta)

        self.detail_layout.addStretch(1)

    def _build_risk_banner(self, entry: Entry) -> QWidget | None:
        """详情页顶部的风险提示。

        用户不需要自己去猜"哪里有风险"：这里直接列出问题类型和具体原因。
        """
        issues = strength.entry_issues(
            entry, self.vault.active_entries(), self.vault.settings.password_max_age_days)
        risks = [i for i in issues if i.is_risk]
        suggests = [i for i in issues if not i.is_risk]
        if not risks:
            return None

        level = "high" if any(i.severity == "high" for i in risks) else "medium"
        card = QFrame()
        card.setObjectName("RiskBanner")
        card.setProperty("level", level)
        layout = QVBoxLayout(card)
        layout.setContentsMargins(16, 13, 16, 13)
        layout.setSpacing(9)

        head = QHBoxLayout()
        head.setSpacing(9)
        icon_label = QLabel()
        icon_label.setPixmap(icons.colored_pixmap(
            "alert", "danger" if level == "high" else "warning", 18))
        head.addWidget(icon_label, 0, Qt.AlignTop)

        title = QLabel(f"这条记录有 {len(risks)} 处需要关注")
        title.setObjectName("RiskTitle")
        title.setProperty("level", level)
        head.addWidget(title)
        head.addStretch(1)

        fix_button = text_button("换个强密码", icon_name="sparkles", size=15)
        fix_button.setToolTip("用密码生成器换一个新密码，并复制到剪贴板")
        fix_button.clicked.connect(lambda: self._fix_password(entry))
        head.addWidget(fix_button)

        ignore_button = text_button("忽略", icon_name="ignore", size=15)
        ignore_button.setToolTip("不再提示这条记录的风险（可在安全审计中恢复）")
        ignore_button.clicked.connect(lambda: self._ignore_all_for_entry(entry))
        head.addWidget(ignore_button)
        layout.addLayout(head)

        for issue in risks + suggests[:1]:      # 最多再带一条建议，避免刷屏
            layout.addLayout(self._build_issue_line(issue))
        return card

    def _build_issue_line(self, issue: strength.Issue) -> QHBoxLayout:
        """一行问题：结论 + 具体原因。"""
        line = QHBoxLayout()
        line.setSpacing(8)

        dot = QLabel("●")
        dot.setObjectName("RiskDot")
        dot.setProperty("level", issue.severity)
        dot.setFixedWidth(12)
        line.addWidget(dot, 0, Qt.AlignTop)

        column = QVBoxLayout()
        column.setSpacing(1)
        title = QLabel(issue.title)
        title.setObjectName("RiskText")
        title.setWordWrap(True)
        column.addWidget(title)
        if issue.detail:
            detail = QLabel(issue.detail)
            detail.setObjectName("Faint")
            detail.setWordWrap(True)
            column.addWidget(detail)
        line.addLayout(column, 1)
        return line

    def _fix_password(self, entry: Entry) -> None:
        """用生成器给这条记录换一个新密码，并复制到剪贴板方便去网站改。"""
        password = GeneratorDialog.get_password(
            self, max(len(entry.password), 18), self.vault.settings)
        if not password:
            return
        self.vault.update_entry(entry.id, {}, new_password=password)
        self._save_vault()
        self.copy_text(password, "新密码", sensitive=True)
        self.reload_all()
        self.toast.show_message("已保存新密码；建议先到网站完成修改，旧密码可在编辑窗口的历史中找回")

    def _build_password_row(self, entry: Entry) -> QFrame:
        """密码行：默认掩码，可切换显示。"""
        row = QFrame()
        row.setObjectName("FieldRow")
        row.setMinimumHeight(52)
        layout = QHBoxLayout(row)
        layout.setContentsMargins(14, 8, 8, 8)
        layout.setSpacing(10)

        icon_label = QLabel()
        icon_label.setPixmap(icons.colored_pixmap("key", "text_faint", 16))
        icon_label.setFixedWidth(18)
        layout.addWidget(icon_label)

        column = QVBoxLayout()
        column.setSpacing(1)
        caption = QLabel("密码")
        caption.setObjectName("FieldLabel")
        column.addWidget(caption)
        self.password_label = QLabel("•" * min(max(len(entry.password), 8), 16))
        self.password_label.setObjectName("Mono")
        self.password_label.setStyleSheet("font-size: 14px; letter-spacing: 1px;")
        self.password_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        column.addWidget(self.password_label)
        layout.addLayout(column, 1)

        self.reveal_button = IconButton("eye", "显示密码", box=28, size=15)
        self.reveal_button.clicked.connect(lambda: self._toggle_password_visibility(entry))
        layout.addWidget(self.reveal_button)
        copy_button = IconButton("copy", "复制密码", box=28, size=15)
        copy_button.clicked.connect(lambda: self.copy_text(entry.password, "密码", sensitive=True))
        layout.addWidget(copy_button)
        return row

    def _build_totp_row(self, entry: Entry) -> QFrame:
        """两步验证行：动态口令 + 倒计时。"""
        config = totp.parse_secret_input(entry.totp_secret)
        row = QFrame()
        row.setObjectName("FieldRow")
        row.setMinimumHeight(58)
        layout = QHBoxLayout(row)
        layout.setContentsMargins(14, 8, 8, 8)
        layout.setSpacing(10)

        icon_label = QLabel()
        icon_label.setPixmap(icons.colored_pixmap(
            "alert" if config is None else "shield-check",
            "danger" if config is None else "accent", 16))
        icon_label.setFixedWidth(18)
        layout.addWidget(icon_label)

        column = QVBoxLayout()
        column.setSpacing(2)
        caption = QLabel("两步验证口令")
        caption.setObjectName("FieldLabel")
        column.addWidget(caption)

        if config is None:
            # 导入的 CSV/JSON 可能带着无法解析的密钥（编辑窗口保存时会校验，
            # 导入路径不会）。这里给出提示而不是让详情页整个崩掉。
            broken = QLabel("密钥格式无法识别，请在编辑窗口重新填写")
            broken.setObjectName("Danger")
            broken.setWordWrap(True)
            column.addWidget(broken)
            layout.addLayout(column, 1)
            fix_button = text_button("去修正", kind="Link")
            fix_button.clicked.connect(lambda: self.edit_entry(entry.id))
            layout.addWidget(fix_button)
            self.totp_label = None
            self._totp_state = None
            return row

        self.totp_label = QLabel("—")
        self.totp_label.setObjectName("Mono")
        self.totp_label.setStyleSheet("font-size: 18px; font-weight: 600; letter-spacing: 2px;")
        column.addWidget(self.totp_label)
        layout.addLayout(column, 1)

        self.totp_countdown = QLabel("")
        self.totp_countdown.setObjectName("Faint")
        layout.addWidget(self.totp_countdown)

        copy_button = IconButton("copy", "复制当前口令", box=28, size=15)
        copy_button.clicked.connect(self._copy_totp)
        layout.addWidget(copy_button)

        self._totp_state = (config, entry.totp_secret)
        self._refresh_totp()
        return row

    def _build_history_section(self, entry: Entry) -> QWidget:
        """历史密码列表。"""
        card = QFrame()
        card.setObjectName("FieldRow")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(8)

        header = QHBoxLayout()
        header.addWidget(widgets.section_title(f"历史密码 · {len(entry.history)}"))
        header.addStretch(1)
        layout.addLayout(header)

        for item in entry.history[:6]:
            line = QHBoxLayout()
            line.setSpacing(8)
            moment = (item.changed_at or "")[:19].replace("T", " ")
            label = QLabel(f"{moment}　{'•' * min(len(item.password), 10)}")
            label.setObjectName("Faint")
            line.addWidget(label, 1)
            copy_button = IconButton("copy", "复制这条历史密码", box=24, size=13)
            copy_button.clicked.connect(
                lambda _=False, p=item.password: self.copy_text(p, "历史密码", sensitive=True))
            line.addWidget(copy_button)
            layout.addLayout(line)
        return card

    # ============================================================ 交互动作

    def set_filter(self, kind: str, value: str = "") -> None:
        """切换筛选条件。"""
        self.filter_kind = kind
        self.filter_value = value
        if kind == "audit":
            self.selected_id = ""       # 进入审计视图先看总体报告
        self._refresh_sidebar()
        self.refresh_list()
        self.refresh_detail()

    def _on_search_changed(self, text: str) -> None:
        self.search_text = text.strip()
        self.refresh_list()

    def _clear_search(self) -> None:
        """Esc：清空搜索并把焦点交回搜索框（无论当前焦点在列表还是别处）。"""
        if self.search_box.text():
            self.search_box.clear()
        self.search_box.setFocus()

    # ------------------------------------------------------------ 键盘操作

    def _navigate_card(self, entry_id: str, delta: int) -> None:
        """↑ / ↓ 在当前列表中切换记录。"""
        order = list(self._cards)
        if not order:
            return
        try:
            index = order.index(entry_id)
        except ValueError:
            index = 0
        target = order[max(0, min(len(order) - 1, index + delta))]
        self.select_entry(target)
        card = self._cards.get(target)
        if card is not None:
            card.setFocus()
            self.list_scroll.ensureWidgetVisible(card)

    def _focus_first_card(self) -> None:
        """搜索框按 ↓：焦点进入列表（优先当前选中的那条）。"""
        order = list(self._cards)
        if not order:
            return
        target = self.selected_id if self.selected_id in self._cards else order[0]
        self.select_entry(target)
        card = self._cards.get(target)
        if card is not None:
            card.setFocus()
            self.list_scroll.ensureWidgetVisible(card)

    def _copy_password_of(self, entry_id: str) -> None:
        """列表里按 Ctrl+C：复制该条记录的密码。"""
        entry = self.vault.find(entry_id)
        if entry is not None:
            self.copy_text(entry.password, "密码", sensitive=True)

    def select_entry(self, entry_id: str) -> None:
        """选中一条记录。"""
        self.selected_id = entry_id
        for eid, card in self._cards.items():
            card.set_selected(eid == entry_id)
        self.refresh_detail()

    def selected_entry(self) -> Entry | None:
        if not self.selected_id:
            return None
        return self.vault.find(self.selected_id)

    # ------------------------------------------------------------ 增删改

    def create_entry(self) -> None:
        """新建记录。"""
        default_category = self.filter_value if self.filter_kind == "category" else DEFAULT_CATEGORY
        default_tags = [self.filter_value] if self.filter_kind == "tag" else []
        dialog = EntryDialog(self, self.vault, None, default_category, default_tags)
        result = dialog.exec()
        if result == QDialog.Accepted:
            entry = Entry(
                title=dialog.data["title"],
                username=dialog.data["username"],
                password=dialog.new_password or "",
                phone=dialog.data["phone"],
                email=dialog.data["email"],
                url=dialog.data["url"],
                notes=dialog.data["notes"],
                category=dialog.data["category"],
                tags=dialog.data["tags"],
                favorite=dialog.data["favorite"],
                totp_secret=dialog.data["totp_secret"],
            )
            self.vault.add_entry(entry)
            self._save_vault()
            self.selected_id = entry.id
            self.reload_all()
            self.toast.show_message("记录已保存")
        elif result == 2:
            pass

    def edit_entry(self, entry_id: str) -> None:
        """编辑记录。"""
        entry = self.vault.find(entry_id)
        if entry is None:
            return
        dialog = EntryDialog(self, self.vault, entry)
        result = dialog.exec()
        if result == QDialog.Accepted:
            self.vault.update_entry(
                entry_id, dialog.data, new_password=dialog.new_password)
            self._save_vault()
            self.selected_id = entry_id
            self.reload_all()
            self.toast.show_message("修改已保存")
        elif result == 2:
            self.delete_entry(entry_id)

    def edit_selected(self) -> None:
        if self.selected_id:
            self.edit_entry(self.selected_id)

    def delete_entry(self, entry_id: str) -> None:
        """移入回收站。"""
        entry = self.vault.find(entry_id)
        if entry is None:
            return
        answer = QMessageBox.question(
            self, "删除记录", f"把「{entry.title}」移入回收站？\n可以稍后恢复。",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if answer != QMessageBox.Yes:
            return
        self.vault.trash_entry(entry_id)
        self._save_vault()
        if self.selected_id == entry_id:
            self.selected_id = ""
        self.reload_all()
        self.toast.show_message("已移入回收站")

    def delete_selected(self) -> None:
        if self.selected_id and self.filter_kind != "trash":
            self.delete_entry(self.selected_id)

    def restore_entry(self, entry_id: str) -> None:
        self.vault.restore_entry(entry_id)
        self._save_vault()
        self.selected_id = entry_id
        self.reload_all()
        self.toast.show_message("已恢复")

    def purge_entry(self, entry_id: str) -> None:
        entry = self.vault.find(entry_id)
        if entry is None:
            return
        answer = QMessageBox.warning(
            self, "彻底删除", f"「{entry.title}」将被永久删除，无法恢复。确定继续吗？",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if answer != QMessageBox.Yes:
            return
        self.vault.purge_entry(entry_id)
        self._save_vault()
        self.selected_id = ""
        self.reload_all()
        self.toast.show_message("已彻底删除", danger=True)

    def empty_trash(self) -> None:
        count = len(self.vault.trashed_entries())
        if not count:
            self.toast.show_message("回收站已经是空的")
            return
        answer = QMessageBox.warning(
            self, "清空回收站", f"将永久删除 {count} 条记录，无法恢复。确定继续吗？",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if answer != QMessageBox.Yes:
            return
        self.vault.empty_trash()
        self._save_vault()
        self.selected_id = ""
        self.reload_all()
        self.toast.show_message(f"已清空回收站（{count} 条）", danger=True)

    def toggle_favorite(self, entry_id: str) -> None:
        if not entry_id:
            return
        now_favorite = self.vault.toggle_favorite(entry_id)
        self._save_vault()
        self.reload_all()
        self.toast.show_message("已加入收藏" if now_favorite else "已取消收藏")

    # ------------------------------------------------------------ 菜单

    def _show_entry_menu(self, entry_id: str, global_pos: QPoint) -> None:
        entry = self.vault.find(entry_id)
        if entry is None:
            return
        menu = QMenu(self)
        if entry.is_deleted:
            menu.addAction(icons.icon("restore", "text_muted"),
                           "恢复", lambda: self.restore_entry(entry_id))
            menu.addAction(icons.icon("trash", "danger"),
                           "彻底删除", lambda: self.purge_entry(entry_id))
        else:
            menu.addAction(icons.icon("copy", "text_muted"), "复制用户名",
                           lambda: self.copy_text(entry.username, "用户名"))
            menu.addAction(icons.icon("copy", "text_muted"), "复制密码",
                           lambda: self.copy_text(entry.password, "密码", sensitive=True))
            menu.addAction(icons.icon("link", "text_muted"), "复制网址",
                           lambda: self.copy_text(entry.url, "网址"))
            menu.addSeparator()
            menu.addAction(icons.icon("pencil", "text_muted"), "编辑",
                           lambda: self.edit_entry(entry_id))
            star_icon = "star-filled" if entry.favorite else "star"
            menu.addAction(icons.icon(star_icon, "text_muted"),
                           "取消收藏" if entry.favorite else "加入收藏",
                           lambda: self.toggle_favorite(entry_id))
            menu.addSeparator()
            menu.addAction(icons.icon("trash", "danger"), "删除",
                           lambda: self.delete_entry(entry_id))
        menu.exec(global_pos)

    def _category_menu(self, name: str, global_pos: QPoint) -> None:
        menu = QMenu(self)
        menu.addAction(icons.icon("pencil", "text_muted"), "重命名分类",
                       lambda: self._rename_category(name))
        if name != DEFAULT_CATEGORY:
            menu.addAction(icons.icon("trash", "danger"), "删除分类",
                           lambda: self._remove_category(name))
        menu.exec(global_pos)

    def _add_category(self) -> None:
        name, ok = QInputDialog.getText(self, "新建分类", "分类名称：")
        if ok and name.strip():
            if self.vault.add_category(name.strip()):
                self._save_vault()
                self.reload_all()

    def _rename_category(self, name: str) -> None:
        new_name, ok = QInputDialog.getText(self, "重命名分类", "新的名称：", text=name)
        if ok and new_name.strip() and new_name.strip() != name:
            if not self.vault.rename_category(name, new_name.strip()):
                self.toast.show_message("分类名已存在或无效", danger=True)
                return
            if self.filter_kind == "category" and self.filter_value == name:
                self.filter_value = new_name.strip()
            self._save_vault()
            self.reload_all()

    def _remove_category(self, name: str) -> None:
        answer = QMessageBox.question(
            self, "删除分类", f"删除分类「{name}」？其中的记录会移动到「未分类」。",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if answer != QMessageBox.Yes:
            return
        self.vault.remove_category(name)
        if self.filter_kind == "category" and self.filter_value == name:
            self.set_filter("all")
        self._save_vault()
        self.reload_all()

    # ------------------------------------------------------------ 复制与显示

    def copy_text(self, text: str, what: str, *, sensitive: bool = False) -> None:
        """复制到剪贴板。

        敏感内容会被排除在 Windows 剪贴板历史与云同步之外，并按设定秒数清空。
        """
        if not text:
            self.toast.show_message(f"没有可复制的{what}", danger=True)
            return
        clipboard_utils.put_text(text, sensitive=sensitive)
        seconds = self.vault.settings.clipboard_clear_seconds
        if sensitive and seconds > 0:
            self._schedule_clipboard_clear(text, seconds)
            self.toast.show_message(f"{what}已复制　·　{seconds} 秒后自动清空剪贴板")
        else:
            self.toast.show_message(f"{what}已复制")

    def _schedule_clipboard_clear(self, expected: str, seconds: int) -> None:
        if self._clipboard_timer is not None:
            self._clipboard_timer.stop()
        timer = QTimer(self)
        timer.setSingleShot(True)
        timer.timeout.connect(lambda: clipboard_utils.clear_if_unchanged(expected))
        timer.start(seconds * 1000)
        self._clipboard_timer = timer

    def _toggle_password_visibility(self, entry: Entry) -> None:
        showing = self.password_label.text() == entry.password
        if showing:
            self.password_label.setText("•" * min(max(len(entry.password), 8), 16))
            self.reveal_button.set_icon_name("eye")
            self.reveal_button.setToolTip("显示密码")
        else:
            self.password_label.setText(entry.password)
            self.reveal_button.set_icon_name("eye-off")
            self.reveal_button.setToolTip("隐藏密码")

    def _copy_totp(self) -> None:
        if self._totp_state is None or self.totp_label is None:
            return                      # 没有可用的 TOTP 配置（含密钥非法的情况）
        config, _secret = self._totp_state
        code = totp.generate_code(config.secret, digits=config.digits,
                                  period=config.period, algorithm=config.algorithm)
        self.copy_text(code, "动态口令", sensitive=True)

    def _normalize_url(self, url: str) -> str:
        return url if "://" in url else "https://" + url

    def _format_time(self, value: str) -> str:
        moment = None
        try:
            moment = datetime.fromisoformat(value)
        except (TypeError, ValueError):
            return "—"
        return moment.strftime("%Y-%m-%d %H:%M")

    # ------------------------------------------------------------ 对话框

    def open_generator(self) -> None:
        GeneratorDialog.get_password(self, settings=self.vault.settings)

    def manage_categories(self) -> None:
        """打开分类管理窗口（新建 / 重命名 / 删除）。"""
        dialog = CategoryDialog(self, self.vault)
        dialog.data_changed.connect(self.reload_all)
        dialog.exec()
        if self.filter_kind == "category" and self.filter_value not in self.vault.categories:
            self.filter_kind = "all"
            self.filter_value = ""
        self.reload_all()

    def open_settings(self) -> None:
        dialog = SettingsDialog(self, self.vault)
        if dialog.exec() == QDialog.Accepted:
            self._save_vault()
            self._apply_settings()
            self.reload_all()
            self.toast.show_message("设置已更新")

    def _jump_to_entry(self, entry_id: str) -> None:
        """从审计报告跳到某条记录（停留在审计视图，方便看完再回到报告）。"""
        self.select_entry(entry_id)
        card = self._cards.get(entry_id)
        if card is not None:
            self.list_scroll.ensureWidgetVisible(card)

    def _back_to_audit(self) -> None:
        """从某条记录回到审计报告。"""
        self.selected_id = ""
        for card in self._cards.values():
            card.set_selected(False)
        self.refresh_detail()

    # ------------------------------------------------------------ 忽略风险提示

    def _ignore_issue(self, entry_id: str, kind: str) -> None:
        """忽略某条记录的某类风险提示（精确到问题类型）。"""
        if not self.vault.ignore_issue(entry_id, kind):
            return
        self._save_vault()
        self.reload_all()
        self.toast.show_message("已忽略该提示，可在审计报告底部随时恢复")

    def _restore_issue(self, entry_id: str, kind: str) -> None:
        """恢复某条被忽略的提示。"""
        if not self.vault.unignore_issue(entry_id, kind):
            return
        self._save_vault()
        self.reload_all()
        self.toast.show_message("已恢复该提示")

    def _restore_all_issues(self) -> None:
        """恢复全部被忽略的提示。"""
        count = self.vault.unignore_all()
        if not count:
            return
        self._save_vault()
        self.reload_all()
        self.toast.show_message(f"已恢复 {count} 项被忽略的提示")

    def _ignore_all_for_entry(self, entry: Entry) -> None:
        """一键忽略这条记录当前的全部风险提示。"""
        issues = strength.entry_issues(
            entry, self.vault.active_entries(), self.vault.settings.password_max_age_days)
        risks = [i for i in issues if i.is_risk]
        if not risks:
            self.toast.show_message("这条记录目前没有需要忽略的提示")
            return

        answer = QMessageBox.question(
            self, "忽略风险提示",
            "不再对「%s」提示以下 %d 项？\n\n%s\n\n"
            "可以随时在「安全审计」底部的已忽略列表里恢复。" % (
                entry.title, len(risks), "\n".join(f"· {i.title}" for i in risks)),
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if answer != QMessageBox.Yes:
            return

        for issue in risks:
            self.vault.ignore_issue(entry.id, issue.kind)
        self._save_vault()
        self.reload_all()
        self.toast.show_message("已忽略这条记录的风险提示")

    # ------------------------------------------------------------ 主题与设置

    def _toggle_theme(self) -> None:
        theme = Theme.instance()
        new_name = "light" if theme.is_dark else "dark"
        theme.set_theme(new_name)
        self.vault.settings.theme = new_name
        self._save_vault()

    def apply_theme(self) -> None:
        """主题变化后刷新自绘元素。"""
        theme = Theme.instance()
        self.theme_button.set_icon_name("sun" if theme.is_dark else "moon")
        self.new_button.setStyleSheet(
            f"QToolButton {{ background: {theme.hex('accent')}; border-radius: 8px; }}"
            f"QToolButton:hover {{ background: {theme.hex('accent_hover')}; }}")
        self.new_button.setIcon(icons.icon("plus", "accent_text", 18))

    def _apply_settings(self) -> None:
        theme = Theme.instance()
        if theme.palette.name != self.vault.settings.theme:
            theme.set_theme(self.vault.settings.theme)
        self._refresh_status()

    # ------------------------------------------------------------ 状态栏与锁定

    def _refresh_status(self) -> None:
        stats = self.vault.statistics()
        self.status_left.setText(
            f"{stats['total']} 条记录　·　{stats['categories']} 个分类　·　"
            f"文件：{self.vault.path}")
        self._update_countdown()

    def _update_countdown(self) -> None:
        minutes = self.vault.settings.auto_lock_minutes
        if minutes <= 0:
            self.status_right.setText("自动锁定：已关闭")
            return
        remaining = minutes * 60 - (time.monotonic() - self._last_activity)
        remaining = max(0, int(remaining))
        self.status_right.setText(f"自动锁定　{remaining // 60:02d}:{remaining % 60:02d}")

    def _refresh_totp(self) -> None:
        """每秒刷新动态口令。

        兜底 try：这个函数由定时器反复调用，任何一条脏数据都不该让
        整个界面在后台报错。
        """
        if self._totp_state is None or self.totp_label is None:
            return
        config, _secret = self._totp_state
        try:
            code = totp.generate_code(config.secret, digits=config.digits,
                                      period=config.period, algorithm=config.algorithm)
            remaining = totp.seconds_remaining(config.period)
        except (ValueError, TypeError):     # binascii.Error 是 ValueError 的子类
            self.totp_label.setText("密钥无法解析")
            self.totp_countdown.setText("")
            self._totp_state = None
            return
        self.totp_label.setText(totp.format_code(code))
        self.totp_countdown.setText(f"{remaining} 秒后刷新")

    def _start_timers(self) -> None:
        self._clock = QTimer(self)
        self._clock.setInterval(TOTP_REFRESH_MS)
        self._clock.timeout.connect(self._tick)
        self._clock.start()

        self._save_timer = QTimer(self)
        self._save_timer.setSingleShot(True)
        self._save_timer.setInterval(AUTO_SAVE_DELAY_MS)

    def _tick(self) -> None:
        self._refresh_totp()
        self._update_countdown()
        minutes = self.vault.settings.auto_lock_minutes
        if minutes > 0 and time.monotonic() - self._last_activity > minutes * 60:
            self.lock("长时间未操作，已自动锁定")

    def note_activity(self) -> None:
        """记录一次用户活动（由事件过滤器调用）。"""
        self._last_activity = time.monotonic()

    def lock(self, reason: str = "") -> None:
        """锁定保险箱并弹出解锁窗口。"""
        if self.vault.is_locked:
            return
        self.vault.lock()
        self.selected_id = ""
        self.hide()
        self.lock_requested.emit(reason)

    def _save_vault(self) -> None:
        """立即保存（数据量小，直接写入即可）。"""
        if self.vault.is_locked:
            return
        try:
            self.vault.save()
        except (OSError, crypto.VaultError) as exc:
            QMessageBox.critical(self, "保存失败", f"无法写入保险箱文件：\n{exc}")

    # ------------------------------------------------------------ 事件

    def rebuild_for_theme(self) -> None:
        """主题切换后整窗重建，确保所有图标与自绘元素都用上新配色。"""
        root = self.layout()
        if root is not None:
            self._clear_layout(root)
            # QWidget 只允许有一个顶层布局：把旧布局转移到临时控件上再销毁
            stale = QWidget()
            stale.setLayout(root)
            stale.deleteLater()
            self._stale_layout = stale
        toast = getattr(self, "toast", None)
        if toast is not None:
            toast.deleteLater()
            self.toast = None
        self._cards.clear()
        self._build_ui()
        self.reload_all()
        self.apply_theme()

    def changeEvent(self, event) -> None:  # noqa: N802 - Qt 命名
        if event.type() == QEvent.WindowStateChange and self.isMinimized():
            if self.vault.settings.lock_on_minimize and not self.vault.is_locked:
                QTimer.singleShot(0, lambda: self.lock("窗口已最小化，自动锁定"))
        super().changeEvent(event)

    def closeEvent(self, event) -> None:  # noqa: N802 - Qt 命名
        self._save_vault()
        self.vault.lock()
        super().closeEvent(event)
