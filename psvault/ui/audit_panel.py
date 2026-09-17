"""安全审计报告面板。

它不是"再列一遍记录"，而是直接回答**风险在哪**：
每一项都写清楚是哪一条记录、属于哪类问题、具体原因是什么。
面板直接嵌在主界面右侧（外层已有滚动区域），因此是 QWidget 而不是对话框。
"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QVBoxLayout,
    QWidget,
)

from ..core import strength
from ..core.storage import Vault
from . import icons, widgets
from .widgets import Badge, IconButton, RingGauge, text_button

# 严重程度 -> 徽章样式
SEVERITY_BADGE = {
    "high": "danger",
    "medium": "warning",
    "low": "accent",
    "info": "plain",
}


class AuditPanel(QWidget):
    """完整的安全审计报告。"""

    entry_selected = Signal(str)            # 点击"查看"时跳转到该记录
    issue_ignored = Signal(str, str)        # (记录 id, 问题类型) 忽略这类提示
    issue_restored = Signal(str, str)       # 恢复某条被忽略的提示
    all_restored = Signal()                 # 恢复全部忽略

    def __init__(self, parent: QWidget | None, vault: Vault) -> None:
        super().__init__(parent)
        self.vault = vault
        self.setObjectName("AuditPanel")

        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(14)
        self.refresh()

    # ------------------------------------------------------------ 构建

    def refresh(self) -> None:
        """重新体检并重建整个面板。"""
        widgets.clear_layout(self._layout)

        entries = self.vault.active_entries()
        max_age = self.vault.settings.password_max_age_days

        grouped: dict[str, list[tuple[object, strength.Issue]]] = {
            key: [] for key, _title, _icon, _hint in strength.ISSUE_GROUPS
        }
        entries_with_risk = 0
        for entry in entries:
            issues = strength.entry_issues(entry, entries, max_age)
            if any(issue.is_risk for issue in issues):
                entries_with_risk += 1
            for issue in issues:
                if issue.ignored:
                    continue        # 已忽略的单独放在报告末尾，不混进正式问题里
                grouped.setdefault(issue.kind, []).append((entry, issue))
        ignored_items = strength.ignored_issues(entries, max_age)

        risk_total = sum(
            len(grouped.get(key, []))
            for key, _t, _i, _h in strength.ISSUE_GROUPS if key != "suggest"
        )
        score = self._score(entries, risk_total)

        counts = {key: len(grouped.get(key, []))
                  for key, _t, _i, _h in strength.ISSUE_GROUPS}
        self._layout.addWidget(
            self._build_hero(score, entries, entries_with_risk, risk_total, counts))

        # 没有任何风险时给一个明确的"健康"结论
        if risk_total == 0:
            self._layout.addWidget(self._build_all_clear(entries))
        for key, title, icon_name, hint in strength.ISSUE_GROUPS:
            items = grouped.get(key, [])
            if not items:
                continue
            self._layout.addWidget(self._build_group(key, title, icon_name, hint, items))

        ignored_card = self._build_ignored(ignored_items)
        if ignored_card is not None:
            self._layout.addWidget(ignored_card)

        self._layout.addWidget(self._build_footer(entries))
        self._layout.addStretch(1)

    def _build_hero(self, score: int, entries: list, affected: int, risk_total: int,
                    counts: dict[str, int]) -> QWidget:
        """顶部总览：评分环 + 结论 + 分类计数。"""
        card = QFrame()
        card.setObjectName("Hero")
        layout = QHBoxLayout(card)
        layout.setContentsMargins(22, 18, 22, 18)
        layout.setSpacing(22)

        gauge = RingGauge(120)
        gauge.set_value(score, "安全评分")
        layout.addWidget(gauge, 0, Qt.AlignVCenter)

        column = QVBoxLayout()
        column.setSpacing(8)

        title = QLabel(self._score_title(score, risk_total))
        title.setObjectName("PageTitle")
        column.addWidget(title)

        if not entries:
            summary = "保险箱里还没有记录，添加账号后这里会给出体检结果。"
        elif risk_total == 0:
            summary = (f"已检查 {len(entries)} 条记录，没有发现需要处理的问题。"
                       f"可以点左侧任意记录查看详情。")
        else:
            summary = (f"已检查 {len(entries)} 条记录，其中 {affected} 条存在 "
                       f"{risk_total} 处需要关注的问题，具体原因列在下面。")
        column.addWidget(widgets.hint_label(summary, faint=False))

        chips = QHBoxLayout()
        chips.setSpacing(6)
        for key, label, _icon, _hint in strength.ISSUE_GROUPS:
            count = counts.get(key, 0)
            if not count:
                continue
            kind = "danger" if key in ("weak", "reused") else (
                "warning" if key == "aged" else "plain")
            chips.addWidget(Badge(f"{label} {count}", kind))
        chips.addStretch(1)
        column.addLayout(chips)
        layout.addLayout(column, 1)
        return card

    def _build_all_clear(self, entries: list) -> QWidget:
        card = QFrame()
        card.setObjectName("Card")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(8)
        row = QHBoxLayout()
        row.setSpacing(10)
        icon_label = QLabel()
        icon_label.setPixmap(icons.colored_pixmap("shield-check", "success", 20))
        row.addWidget(icon_label)
        text = QLabel("没有发现弱密码、重复密码或长期未更换的密码")
        text.setObjectName("EntryTitle")
        row.addWidget(text)
        row.addStretch(1)
        layout.addLayout(row)
        layout.addWidget(widgets.hint_label(
            "继续保持：为每个网站使用独立的高强度密码，重要账号开启两步验证。"))
        return card

    def _build_group(self, key: str, title: str, icon_name: str, hint: str,
                     items: list[tuple[object, strength.Issue]]) -> QWidget:
        """一个问题分组：标题 + 说明 + 每条记录的具体原因。"""
        card = QFrame()
        card.setObjectName("Card")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(10)

        header = QHBoxLayout()
        header.setSpacing(8)
        icon_label = QLabel()
        icon_label.setPixmap(icons.colored_pixmap(
            icon_name, "danger" if key in ("weak", "reused") else "text_muted", 16))
        header.addWidget(icon_label)
        header.addWidget(widgets.section_title(title))
        header.addStretch(1)
        header.addWidget(Badge(str(len(items)),
                              "danger" if key in ("weak", "reused") else "warning"))
        layout.addLayout(header)
        layout.addWidget(widgets.hint_label(hint))

        # 纯建议类的问题可能很多，只列前几条，避免报告被刷屏
        limit = 5 if key == "suggest" else 40
        for entry, issue in items[:limit]:
            layout.addWidget(self._build_row(entry, issue))
        if len(items) > limit:
            layout.addWidget(widgets.hint_label(f"…… 其余 {len(items) - limit} 条未列出"))
        return card

    def _build_row(self, entry, issue: strength.Issue) -> QWidget:
        """单条问题：记录名 + 账号 + 具体原因 + 查看按钮。"""
        row = QFrame()
        row.setObjectName("FieldRow")
        layout = QHBoxLayout(row)
        layout.setContentsMargins(12, 9, 8, 9)
        layout.setSpacing(10)

        column = QVBoxLayout()
        column.setSpacing(3)

        top = QHBoxLayout()
        top.setSpacing(8)
        name = QLabel(widgets.elide(entry.title, 22))
        name.setObjectName("FieldValue")
        top.addWidget(name)
        account = entry.username or entry.domain()
        if account:
            account_label = QLabel(widgets.elide(account, 20))
            account_label.setObjectName("Faint")
            top.addWidget(account_label)
        top.addWidget(Badge(issue.short_label, SEVERITY_BADGE.get(issue.severity, "plain")))
        top.addStretch(1)
        column.addLayout(top)

        detail = QLabel(issue.detail)
        detail.setObjectName("Faint")
        detail.setWordWrap(True)
        column.addWidget(detail)
        layout.addLayout(column, 1)

        ignore_button = IconButton("ignore", f"忽略「{issue.short_label}」提示", box=26, size=14)
        ignore_button.clicked.connect(
            lambda _=False, eid=entry.id, k=issue.kind: self.issue_ignored.emit(eid, k))
        layout.addWidget(ignore_button, 0, Qt.AlignTop)

        view_button = text_button("查看", kind="Link")
        view_button.clicked.connect(lambda _=False, eid=entry.id: self.entry_selected.emit(eid))
        layout.addWidget(view_button, 0, Qt.AlignTop)
        return row

    def _build_ignored(self, items: list[tuple[object, strength.Issue]]) -> QWidget | None:
        """已忽略的提示：集中列出并可随时恢复，避免"点错了再也看不到"。"""
        if not items:
            return None

        card = QFrame()
        card.setObjectName("Card")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(10)

        header = QHBoxLayout()
        header.setSpacing(8)
        icon_label = QLabel()
        icon_label.setPixmap(icons.colored_pixmap("ignore", "text_faint", 15))
        header.addWidget(icon_label)
        header.addWidget(widgets.section_title(f"已忽略的提示 · {len(items)}"))
        header.addStretch(1)
        restore_all = text_button("全部恢复", kind="Link")
        restore_all.clicked.connect(lambda _=False: self.all_restored.emit())
        header.addWidget(restore_all)
        layout.addLayout(header)
        layout.addWidget(widgets.hint_label(
            "这些提示已被你忽略，不再计入安全评分。随时可以恢复。"))

        for entry, issue in items[:20]:
            line = QHBoxLayout()
            line.setSpacing(10)
            name = QLabel(widgets.elide(entry.title, 18))
            name.setObjectName("FieldValue")
            line.addWidget(name)
            account = entry.username or entry.domain()
            if account:
                account_label = QLabel(widgets.elide(account, 16))
                account_label.setObjectName("Faint")
                line.addWidget(account_label)
            line.addStretch(1)
            tag = QLabel(issue.title)
            tag.setObjectName("Faint")
            line.addWidget(tag)
            restore = text_button("恢复", kind="Link")
            restore.clicked.connect(
                lambda _=False, eid=entry.id, k=issue.kind: self.issue_restored.emit(eid, k))
            line.addWidget(restore)
            layout.addLayout(line)

        if len(items) > 20:
            layout.addWidget(widgets.hint_label(f"…… 其余 {len(items) - 20} 条未列出"))
        return card

    def _build_footer(self, entries: list) -> QWidget:
        card = QFrame()
        card.setObjectName("Card")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(8)
        layout.addWidget(widgets.section_title("怎么处理"))
        for text in (
            "点任意一行的「查看」可以直接跳到该记录，在详情页用生成器换一个新密码。",
            "重复使用的密码建议优先处理：换掉其中一个，两个账号就都安全了。",
            "确实不想处理的提示，点行尾的 ⊘ 忽略；随时可以在下方「已忽略的提示」里恢复。",
            "长期未更换的提醒天数可以在「设置 → 安全」里调整。",
        ):
            line = QHBoxLayout()
            line.setSpacing(8)
            dot = QLabel("·")
            dot.setObjectName("Faint")
            line.addWidget(dot, 0, Qt.AlignTop)
            line.addWidget(widgets.hint_label(text), 1)
            layout.addLayout(line)
        return card

    # ------------------------------------------------------------ 评分

    def _score(self, entries: list, risk_total: int) -> int:
        """按"有问题的记录占比"折算 0~100 分。"""
        if not entries:
            return 100
        if risk_total == 0:
            return 100
        affected = min(risk_total, len(entries))
        ratio = affected / len(entries)
        return max(10, int(round(100 * (1 - ratio * 0.85))))

    def _score_title(self, score: int, risk_total: int) -> str:
        if risk_total == 0:
            return "整体状况良好"
        if score >= 80:
            return "基本安全，有少量可以改进的地方"
        if score >= 55:
            return "存在一些密码风险，建议抽空处理"
        return "风险较多，建议尽快处理"
