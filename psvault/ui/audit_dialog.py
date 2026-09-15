"""安全审计窗口：集中列出弱密码、重复密码与长期未更换的密码。"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from ..core import strength
from ..core.models import Entry
from ..core.storage import Vault
from . import icons, widgets
from .widgets import Badge, RingGauge, text_button


class AuditDialog(QDialog):
    """安全审计报告。点击任意记录可跳转到主界面查看。"""

    entry_selected = Signal(str)

    def __init__(self, parent: QWidget | None, vault: Vault) -> None:
        super().__init__(parent)
        self.vault = vault
        self.setWindowTitle("安全审计")
        self.setWindowIcon(icons.app_icon())
        self.setMinimumSize(660, 640)
        self.resize(700, 700)
        self.setModal(True)
        self._build_ui()

    # ------------------------------------------------------------ 界面

    def _build_ui(self) -> None:
        entries = self.vault.active_entries()
        report = strength.audit(entries, self.vault.settings.password_max_age_days)
        score = self._score(entries, report)

        root = QVBoxLayout(self)
        root.setContentsMargins(22, 20, 22, 16)
        root.setSpacing(14)

        # 概览卡片
        hero = QFrame()
        hero.setObjectName("Hero")
        hero_layout = QHBoxLayout(hero)
        hero_layout.setContentsMargins(22, 18, 22, 18)
        hero_layout.setSpacing(22)

        gauge = RingGauge(120)
        gauge.set_value(score, "安全评分")
        hero_layout.addWidget(gauge, 0, Qt.AlignVCenter)

        summary = QVBoxLayout()
        summary.setSpacing(8)
        title = QLabel(self._score_title(score))
        title.setObjectName("PageTitle")
        summary.addWidget(title)

        issue_count = len(report["weak"]) + len(report["reused"]) + len(report["aged"])
        if issue_count == 0:
            text = "没有发现明显问题，继续保持：为每个网站使用独立的高强度密码。"
        else:
            text = (f"共发现 {issue_count} 处可以改进的地方。"
                    f"被重复使用的密码一旦泄漏，会让其他账号一并失守，建议优先处理。")
        summary.addWidget(widgets.hint_label(text, faint=False))

        chips = QHBoxLayout()
        chips.setSpacing(6)
        chips.addWidget(Badge(f"弱密码 {len(report['weak'])}",
                              "danger" if report["weak"] else "success"))
        chips.addWidget(Badge(f"重复使用 {len(report['reused'])}",
                              "warning" if report["reused"] else "success"))
        chips.addWidget(Badge(f"长期未更换 {len(report['aged'])}",
                              "warning" if report["aged"] else "success"))
        chips.addWidget(Badge(f"未设密码 {len(report['empty'])}", "plain"))
        chips.addStretch(1)
        summary.addLayout(chips)
        hero_layout.addLayout(summary, 1)
        root.addWidget(hero)

        # 问题列表
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.NoFrame)
        host = QWidget()
        layout = QVBoxLayout(host)
        layout.setContentsMargins(0, 0, 6, 0)
        layout.setSpacing(14)

        self._add_group(layout, "弱密码", "trash",
                        [(e, f"强度：{strength.evaluate(e.password).label}") for e in report["weak"]],
                        "所有密码强度都达标")
        reused_items = []
        for group in report["reused"]:
            for entry in group:
                reused_items.append((entry, f"与另外 {len(group) - 1} 条记录使用相同密码"))
        self._add_group(layout, "重复使用的密码", "copy", reused_items, "没有重复使用的密码")
        self._add_group(layout, "长期未更换", "clock",
                        [(e, f"已 {e.age_days()} 天未修改") for e in report["aged"]],
                        f"都在 {self.vault.settings.password_max_age_days} 天内更新过")
        self._add_group(layout, "未设置密码", "info",
                        [(e, "这条记录还没有保存密码") for e in report["empty"]],
                        "每条记录都保存了密码")

        layout.addStretch(1)
        scroll.setWidget(host)
        root.addWidget(scroll, 1)

        footer = QHBoxLayout()
        footer.addStretch(1)
        close_button = text_button("关闭", kind="Primary", icon_name="check",
                                   token="accent_text", size=16)
        close_button.clicked.connect(self.accept)
        footer.addWidget(close_button)
        root.addLayout(footer)

    def _add_group(self, layout: QVBoxLayout, title: str, icon_name: str,
                   items: list[tuple[Entry, str]], ok_text: str) -> None:
        """渲染一个审计分区。"""
        card = QFrame()
        card.setObjectName("Card")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(16, 14, 16, 14)
        card_layout.setSpacing(10)

        header = QHBoxLayout()
        header.setSpacing(8)
        icon_label = QLabel()
        icon_label.setPixmap(icons.colored_pixmap(
            icon_name, "danger" if items else "success", 16))
        header.addWidget(icon_label)
        header.addWidget(widgets.section_title(title))
        header.addStretch(1)
        header.addWidget(Badge(str(len(items)), "danger" if items else "success"))
        card_layout.addLayout(header)

        if not items:
            card_layout.addWidget(widgets.hint_label("✓  " + ok_text))
        else:
            for entry, reason in items[:30]:
                card_layout.addLayout(self._entry_line(entry, reason))
            if len(items) > 30:
                card_layout.addWidget(widgets.hint_label(f"…… 其余 {len(items) - 30} 条未列出"))
        layout.addWidget(card)

    def _entry_line(self, entry: Entry, reason: str) -> QHBoxLayout:
        """单条问题记录。"""
        line = QHBoxLayout()
        line.setSpacing(10)

        name = QLabel(widgets.elide(entry.title, 24))
        name.setObjectName("FieldValue")
        line.addWidget(name)

        extra = entry.username or entry.domain()
        if extra:
            account = QLabel(widgets.elide(extra, 20))
            account.setObjectName("Faint")
            line.addWidget(account)

        line.addStretch(1)

        reason_label = QLabel(reason)
        reason_label.setObjectName("Faint")
        line.addWidget(reason_label)

        view_button = text_button("查看", kind="Link")
        view_button.clicked.connect(lambda _=False, eid=entry.id: self._jump(eid))
        line.addWidget(view_button)
        return line

    def _jump(self, entry_id: str) -> None:
        self.entry_selected.emit(entry_id)
        self.accept()

    # ------------------------------------------------------------ 评分

    def _score(self, entries: list[Entry], report: dict) -> int:
        """按问题数量折算 0~100 分。"""
        if not entries:
            return 100
        total = len(entries)
        penalty = (len(report["weak"]) * 60 + len(report["reused"]) * 12
                   + len(report["aged"]) * 6 + len(report["empty"]) * 4)
        return max(5, min(100, 100 - penalty * 100 // max(total * 10, 1) * 2))

    def _score_title(self, score: int) -> str:
        if score >= 85:
            return "整体状况良好"
        if score >= 65:
            return "基本安全，仍有改进空间"
        if score >= 45:
            return "存在明显的密码风险"
        return "风险较高，建议尽快处理"
