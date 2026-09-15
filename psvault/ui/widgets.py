"""通用界面控件：图标按钮、字段行、强度条、标签胶囊、导航项、轻提示等。

所有控件都从主题令牌取色，因此天然支持浅色 / 深色两套皮肤。
"""

from __future__ import annotations

import colorsys
import hashlib
from typing import Callable

from PySide6.QtCore import QEasingCurve, QPropertyAnimation, QSize, Qt, QTimer
from PySide6.QtGui import QColor, QFont, QPainter, QPixmap
from PySide6.QtWidgets import (
    QFrame,
    QGraphicsOpacityEffect,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSizePolicy,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from . import icons
from .theme import Theme


# ---------------------------------------------------------------- 工具函数

def restyle(widget: QWidget) -> None:
    """属性变化后强制刷新 QSS。"""
    widget.style().unpolish(widget)
    widget.style().polish(widget)
    widget.update()


def elide(text: str, limit: int) -> str:
    """超长文本截断。"""
    text = text or ""
    return text if len(text) <= limit else text[: limit - 1] + "…"


# ---------------------------------------------------------------- 基础按钮

class IconButton(QToolButton):
    """方形图标按钮。"""

    def __init__(self, name: str, tooltip: str = "", token: str = "text_muted",
                 size: int = 18, box: int = 32, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._name = name
        self._token = token
        self._size = size
        self.setCursor(Qt.PointingHandCursor)
        self.setFixedSize(box, box)
        self.setIconSize(QSize(size, size))
        if tooltip:
            self.setToolTip(tooltip)
        self.setIcon(icons.icon(name, token, size))

    def refresh_theme(self) -> None:
        """主题变化后重新着色。"""
        self.setIcon(icons.icon(self._name, self._token, self._size))

    def set_token(self, token: str) -> None:
        self._token = token
        self.refresh_theme()

    def set_icon_name(self, name: str) -> None:
        self._name = name
        self.refresh_theme()


def text_button(text: str, *, kind: str = "", icon_name: str = "",
                token: str = "text_muted", size: int = 16) -> QPushButton:
    """构造统一风格的文字按钮。kind 取 Primary / Danger / Ghost / Link。"""
    button = QPushButton(text)
    button.setCursor(Qt.PointingHandCursor)
    if kind:
        button.setObjectName(kind)
    if icon_name:
        button.setIcon(icons.icon(icon_name, token, size))
        button.setIconSize(QSize(size, size))
    return button


# ---------------------------------------------------------------- 文本与容器

def section_title(text: str) -> QLabel:
    """分组小标题（全大写细体）。"""
    label = QLabel(text)
    label.setObjectName("SectionTitle")
    return label


def hint_label(text: str, *, faint: bool = True) -> QLabel:
    """灰色说明文字。"""
    label = QLabel(text)
    label.setObjectName("Faint" if faint else "Hint")
    label.setWordWrap(True)
    return label


def divider(horizontal: bool = True) -> QFrame:
    """1px 分隔线。"""
    line = QFrame()
    line.setObjectName("Divider")
    if horizontal:
        line.setFixedHeight(1)
        line.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
    else:
        line.setFixedWidth(1)
        line.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Expanding)
    return line


class Card(QFrame):
    """带描边的卡片容器。"""

    def __init__(self, parent: QWidget | None = None, object_name: str = "Card") -> None:
        super().__init__(parent)
        self.setObjectName(object_name)


# ---------------------------------------------------------------- 头像

def avatar_pixmap(text: str, size: int = 40, scale: int = 2) -> QPixmap:
    """根据文字生成确定性的圆形字母头像（颜色由内容哈希决定）。"""
    theme = Theme.instance()
    digest = hashlib.md5((text or "?").encode("utf-8")).hexdigest()
    hue = int(digest[:4], 16) % 360 / 360.0

    # 低饱和度配色，保证多条目并存时依然克制
    if theme.is_dark:
        base = colorsys.hls_to_rgb(hue, 0.28, 0.32)
        fg = colorsys.hls_to_rgb(hue, 0.82, 0.40)
    else:
        base = colorsys.hls_to_rgb(hue, 0.93, 0.42)
        fg = colorsys.hls_to_rgb(hue, 0.34, 0.40)

    canvas = QPixmap(size * scale, size * scale)
    canvas.fill(Qt.transparent)
    painter = QPainter(canvas)
    painter.setRenderHint(QPainter.Antialiasing, True)
    painter.setPen(Qt.NoPen)
    painter.setBrush(QColor.fromRgbF(*base))
    painter.drawEllipse(0, 0, size * scale, size * scale)

    initial = next((ch for ch in (text or "") if ch.strip()), "?")
    font = QFont()
    font.setPixelSize(int(size * scale * 0.44))
    font.setWeight(QFont.DemiBold)
    painter.setFont(font)
    painter.setPen(QColor.fromRgbF(*fg))
    painter.drawText(canvas.rect(), Qt.AlignCenter, initial.upper())
    painter.end()
    canvas.setDevicePixelRatio(float(scale))
    return canvas


class Avatar(QLabel):
    """圆形字母头像控件。"""

    def __init__(self, text: str = "?", size: int = 40, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._text = text
        self._size = size
        self.setFixedSize(size, size)
        self.setPixmap(avatar_pixmap(text, size))

    def set_text(self, text: str) -> None:
        self._text = text
        self.setPixmap(avatar_pixmap(text, self._size))

    def refresh_theme(self) -> None:
        self.setPixmap(avatar_pixmap(self._text, self._size))


# ---------------------------------------------------------------- 输入控件

class SecretLineEdit(QLineEdit):
    """带"显示 / 隐藏"按钮的密码输入框。"""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setEchoMode(QLineEdit.Password)
        self._button = QToolButton(self)
        self._button.setCursor(Qt.PointingHandCursor)
        self._button.setAutoRaise(True)
        self._button.setToolTip("显示密码")
        self._button.setIconSize(QSize(16, 16))
        self._button.setFixedSize(26, 26)
        self._button.clicked.connect(self._toggle)
        self.refresh_theme()
        self.setTextMargins(0, 0, 30, 0)

    def resizeEvent(self, event) -> None:  # noqa: N802 - Qt 命名
        super().resizeEvent(event)
        self._button.move(self.width() - 32, (self.height() - 26) // 2)

    def _toggle(self) -> None:
        hidden = self.echoMode() == QLineEdit.Password
        self.setEchoMode(QLineEdit.Normal if hidden else QLineEdit.Password)
        self._button.setToolTip("隐藏密码" if hidden else "显示密码")
        self.refresh_theme()

    def refresh_theme(self) -> None:
        showing = self.echoMode() == QLineEdit.Normal
        self._button.setIcon(icons.icon("eye-off" if showing else "eye", "text_faint", 16))


class SearchBox(QLineEdit):
    """左侧带放大镜图标的搜索框。"""

    def __init__(self, placeholder: str = "搜索…", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("Search")
        self.setPlaceholderText(placeholder)
        self.setClearButtonEnabled(True)
        self.setTextMargins(24, 0, 0, 0)
        self._action = self.addAction(icons.icon("search", "text_faint", 16), QLineEdit.LeadingPosition)


# ---------------------------------------------------------------- 强度条

STRENGTH_TOKENS = ("danger", "danger", "warning", "accent", "success")


class StrengthMeter(QWidget):
    """密码强度条：分段填充 + 文字说明。"""

    def __init__(self, parent: QWidget | None = None, segments: int = 4) -> None:
        super().__init__(parent)
        self._score = 0
        self._label = ""
        self._segments = segments
        self.setFixedHeight(6)

    def set_state(self, score: int, label: str = "") -> None:
        """score 取 0~4。"""
        self._score = max(0, min(4, score))
        self._label = label
        self.update()

    def paintEvent(self, event) -> None:  # noqa: N802 - Qt 命名
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing, True)
        painter.setPen(Qt.NoPen)

        theme = Theme.instance()
        width = self.width()
        height = self.height()
        gap = 4
        seg_width = (width - gap * (self._segments - 1)) / self._segments

        # 已点亮的段数：0 分点亮 1 段，4 分点亮全部
        filled = self._score + 1 if self._score < 4 else 4
        active = theme.hex(STRENGTH_TOKENS[self._score]) if self._label else theme.hex("border")
        painter.setBrush(QColor(theme.hex("hover")))
        for index in range(self._segments):
            x = index * (seg_width + gap)
            painter.drawRoundedRect(int(x), 0, int(seg_width), height, 3, 3)
        if self._label:
            painter.setBrush(QColor(active))
            for index in range(filled):
                x = index * (seg_width + gap)
                painter.drawRoundedRect(int(x), 0, int(seg_width), height, 3, 3)
        painter.end()


class RingGauge(QWidget):
    """环形评分表：用于安全审计的总分展示。"""

    def __init__(self, size: int = 116, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._value = 0
        self._caption = ""
        self.setFixedSize(size, size)

    def set_value(self, value: int, caption: str = "") -> None:
        """value 取 0~100。"""
        self._value = max(0, min(100, int(value)))
        self._caption = caption
        self.update()

    def paintEvent(self, event) -> None:  # noqa: N802 - Qt 命名
        theme = Theme.instance()
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing, True)

        thickness = 12
        margin = thickness / 2 + 2
        rect = self.rect().adjusted(int(margin), int(margin), -int(margin), -int(margin))

        pen = painter.pen()
        pen.setWidth(thickness)
        pen.setCapStyle(Qt.RoundCap)

        pen.setColor(QColor(theme.hex("hover")))
        painter.setPen(pen)
        painter.drawArc(rect, 0, 360 * 16)

        if self._value >= 80:
            token = "success"
        elif self._value >= 60:
            token = "accent"
        elif self._value >= 40:
            token = "warning"
        else:
            token = "danger"
        pen.setColor(QColor(theme.hex(token)))
        painter.setPen(pen)
        painter.drawArc(rect, 90 * 16, -int(360 * 16 * self._value / 100))

        painter.setPen(QColor(theme.hex("text")))
        font = QFont()
        font.setPixelSize(int(self.width() * 0.28))
        font.setWeight(QFont.DemiBold)
        painter.setFont(font)
        painter.drawText(self.rect().adjusted(0, -6, 0, -6), Qt.AlignCenter, str(self._value))

        if self._caption:
            painter.setPen(QColor(theme.hex("text_faint")))
            font.setPixelSize(int(self.width() * 0.11))
            font.setWeight(QFont.Normal)
            painter.setFont(font)
            painter.drawText(self.rect().adjusted(0, int(self.height() * 0.34), 0, 0),
                             Qt.AlignCenter, self._caption)
        painter.end()


# ---------------------------------------------------------------- 标签胶囊

class TagChip(QPushButton):
    """可点击的标签胶囊。"""

    def __init__(self, text: str, active: bool = False, parent: QWidget | None = None) -> None:
        super().__init__(text, parent)
        self.setObjectName("TagChip")
        self.setCursor(Qt.PointingHandCursor)
        self.setCheckable(True)
        self.setChecked(active)
        self.setProperty("active", "true" if active else "false")

    def set_active(self, active: bool) -> None:
        self.setChecked(active)
        self.setProperty("active", "true" if active else "false")
        restyle(self)


class Badge(QLabel):
    """小圆角计数/状态标签。kind: plain | accent | danger | warning | success。"""

    def __init__(self, text: str = "", kind: str = "plain", parent: QWidget | None = None) -> None:
        super().__init__(text, parent)
        names = {"plain": "Badge", "accent": "BadgeAccent", "danger": "BadgeDanger",
                 "warning": "BadgeWarning", "success": "BadgeSuccess"}
        self.setObjectName(names.get(kind, "Badge"))
        self.setAlignment(Qt.AlignCenter)

    def set_kind(self, kind: str) -> None:
        names = {"plain": "Badge", "accent": "BadgeAccent", "danger": "BadgeDanger",
                 "warning": "BadgeWarning", "success": "BadgeSuccess"}
        self.setObjectName(names.get(kind, "Badge"))
        restyle(self)


# ---------------------------------------------------------------- 导航项

class NavItem(QPushButton):
    """侧栏导航项：图标 + 文字 + 右侧计数。"""

    def __init__(self, text: str, icon_name: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("NavItem")
        self.setCheckable(True)
        self.setCursor(Qt.PointingHandCursor)
        self.setIconSize(QSize(17, 17))
        self.setMinimumHeight(34)
        self._icon_name = icon_name
        self._text = text
        self._count = 0
        self.setText("  " + text)
        self.refresh_theme()

    def set_count(self, count: int) -> None:
        self._count = count
        self.setText(f"  {self._text}" + (f"   {count}" if count else ""))

    def set_icon_name(self, name: str) -> None:
        self._icon_name = name
        self.refresh_theme()

    def refresh_theme(self) -> None:
        token = "accent" if self.isChecked() else "text_muted"
        self.setIcon(icons.icon(self._icon_name, token, 17))

    def setChecked(self, checked: bool) -> None:  # noqa: N802 - Qt 命名
        super().setChecked(checked)
        self.refresh_theme()


# ---------------------------------------------------------------- 空状态

class EmptyState(QWidget):
    """列表 / 详情为空时的占位提示。"""

    def __init__(self, icon_name: str, title: str, description: str = "",
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(10)
        layout.addStretch(1)

        self._icon_name = icon_name
        self._icon_label = QLabel()
        self._icon_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self._icon_label)

        self._title = QLabel(title)
        self._title.setObjectName("EmptyTitle")
        self._title.setAlignment(Qt.AlignCenter)
        layout.addWidget(self._title)

        if description:
            description_label = QLabel(description)
            description_label.setObjectName("Faint")
            description_label.setAlignment(Qt.AlignCenter)
            description_label.setWordWrap(True)
            layout.addWidget(description_label)
        layout.addStretch(1)

        self.refresh_theme()

    def refresh_theme(self) -> None:
        self._icon_label.setPixmap(icons.colored_pixmap(self._icon_name, "text_faint", 44))


# ---------------------------------------------------------------- 轻提示

class Toast(QLabel):
    """悬浮在窗口顶部的轻提示，自动淡出。"""

    def __init__(self, parent: QWidget) -> None:
        super().__init__(parent)
        self.setObjectName("Toast")
        self.setAlignment(Qt.AlignCenter)
        self.hide()
        self._effect = QGraphicsOpacityEffect(self)
        self.setGraphicsEffect(self._effect)
        self._animation = QPropertyAnimation(self._effect, b"opacity", self)
        self._animation.setDuration(220)
        self._animation.setEasingCurve(QEasingCurve.InOutQuad)
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self._fade_out)

    def show_message(self, text: str, *, danger: bool = False, duration: int = 2600) -> None:
        """展示提示文字。"""
        self.setText("  " + text + "  ")
        self.setProperty("danger", "true" if danger else "false")
        restyle(self)
        self.adjustSize()
        self._reposition()
        self.raise_()
        self.show()
        self._effect.setOpacity(0.0)
        self._animation.stop()
        self._animation.setStartValue(0.0)
        self._animation.setEndValue(1.0)
        self._animation.start()
        self._timer.start(duration)

    def _fade_out(self) -> None:
        self._animation.stop()
        self._animation.setStartValue(self._effect.opacity())
        self._animation.setEndValue(0.0)
        self._animation.finished.connect(self._maybe_hide)
        self._animation.start()

    def _maybe_hide(self) -> None:
        try:
            self._animation.finished.disconnect(self._maybe_hide)
        except (RuntimeError, TypeError):
            pass
        if self._effect.opacity() <= 0.01:
            self.hide()

    def _reposition(self) -> None:
        parent = self.parentWidget()
        if parent is None:
            return
        x = (parent.width() - self.width()) // 2
        self.move(max(12, x), 18)


# ---------------------------------------------------------------- 字段行

class FieldRow(QFrame):
    """详情面板的一条字段：标签 + 值 + 若干操作按钮。"""

    def __init__(self, label: str, value: str, icon_name: str = "",
                 actions: list[tuple[str, str, Callable[[], None]]] | None = None,
                 mono: bool = False, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("FieldRow")
        self.setMinimumHeight(46)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 8, 8, 8)
        layout.setSpacing(10)

        if icon_name:
            icon_label = QLabel()
            icon_label.setPixmap(icons.colored_pixmap(icon_name, "text_faint", 16))
            icon_label.setFixedWidth(18)
            layout.addWidget(icon_label)

        column = QVBoxLayout()
        column.setSpacing(1)
        column.setContentsMargins(0, 0, 0, 0)

        caption = QLabel(label)
        caption.setObjectName("FieldLabel")
        column.addWidget(caption)

        self.value_label = QLabel(value or "—")
        self.value_label.setObjectName("Mono" if mono else "FieldValue")
        self.value_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.value_label.setWordWrap(False)
        column.addWidget(self.value_label)
        layout.addLayout(column, 1)

        self._buttons: list[IconButton] = []
        for name, tooltip, slot in actions or []:
            button = IconButton(name, tooltip, box=28, size=15)
            button.clicked.connect(slot)
            layout.addWidget(button)
            self._buttons.append(button)

        self._value = value

    def set_value(self, value: str) -> None:
        """更新显示值。"""
        self._value = value
        self.value_label.setText(value or "—")

    def refresh_theme(self) -> None:
        for button in self._buttons:
            button.refresh_theme()
