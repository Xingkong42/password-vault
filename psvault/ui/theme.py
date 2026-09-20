"""主题系统：一套颜色令牌 + 一份生成式 QSS。

风格取向是极简扁平：大量留白、1px 浅描边代替阴影、只在关键处使用强调色。
浅色为默认主题，深色提供同等完整度的一套配色。
"""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from string import Template

from PySide6.QtCore import QObject, Signal
from PySide6.QtGui import QColor

# 界面统一字体族（中文优先，逐级回退保证在各类环境下都有可用的中文字形）
FONT_FAMILY = ('"Microsoft YaHei UI", "Microsoft YaHei", "PingFang SC", "Segoe UI", '
               '"Source Han Sans SC", "SimHei", "SimSun", sans-serif')
MONO_FAMILY = ('"Cascadia Mono", "JetBrains Mono", "Consolas", "DejaVu Sans Mono", '
               '"Courier New", monospace')


@dataclass(frozen=True)
class Palette:
    """一套配色令牌。"""

    name: str
    canvas: str          # 窗口底
    surface: str         # 卡片/面板
    surface_alt: str     # 次级面板（列表栏）
    border: str          # 常规描边
    border_strong: str   # 强调描边
    text: str            # 主文字
    text_muted: str      # 次要文字
    text_faint: str      # 更弱的提示文字
    accent: str          # 强调色
    accent_hover: str
    accent_soft: str     # 强调色的浅底（选中态背景）
    accent_line: str     # 强调色的柔和描边（选中框）
    accent_text: str     # 强调色上的文字
    danger: str
    danger_soft: str
    success: str
    success_soft: str
    warning: str
    warning_soft: str
    hover: str           # 通用悬停底色
    selected: str        # 选中底色
    shadow: str          # 阴影颜色（rgba 字符串）


LIGHT = Palette(
    name="light",
    canvas="#F4F5F7",
    surface="#FFFFFF",
    surface_alt="#FAFBFC",
    border="#E7E9EE",
    border_strong="#D5D9E0",
    text="#1B1F26",
    text_muted="#5F6875",
    text_faint="#98A1B0",
    accent="#2F6BEE",
    accent_hover="#2559D6",
    accent_soft="#EAF0FE",
    accent_line="#BFD3FC",
    accent_text="#FFFFFF",
    danger="#DE3B41",
    danger_soft="#FCEDED",
    success="#0E9F6E",
    success_soft="#E7F6F0",
    warning="#D98207",
    warning_soft="#FDF3E2",
    hover="#F1F3F7",
    selected="#EAF0FE",
    shadow="rgba(15, 23, 42, 0.06)",
)

DARK = Palette(
    name="dark",
    canvas="#15171C",
    surface="#1C1F26",
    surface_alt="#191C22",
    border="#2A2F38",
    border_strong="#3A404A",
    text="#E6E9EE",
    text_muted="#98A1B0",
    text_faint="#6C7480",
    accent="#5B8CFF",
    accent_hover="#7AA2FF",
    accent_soft="#212C44",
    accent_line="#39497A",
    accent_text="#0E1116",
    danger="#F2555A",
    danger_soft="#38222A",
    success="#35C08A",
    success_soft="#16302A",
    warning="#E0A340",
    warning_soft="#3A3020",
    hover="#23272F",
    selected="#212C44",
    shadow="rgba(0, 0, 0, 0.35)",
)

PALETTES = {"light": LIGHT, "dark": DARK}


_QSS = Template("""
* { outline: none; }

QWidget {
    font-family: $font;
    font-size: 13px;
    color: $text;
}

QMainWindow, QDialog, #RootSurface {
    background: $canvas;
}

QToolTip {
    background: $surface;
    color: $text;
    border: 1px solid $border;
    border-radius: 6px;
    padding: 5px 9px;
}

/* ---------------------------------------------------------- 通用容器 */
#Card, #Panel, #Surface {
    background: $surface;
    border: 1px solid $border;
    border-radius: 12px;
}

#Sidebar {
    background: $surface_alt;
    border-right: 1px solid $border;
}

#ListPane {
    background: $surface;
    border-right: 1px solid $border;
}

#DetailPane {
    background: $canvas;
}

#Divider { background: $border; }

/* ---------------------------------------------------------- 文字层级
   注意：带 objectName 的控件必须显式声明 color，否则在深色主题下会沿用
   系统默认的深色文字，导致几乎看不见。 */
#AppTitle { font-size: 16px; font-weight: 600; color: $text; letter-spacing: 0.5px; }
#PageTitle { font-size: 19px; font-weight: 600; color: $text; }
#SectionTitle { font-size: 12px; font-weight: 600; color: $text_faint; letter-spacing: 1px; }
#EntryTitle { font-size: 14px; font-weight: 600; color: $text; }
#Hint { color: $text_muted; font-size: 12px; }
#Faint { color: $text_faint; font-size: 12px; }
#Mono { font-family: $mono; color: $text; }
#Danger { color: $danger; }
#Success { color: $success; }
#Warning { color: $warning; }

/* ---------------------------------------------------------- 风险提示
   详情页顶部的风险横幅、审计视图列表里的风险标签都走这套样式 */
#RiskBanner {
    background: $warning_soft;
    border: 1px solid $border;
    border-radius: 10px;
}
#RiskBanner[level="high"] { background: $danger_soft; }

#RiskTitle { font-size: 14px; font-weight: 600; color: $warning; }
#RiskTitle[level="high"] { color: $danger; }

#RiskText { font-size: 13px; color: $text; }

#RiskDot { font-size: 9px; color: $warning; }
#RiskDot[level="high"] { color: $danger; }
#RiskDot[level="info"] { color: $text_faint; }

#RiskTag { font-size: 12px; font-weight: 600; color: $warning; }
#RiskTag[level="high"] { color: $danger; }
#RiskTag[level="info"] { color: $text_faint; }
#FieldLabel { color: $text_faint; font-size: 12px; }
#FieldValue { font-size: 14px; color: $text; }
#EmptyTitle { font-size: 15px; font-weight: 600; color: $text_muted; }

/* ---------------------------------------------------------- 按钮 */
QPushButton {
    background: $surface;
    color: $text;
    border: 1px solid $border_strong;
    border-radius: 8px;
    padding: 7px 14px;
    min-height: 20px;
}
QPushButton:hover { background: $hover; }
QPushButton:pressed { background: $selected; }
QPushButton:disabled { color: $text_faint; border-color: $border; background: $surface; }

QPushButton#Primary {
    background: $accent;
    color: $accent_text;
    border: 1px solid $accent;
    font-weight: 600;
}
QPushButton#Primary:hover { background: $accent_hover; border-color: $accent_hover; }
QPushButton#Primary:pressed { background: $accent; }
QPushButton#Primary:disabled { background: $border_strong; border-color: $border_strong; color: $surface; }

QPushButton#Danger {
    color: $danger;
    border: 1px solid $border_strong;
}
QPushButton#Danger:hover { background: $danger_soft; border-color: $danger; }

QPushButton#Ghost {
    background: transparent;
    border: 1px solid transparent;
    color: $text_muted;
    padding: 6px 10px;
}
QPushButton#Ghost:hover { background: $hover; color: $text; }

QPushButton#Link {
    background: transparent;
    border: none;
    color: $accent;
    padding: 2px 0;
    text-align: left;
}
QPushButton#Link:hover { color: $accent_hover; text-decoration: underline; }

/* 图标按钮：正方形、无边框 */
QToolButton {
    background: transparent;
    border: 1px solid transparent;
    border-radius: 7px;
    padding: 5px;
}
QToolButton:hover { background: $hover; border-color: $border; }
QToolButton:pressed { background: $selected; }
QToolButton:checked { background: $accent_soft; border-color: $accent_soft; }
QToolButton::menu-indicator { image: none; width: 0; }

/* ---------------------------------------------------------- 输入控件 */
QLineEdit, QTextEdit, QPlainTextEdit, QSpinBox, QComboBox {
    background: $surface;
    border: 1px solid $border_strong;
    border-radius: 8px;
    padding: 6px 10px;
    selection-background-color: $accent;
    selection-color: $accent_text;
}
QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus, QSpinBox:focus, QComboBox:focus {
    border: 1px solid $accent;
}
QLineEdit:disabled, QTextEdit:disabled, QSpinBox:disabled, QComboBox:disabled {
    background: $hover; color: $text_faint;
}
QLineEdit#Search {
    background: $surface;
    border: 1px solid $border;
    border-radius: 9px;
    padding: 7px 12px;
}
QLineEdit#Search:focus { border-color: $accent; }

QTextEdit, QPlainTextEdit { padding: 8px 10px; }

QSpinBox::up-button, QSpinBox::down-button {
    width: 20px;
    border: none;
    background: transparent;
}
QSpinBox::up-button:hover, QSpinBox::down-button:hover { background: $hover; }
QSpinBox::up-arrow { image: url($arrow_up); width: 9px; height: 5px; }
QSpinBox::down-arrow { image: url($arrow_down); width: 9px; height: 5px; }
QSpinBox::up-arrow:disabled, QSpinBox::down-arrow:disabled { opacity: 0.4; }

QComboBox::drop-down { border: none; width: 22px; }
QComboBox::down-arrow {
    image: url($arrow_down);
    width: 10px;
    height: 6px;
    margin-right: 8px;
}
QComboBox QAbstractItemView {
    background: $surface;
    border: 1px solid $border;
    border-radius: 8px;
    padding: 4px;
    selection-background-color: $accent_soft;
    selection-color: $text;
    outline: none;
}

/* ---------------------------------------------------------- 列表 */
QListWidget, QListView, QTreeWidget, QTreeView {
    background: transparent;
    border: none;
    outline: none;
}
QListWidget::item {
    border-radius: 8px;
    padding: 6px 9px;
    color: $text_muted;
}
QListWidget::item:hover { background: $hover; color: $text; }
QListWidget::item:selected { background: $accent_soft; color: $accent; }

/* ---------------------------------------------------------- 分段控件 */
#SegmentBar {
    background: $hover;
    border: 1px solid $border;
    border-radius: 10px;
}
#Segment {
    background: transparent;
    border: none;
    border-radius: 8px;
    padding: 7px 18px;
    color: $text_muted;
    font-weight: 500;
}
#Segment:hover { color: $text; }
#Segment:checked {
    background: $surface;
    color: $text;
    font-weight: 600;
}

/* ---------------------------------------------------------- 滚动条 */
QScrollArea { background: transparent; border: none; }
QScrollBar:vertical {
    background: transparent;
    width: 10px;
    margin: 2px 2px 2px 0;
}
QScrollBar::handle:vertical {
    background: $border_strong;
    border-radius: 4px;
    min-height: 32px;
}
QScrollBar::handle:vertical:hover { background: $text_faint; }
QScrollBar:horizontal {
    background: transparent;
    height: 10px;
    margin: 0 2px 2px 2px;
}
QScrollBar::handle:horizontal {
    background: $border_strong;
    border-radius: 4px;
    min-width: 32px;
}
QScrollBar::add-line, QScrollBar::sub-line { height: 0; width: 0; }
QScrollBar::add-page, QScrollBar::sub-page { background: transparent; }

/* ---------------------------------------------------------- 勾选 */
QCheckBox, QRadioButton { spacing: 8px; color: $text; }
QCheckBox::indicator, QRadioButton::indicator {
    width: 16px; height: 16px;
    border: 1px solid $border_strong;
    background: $surface;
}
QCheckBox::indicator { border-radius: 5px; }
QRadioButton::indicator { border-radius: 9px; }
QCheckBox::indicator:hover, QRadioButton::indicator:hover { border-color: $accent; }
QCheckBox::indicator:checked {
    background: $accent;
    border-color: $accent;
    image: url($check_icon);
}
QCheckBox::indicator:disabled { background: $hover; }
QRadioButton::indicator:checked {
    background: $accent;
    border: 5px solid $accent_soft;
}

/* ---------------------------------------------------------- 菜单 */
QMenu {
    background: $surface;
    border: 1px solid $border;
    border-radius: 10px;
    padding: 6px;
}
QMenu::item {
    padding: 7px 26px 7px 12px;
    border-radius: 6px;
    color: $text;
}
QMenu::item:selected { background: $accent_soft; color: $text; }
QMenu::item:disabled { color: $text_faint; }
QMenu::separator { height: 1px; background: $border; margin: 5px 8px; }

/* ---------------------------------------------------------- 进度与滑块 */
QProgressBar {
    background: $hover;
    border: none;
    border-radius: 4px;
    height: 8px;
    text-align: center;
}
QProgressBar::chunk { background: $accent; border-radius: 4px; }

QSlider::groove:horizontal {
    height: 4px;
    background: $hover;
    border-radius: 2px;
}
QSlider::sub-page:horizontal { background: $accent; border-radius: 2px; }
QSlider::handle:horizontal {
    background: $surface;
    border: 2px solid $accent;
    width: 12px; height: 12px;
    margin: -6px 0;
    border-radius: 8px;
}

/* ---------------------------------------------------------- 分组框/选项卡 */
QGroupBox {
    border: 1px solid $border;
    border-radius: 10px;
    margin-top: 14px;
    padding: 14px 12px 12px 12px;
    font-weight: 600;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 12px;
    padding: 0 5px;
    color: $text_muted;
}
QTabWidget::pane { border: none; background: transparent; }
QTabBar::tab {
    background: transparent;
    color: $text_muted;
    padding: 7px 14px;
    border-radius: 8px;
    margin-right: 4px;
}
QTabBar::tab:selected { background: $accent_soft; color: $accent; font-weight: 600; }
QTabBar::tab:hover:!selected { background: $hover; color: $text; }

/* ---------------------------------------------------------- 自定义控件 */
#NavItem {
    background: transparent;
    border: none;
    border-radius: 8px;
    padding: 7px 10px;
    color: $text_muted;
    text-align: left;
}
#NavItem:hover { background: $hover; color: $text; }
#NavItem:checked { background: $accent_soft; color: $accent; font-weight: 600; }

#EntryCard {
    background: transparent;
    border: 1px solid transparent;
    border-radius: 10px;
}
#EntryCard:hover { background: $hover; }
#EntryCard[selected="true"] {
    background: $accent_soft;
    border: 1px solid $accent_line;
}
/* 键盘焦点：比选中态更醒目一点，便于纯键盘操作时定位 */
#EntryCard:focus { border: 1px solid $accent; }

#TagChip {
    background: $hover;
    border: 1px solid $border;
    border-radius: 9px;
    padding: 2px 9px;
    color: $text_muted;
    font-size: 11px;
}
#TagChip[active="true"] {
    background: $accent_soft;
    border-color: $accent;
    color: $accent;
}

#Badge {
    background: $hover;
    border-radius: 8px;
    padding: 1px 8px;
    color: $text_muted;
    font-size: 11px;
}
#BadgeAccent { background: $accent_soft; color: $accent; border-radius: 8px; padding: 1px 8px; font-size: 11px; }
#BadgeDanger { background: $danger_soft; color: $danger; border-radius: 8px; padding: 1px 8px; font-size: 11px; }
#BadgeWarning { background: $warning_soft; color: $warning; border-radius: 8px; padding: 1px 8px; font-size: 11px; }
#BadgeSuccess { background: $success_soft; color: $success; border-radius: 8px; padding: 1px 8px; font-size: 11px; }

#FieldRow {
    background: $surface;
    border: 1px solid $border;
    border-radius: 9px;
}
#FieldRow:hover { border-color: $border_strong; }

#Toast {
    background: $text;
    color: $surface;
    border-radius: 10px;
    padding: 9px 16px;
    font-size: 12px;
}
#Toast[danger="true"] { background: $danger; color: #FFFFFF; }

#Hero {
    background: $surface;
    border: 1px solid $border;
    border-radius: 14px;
}
#StrengthBar { background: $hover; border-radius: 3px; }
""")


_ASSET_CACHE: dict[str, str] = {}


def _asset_path(kind: str, palette: Palette) -> str:
    """生成 QSS 需要的小图片（对勾、上下三角箭头），返回可用的 url 路径。

    Qt 的样式表画不出对勾和三角形，只能用图片；这里在运行时画出来写到
    临时目录，因此不需要随程序附带任何资源文件。

    两个细节：
    * 文件名带随机后缀——多个实例用同一主题时不会互相覆盖；
    * 复用缓存前先确认文件还在——临时目录被系统清理后能重新生成，
      否则样式表会指向一个不存在的图标。
    """
    key = f"{kind}-{palette.name}"
    cached = _ASSET_CACHE.get(key)
    if cached is not None and Path(cached).exists():
        return cached

    from PySide6.QtCore import QPointF, Qt
    from PySide6.QtGui import QColor, QPainter, QPainterPath, QPen, QPixmap

    handle, name = tempfile.mkstemp(prefix=f"psvault-{key}-", suffix=".png")
    os.close(handle)
    target = Path(name)

    if kind == "check":
        pixmap = QPixmap(32, 32)
        pixmap.fill(Qt.transparent)
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.Antialiasing, True)
        pen = QPen(QColor(palette.accent_text))
        pen.setWidthF(3.4)
        pen.setCapStyle(Qt.RoundCap)
        pen.setJoinStyle(Qt.RoundJoin)
        painter.setPen(pen)
        painter.drawPolyline([QPointF(8.5, 16.5), QPointF(13.8, 22), QPointF(23.5, 10.5)])
        painter.end()
    else:
        upward = kind == "arrow-up"
        pixmap = QPixmap(22, 12)
        pixmap.fill(Qt.transparent)
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.Antialiasing, True)
        painter.setPen(Qt.NoPen)
        painter.setBrush(QColor(palette.text_muted))
        path = QPainterPath()
        if upward:
            path.moveTo(11, 1.5)
            path.lineTo(20, 10)
            path.lineTo(2, 10)
        else:
            path.moveTo(2, 2)
            path.lineTo(20, 2)
            path.lineTo(11, 10.5)
        path.closeSubpath()
        painter.drawPath(path)
        painter.end()

    pixmap.save(str(target), "PNG")
    _ASSET_CACHE[key] = target.as_posix()
    return _ASSET_CACHE[key]


def build_qss(palette: Palette) -> str:
    """把配色令牌注入样式模板。"""
    return _QSS.substitute(
        font=FONT_FAMILY,
        mono=MONO_FAMILY,
        check_icon=_asset_path("check", palette),
        arrow_up=_asset_path("arrow-up", palette),
        arrow_down=_asset_path("arrow-down", palette),
        **{k: v for k, v in palette.__dict__.items() if not k.startswith("_")},
    )


class Theme(QObject):
    """全局主题管理器（单例）。"""

    changed = Signal(str)

    _instance: Theme | None = None

    def __init__(self) -> None:
        super().__init__()
        self._palette = LIGHT

    @classmethod
    def instance(cls) -> Theme:
        if cls._instance is None:
            cls._instance = Theme()
        return cls._instance

    @property
    def palette(self) -> Palette:
        return self._palette

    @property
    def is_dark(self) -> bool:
        return self._palette.name == "dark"

    def color(self, token: str) -> QColor:
        """按令牌名取 QColor。"""
        return QColor(getattr(self._palette, token))

    def hex(self, token: str) -> str:
        """按令牌名取十六进制颜色串。"""
        return getattr(self._palette, token)

    def set_theme(self, name: str) -> None:
        """切换主题并广播变化。"""
        palette = PALETTES.get(name, LIGHT)
        if palette.name == self._palette.name:
            return
        self._palette = palette
        self.changed.emit(palette.name)

    def apply(self, app) -> None:
        """把当前主题应用到 QApplication。"""
        app.setStyleSheet(build_qss(self._palette))
