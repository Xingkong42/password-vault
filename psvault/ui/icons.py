"""矢量图标库：内嵌 SVG 路径，按需着色渲染，全程序不依赖任何图片资源。

图标统一采用 24×24 视窗、线性描边风格（stroke-width 1.7、圆角端点），
与整体极简扁平的视觉语言保持一致。需要自绘或替换图标时，只需修改
`ICONS` 中的路径数据即可。
"""

from __future__ import annotations

from functools import lru_cache

from PySide6.QtCore import QByteArray, QSize, Qt
from PySide6.QtGui import QColor, QIcon, QPainter, QPixmap
from PySide6.QtSvg import QSvgRenderer

from .theme import Theme

# 图标名 -> (路径片段, 是否为实心填充)
ICONS: dict[str, tuple[str, bool]] = {
    # 导航
    "grid": ('<rect x="4" y="4" width="7" height="7" rx="1.8"/>'
             '<rect x="13" y="4" width="7" height="7" rx="1.8"/>'
             '<rect x="4" y="13" width="7" height="7" rx="1.8"/>'
             '<rect x="13" y="13" width="7" height="7" rx="1.8"/>', False),
    "star": ('<path d="m12 3.6 2.6 5.3 5.9.85-4.25 4.15 1 5.9-5.25-2.8-5.25 2.8 '
             '1-5.9L3.5 9.75l5.9-.85Z"/>', False),
    "star-filled": ('<path d="m12 3.6 2.6 5.3 5.9.85-4.25 4.15 1 5.9-5.25-2.8-5.25 2.8 '
                    '1-5.9L3.5 9.75l5.9-.85Z"/>', True),
    "shield": ('<path d="M12 3l7.5 3v6c0 4.5-3.1 7.9-7.5 9-4.4-1.1-7.5-4.5-7.5-9V6Z"/>', False),
    "shield-check": ('<path d="M12 3l7.5 3v6c0 4.5-3.1 7.9-7.5 9-4.4-1.1-7.5-4.5-7.5-9V6Z"/>'
                     '<path d="m9 12.2 2.1 2.1L15.4 10"/>', False),
    "folder": ('<path d="M3 7.5A2.5 2.5 0 0 1 5.5 5h3.2l2 2.5h7.8A2.5 2.5 0 0 1 21 10v7.5'
               'A2.5 2.5 0 0 1 18.5 20h-13A2.5 2.5 0 0 1 3 17.5Z"/>', False),
    "tag": ('<path d="M20.6 13.4 12 22l-9-9V3h10l7.6 7.6a2 2 0 0 1 0 2.8Z"/>'
            '<circle cx="7.5" cy="7.5" r="1.4"/>', False),
    "clock": ('<circle cx="12" cy="12" r="9"/><path d="M12 7.4V12l3.1 2"/>', False),
    "trash": ('<path d="M3.5 6.5h17"/><path d="M9 6.5V4.6A1.6 1.6 0 0 1 10.6 3h2.8A1.6 1.6 0 0 1 15 4.6'
              'v1.9"/><path d="M18.5 6.5 17.6 20a1.6 1.6 0 0 1-1.6 1.5H8a1.6 1.6 0 0 1-1.6-1.5'
              'L5.5 6.5"/><path d="M10.2 11v6M13.8 11v6"/>', False),
    "alert": ('<path d="M10.3 4.3 2.6 17.5A1.8 1.8 0 0 0 4.2 20.3h15.6a1.8 1.8 0 0 0 1.6-2.8'
              'L13.7 4.3a1.9 1.9 0 0 0-3.4 0Z"/><path d="M12 9.5v4.2"/>'
              '<circle cx="12" cy="17" r=".9" fill="{color}" stroke="none"/>', False),
    # 操作
    "plus": ('<path d="M12 5v14M5 12h14"/>', False),
    "pencil": ('<path d="M12.5 20H21"/><path d="M16.4 3.6a2.1 2.1 0 0 1 3 3L7.6 18.4 3.5 20l1.6-4.1Z"/>', False),
    "copy": ('<rect x="9" y="9" width="11.5" height="11.5" rx="2.4"/>'
             '<path d="M5.5 15.2A2 2 0 0 1 4 13.3V5.5A1.5 1.5 0 0 1 5.5 4h7.8a2 2 0 0 1 1.9 1.5"/>', False),
    "check": ('<path d="m20 6.5-11 11-5-5"/>', False),
    "close": ('<path d="M18 6 6 18M6 6l12 12"/>', False),
    "eye": ('<path d="M2.2 12S5.8 5.5 12 5.5 21.8 12 21.8 12 18.2 18.5 12 18.5 2.2 12 2.2 12Z"/>'
            '<circle cx="12" cy="12" r="2.9"/>', False),
    "eye-off": ('<path d="M10.7 5.7A9.6 9.6 0 0 1 12 5.6c6.2 0 9.8 6.4 9.8 6.4a17.6 17.6 0 0 1-3.2 4.1'
                'M6.4 6.6A17.4 17.4 0 0 0 2.2 12s3.6 6.4 9.8 6.4a9.6 9.6 0 0 0 3.9-.8"/>'
                '<path d="M3 3l18 18"/><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2"/>', False),
    "refresh": ('<path d="M20.4 12a8.4 8.4 0 1 1-2.5-6"/><path d="M20.4 4.6V10h-5.4"/>', False),
    "sparkles": ('<path d="M11.5 3.2 13 7.4l4.2 1.5L13 10.4l-1.5 4.2-1.5-4.2L5.8 8.9 10 7.4Z"/>'
                 '<path d="M17.8 14.6l.8 2.2 2.2.8-2.2.8-.8 2.2-.8-2.2-2.2-.8 2.2-.8Z"/>', False),
    "settings": ('<path d="M4 7h7M15.2 7h4.8"/><circle cx="13.1" cy="7" r="2.1"/>'
                 '<path d="M4 17h2.8M10.8 17h9.2"/><circle cx="8.8" cy="17" r="2.1"/>', False),
    "search": ('<circle cx="11" cy="11" r="7"/><path d="m20 20-3.4-3.4"/>', False),
    "lock": ('<rect x="4.2" y="10.2" width="15.6" height="10.6" rx="2.6"/>'
             '<path d="M8 10.2V7.4a4 4 0 0 1 8 0v2.8"/><circle cx="12" cy="15.4" r="1.3" fill="currentColor" stroke="none"/>', False),
    "unlock": ('<rect x="4.2" y="10.2" width="15.6" height="10.6" rx="2.6"/>'
               '<path d="M8 10.2V7.4a4 4 0 0 1 7.6-1.9"/><circle cx="12" cy="15.4" r="1.3" fill="currentColor" stroke="none"/>', False),
    "key": ('<circle cx="7.8" cy="15.8" r="4.8"/><path d="m20.5 3.5-8.7 8.7"/>'
            '<path d="m15.2 5.6 3.2 3.2 2.1-2.1-3.2-3.2Z"/>', False),
    "user": ('<path d="M20 20.5v-1.8a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v1.8"/>'
             '<circle cx="12" cy="7.5" r="3.8"/>', False),
    "globe": ('<circle cx="12" cy="12" r="8.8"/><path d="M3.4 12h17.2"/>'
              '<path d="M12 3.2c2.4 2.4 3.6 5.4 3.6 8.8S14.4 18.4 12 20.8c-2.4-2.4-3.6-5.4-3.6-8.8'
              'S9.6 5.6 12 3.2Z"/>', False),
    "note": ('<path d="M14 3.2H7.4A2.2 2.2 0 0 0 5.2 5.4v13.2a2.2 2.2 0 0 0 2.2 2.2h9.2a2.2 2.2 0 0 0 2.2-2.2V8Z"/>'
             '<path d="M14 3.2V8h4.8"/><path d="M9 13h6M9 16.4h4"/>', False),
    "download": ('<path d="M12 3.5v11.4"/><path d="m7.6 10.6 4.4 4.4 4.4-4.4"/><path d="M4 20.4h16"/>', False),
    "upload": ('<path d="M12 20.5V9.1"/><path d="m7.6 13.4 4.4-4.4 4.4 4.4"/><path d="M4 3.6h16"/>', False),
    "history": ('<path d="M3.6 12a8.4 8.4 0 1 0 2.5-6"/><path d="M3.6 4.6V10H9"/><path d="M12 7.8V12l3 1.9"/>', False),
    "chevron-down": ('<path d="m6 9.5 6 6 6-6"/>', False),
    "chevron-right": ('<path d="m9.5 6 6 6-6 6"/>', False),
    "more": ('<circle cx="5.2" cy="12" r="1.5"/><circle cx="12" cy="12" r="1.5"/><circle cx="18.8" cy="12" r="1.5"/>', True),
    "info": ('<circle cx="12" cy="12" r="8.8"/><path d="M12 11.2v5"/>'
             '<circle cx="12" cy="8" r=".95" fill="{color}" stroke="none"/>', False),
    "copy-all": ('<rect x="3.5" y="3.5" width="12" height="12" rx="2.4"/>'
                 '<path d="M8.5 20.5h9A2.5 2.5 0 0 0 20 18V9"/>', False),
    "link": ('<path d="M10.5 13.5a4 4 0 0 0 5.7 0l2.6-2.6a4 4 0 1 0-5.7-5.7l-1 1"/>'
             '<path d="M13.5 10.5a4 4 0 0 0-5.7 0l-2.6 2.6a4 4 0 1 0 5.7 5.7l1-1"/>', False),
    "pin": ('<path d="M9 3.5h6l-.8 5.2 3.3 3.3H6.5l3.3-3.3Z"/><path d="M12 12v8.5"/>', False),
    "restore": ('<path d="M3.6 12a8.4 8.4 0 1 1 2.5 6"/><path d="M3.6 4.6V10H9"/>', False),
    "sun": ('<circle cx="12" cy="12" r="4"/><path d="M12 2.4v2.2M12 19.4v2.2M4.6 4.6l1.6 1.6'
            'M17.8 17.8l1.6 1.6M2.4 12h2.2M19.4 12h2.2M4.6 19.4l1.6-1.6M17.8 6.2l1.6-1.6"/>', False),
    "moon": ('<path d="M20.6 14.8A8.8 8.8 0 0 1 9.2 3.4a8.8 8.8 0 1 0 11.4 11.4Z"/>', False),
    "filter": ('<path d="M3.5 5.5h17l-6.6 7.7v5.6l-3.8 2.2v-7.8Z"/>', False),
    "clipboard": ('<rect x="5.5" y="4.5" width="13" height="16.5" rx="2.4"/>'
                  '<path d="M9.5 4.5V3.6h5v.9"/>', False),
}

# 应用标志：盾牌内嵌钥匙孔
LOGO_BODY = ('<path d="M12 2.6 20 5.9v6.3c0 4.9-3.3 8.7-8 9.9-4.7-1.2-8-5-8-9.9V5.9Z"/>'
             '<circle cx="12" cy="10.4" r="2.2"/><path d="M12 12.6v3.6"/>')


def _svg(name: str, color: str, width: float = 1.7) -> bytes:
    """拼出完整的 SVG 文档。"""
    body, filled = ICONS.get(name, ICONS["info"])
    body = body.replace("{color}", color)
    if filled:
        return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" '
                f'fill="{color}" stroke="none">{body}</svg>').encode("utf-8")
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" '
            f'stroke="{color}" stroke-width="{width}" stroke-linecap="round" '
            f'stroke-linejoin="round">{body}</svg>').encode("utf-8")


@lru_cache(maxsize=512)
def pixmap(name: str, color: str, size: int = 18, scale: int = 2) -> QPixmap:
    """渲染指定图标为位图（按 2 倍分辨率渲染，保证高分屏清晰）。"""
    renderer = QSvgRenderer(QByteArray(_svg(name, color)))
    canvas = QPixmap(size * scale, size * scale)
    canvas.fill(Qt.transparent)
    painter = QPainter(canvas)
    painter.setRenderHint(QPainter.Antialiasing, True)
    renderer.render(painter)
    painter.end()
    canvas.setDevicePixelRatio(float(scale))
    return canvas


def icon(name: str, token: str = "text_muted", size: int = 18) -> QIcon:
    """按主题颜色令牌获取图标（颜色随主题切换而变化）。"""
    color = Theme.instance().hex(token)
    return QIcon(pixmap(name, color, size))


def colored_pixmap(name: str, token: str = "text_muted", size: int = 18) -> QPixmap:
    """按主题颜色令牌获取位图。"""
    return pixmap(name, Theme.instance().hex(token), size)


def build_logo(color: str, size: int = 30, scale: int = 3) -> QPixmap:
    """绘制应用标志。"""
    body = (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" '
            f'stroke="{color}" stroke-width="1.6" stroke-linecap="round" '
            f'stroke-linejoin="round">{LOGO_BODY}</svg>')
    renderer = QSvgRenderer(QByteArray(body.encode("utf-8")))
    canvas = QPixmap(size * scale, size * scale)
    canvas.fill(Qt.transparent)
    painter = QPainter(canvas)
    painter.setRenderHint(QPainter.Antialiasing, True)
    renderer.render(painter)
    painter.end()
    canvas.setDevicePixelRatio(float(scale))
    return canvas


def app_icon() -> QIcon:
    """生成窗口/任务栏图标（多尺寸）。"""
    result = QIcon()
    accent = Theme.instance().hex("accent")
    for size in (16, 24, 32, 48, 64, 128):
        result.addPixmap(build_logo(accent, size=size, scale=1))
    return result


def tinted_dot(color: str, size: int = 10, scale: int = 3) -> QPixmap:
    """生成一个小圆点，用于状态指示。"""
    canvas = QPixmap(size * scale, size * scale)
    canvas.fill(Qt.transparent)
    painter = QPainter(canvas)
    painter.setRenderHint(QPainter.Antialiasing, True)
    painter.setPen(Qt.NoPen)
    painter.setBrush(QColor(color))
    painter.drawEllipse(1 * scale, 1 * scale, (size - 2) * scale, (size - 2) * scale)
    painter.end()
    canvas.setDevicePixelRatio(float(scale))
    return canvas


def icon_size(size: int) -> QSize:
    """便捷构造 QSize。"""
    return QSize(size, size)
