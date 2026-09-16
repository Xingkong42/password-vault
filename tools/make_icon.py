"""生成应用图标 assets/app.ico。

图形与界面里的标志一致（盾牌 + 钥匙孔），为了在小尺寸下依然清晰，
额外加了一层圆角蓝色底：桌面/任务栏图标需要实心底才看得清轮廓。

用法：python tools/make_icon.py
"""

from __future__ import annotations

import os
import struct
import sys
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from PySide6.QtCore import QBuffer, QByteArray, QIODevice, QRectF, Qt  # noqa: E402
from PySide6.QtGui import (  # noqa: E402
    QColor,
    QGuiApplication,
    QImage,
    QLinearGradient,
    QPainter,
    QPainterPath,
)
from PySide6.QtSvg import QSvgRenderer  # noqa: E402

SIZES = (16, 24, 32, 48, 64, 128, 256)
SUPERSAMPLE = 4                  # 超采样倍数，保证边缘平滑
ASSETS = ROOT / "assets"

# 与 psvault/ui/icons.py 中的 LOGO_BODY 保持一致
SHIELD = ('<path d="M12 2.6 20 5.9v6.3c0 4.9-3.3 8.7-8 9.9-4.7-1.2-8-5-8-9.9V5.9Z"/>'
          '<circle cx="12" cy="10.4" r="2.2"/><path d="M12 12.6v3.6"/>')

BACKGROUND_TOP = "#4E86FF"
BACKGROUND_BOTTOM = "#2455D6"


def stroke_width(size: int) -> float:
    """小尺寸下加粗描边，避免缩放后线条糊成一团。"""
    if size <= 24:
        return 2.7
    if size <= 48:
        return 2.2
    return 1.75


def render(size: int) -> QImage:
    """渲染单个尺寸的图标。"""
    canvas = size * SUPERSAMPLE
    image = QImage(canvas, canvas, QImage.Format_ARGB32_Premultiplied)
    image.fill(Qt.transparent)

    painter = QPainter(image)
    painter.setRenderHint(QPainter.Antialiasing, True)

    # 圆角方形底 + 斜向渐变
    radius = canvas * 0.225
    background = QPainterPath()
    background.addRoundedRect(QRectF(0, 0, canvas, canvas), radius, radius)
    gradient = QLinearGradient(0, 0, canvas, canvas)
    gradient.setColorAt(0.0, QColor(BACKGROUND_TOP))
    gradient.setColorAt(1.0, QColor(BACKGROUND_BOTTOM))
    painter.fillPath(background, gradient)

    # 白色盾牌钥匙孔
    body = (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" '
            f'stroke="#FFFFFF" stroke-width="{stroke_width(size)}" '
            f'stroke-linecap="round" stroke-linejoin="round">{SHIELD}</svg>')
    renderer = QSvgRenderer(QByteArray(body.encode("utf-8")))
    side = canvas * 0.78
    offset = (canvas - side) / 2
    renderer.render(painter, QRectF(offset, offset, side, side))
    painter.end()

    return image.scaled(size, size, Qt.KeepAspectRatio, Qt.SmoothTransformation)


def png_bytes(image: QImage) -> bytes:
    """把 QImage 编码成 PNG 字节。"""
    buffer = QBuffer()
    buffer.open(QIODevice.WriteOnly)
    image.save(buffer, "PNG")
    return bytes(buffer.data())


def write_ico(target: Path, items: list[tuple[int, bytes]]) -> None:
    """按 ICO 容器格式写出多尺寸图标（内嵌 PNG，Vista 及以上均支持）。"""
    header = struct.pack("<HHH", 0, 1, len(items))
    offset = 6 + 16 * len(items)
    entries = b""
    payload = b""
    for size, data in items:
        dimension = 0 if size >= 256 else size      # 0 表示 256
        entries += struct.pack("<BBBBHHII", dimension, dimension, 0, 0, 1, 32,
                               len(data), offset)
        offset += len(data)
        payload += data
    target.write_bytes(header + entries + payload)


def main() -> int:
    app = QGuiApplication(sys.argv)          # noqa: F841 - 供 QPainter 使用
    ASSETS.mkdir(parents=True, exist_ok=True)

    items: list[tuple[int, bytes]] = []
    preview: QImage | None = None
    for size in SIZES:
        image = render(size)
        items.append((size, png_bytes(image)))
        if size == 256:
            preview = image

    ico_path = ASSETS / "app.ico"
    write_ico(ico_path, items)
    print(f"✓ 已生成 {ico_path.relative_to(ROOT)}（{len(items)} 个尺寸，"
          f"{ico_path.stat().st_size / 1024:.1f} KB）")

    if preview is not None:
        preview_path = ASSETS / "app-256.png"
        preview.save(str(preview_path), "PNG")
        print(f"✓ 已生成 {preview_path.relative_to(ROOT)}（预览用）")

    if "--preview" in sys.argv:
        write_preview(ASSETS / "app-sizes.png")
    return 0


def write_preview(target: Path, scales: tuple[int, ...] = (16, 24, 32, 48, 64)) -> None:
    """把各尺寸按 4 倍放大并排输出，用于检查小尺寸下的可读性。"""
    zoom = 4
    gap = 18
    width = sum(size * zoom + gap for size in scales) + gap
    height = max(scales) * zoom + gap * 2
    canvas = QImage(width, height, QImage.Format_ARGB32_Premultiplied)
    canvas.fill(QColor("#F0F2F5"))

    painter = QPainter(canvas)
    painter.setRenderHint(QPainter.SmoothPixmapTransform, True)
    x = gap
    for size in scales:
        icon = render(size)
        scaled = icon.scaled(size * zoom, size * zoom, Qt.KeepAspectRatio,
                             Qt.FastTransformation)     # 放大时不插值，看得清真实像素
        painter.drawImage(x, gap, scaled)
        x += size * zoom + gap
    painter.end()

    canvas.save(str(target), "PNG")
    print(f"✓ 已生成 {target.relative_to(ROOT)}（各尺寸放大对照）")


if __name__ == "__main__":
    sys.exit(main())
