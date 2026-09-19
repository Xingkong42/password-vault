"""剪贴板写入封装。

为什么要单独做一层
------------------
Windows 10/11 自带剪贴板历史（Win+V）与跨设备云剪贴板同步。程序虽然会在
若干秒后清空剪贴板，但那只是清掉"当前内容"——如果系统已经把密码记进历史，
它依然躺在那里，甚至可能已经同步到了微软账号。

系统为此留了两个约定格式，应用可以主动声明"这条内容不要记录"：

* ``CanIncludeInClipboardHistory`` = 0    不写进 Win+V 历史
* ``CanUploadToCloudClipboard``    = 0    不上传跨设备云剪贴板

普通文字照常复制；只有密码、动态口令这类敏感内容才附加这两个声明。
"""

from __future__ import annotations

import struct

from PySide6.QtCore import QByteArray, QMimeData
from PySide6.QtWidgets import QApplication

# 这两个格式名由 Windows 定义，值为 DWORD 0 时表示"排除"
EXCLUDE_FORMATS = ("CanIncludeInClipboardHistory", "CanUploadToCloudClipboard")


def put_text(text: str, *, sensitive: bool = False) -> None:
    """把文本写入系统剪贴板。

    sensitive=True 时会额外声明"不记录到剪贴板历史、不同步到云"。
    """
    clipboard = QApplication.clipboard()
    if not sensitive:
        clipboard.setText(text)
        return

    mime = QMimeData()
    mime.setText(text)
    zero = QByteArray(struct.pack("<I", 0))
    for name in EXCLUDE_FORMATS:
        mime.setData(name, zero)
    clipboard.setMimeData(mime)


def clipboard_text() -> str:
    """读取当前剪贴板文本（用于判断是否还需要清空）。"""
    return QApplication.clipboard().text()


def clear_if_unchanged(expected: str) -> bool:
    """剪贴板内容仍是 expected 时清空它，返回是否执行了清空。

    用户如果已经复制了别的东西，就不该再动剪贴板。
    """
    clipboard = QApplication.clipboard()
    if clipboard.text() != expected:
        return False
    clipboard.clear()
    return True
