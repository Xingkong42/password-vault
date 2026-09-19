"""临时探针：在真实平台上复制一段文本，供外部程序检查剪贴板格式。

用法：
    python tools/clipboard_probe.py           复制"敏感"内容（带排除声明）
    python tools/clipboard_probe.py --plain   复制普通内容（作对照）

配合 tools/read_clipboard.ps1 使用，确认 CanIncludeInClipboardHistory /
CanUploadToCloudClipboard 是否真的写进了系统剪贴板。
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from PySide6.QtCore import QTimer  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from psvault.ui import clipboard as cb  # noqa: E402

plain = "--plain" in sys.argv
app = QApplication(sys.argv)
cb.put_text("PV-CLIPBOARD-PROBE", sensitive=not plain)
print("copied", "plain" if plain else "sensitive", flush=True)

# 必须跑事件循环：Qt 对剪贴板是"延迟渲染"，别的程序来取数据时
# 需要本进程响应请求，光 sleep 是取不到的。
QTimer.singleShot(8000, app.quit)
app.exec()
_ = time
