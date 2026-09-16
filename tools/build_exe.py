"""把程序打包成单目录（onedir）形式的 exe。

用法：
    python tools/build_exe.py            正常打包
    python tools/build_exe.py --no-clean 跳过清理，加快重复打包

产物：
    dist/密码保险箱/密码保险箱.exe       主程序
    dist/密码保险箱/_internal/…          运行库（必须与 exe 一起分发）
    dist/密码保险箱/data/                首次运行后生成，存放保险箱文件
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

APP_NAME = "密码保险箱"
ICON = ROOT / "assets" / "app.ico"
VERSION_FILE = ROOT / "tools" / "version_info.txt"
DIST = ROOT / "dist"
BUILD = ROOT / "build"

# 用不到的 Qt 模块，排除后能明显减小体积
EXCLUDES = [
    "PySide6.Qt3DAnimation", "PySide6.Qt3DCore", "PySide6.Qt3DExtras",
    "PySide6.Qt3DInput", "PySide6.Qt3DLogic", "PySide6.Qt3DRender",
    "PySide6.QtBluetooth", "PySide6.QtCharts", "PySide6.QtDataVisualization",
    "PySide6.QtDesigner", "PySide6.QtHelp", "PySide6.QtMultimedia",
    "PySide6.QtMultimediaWidgets", "PySide6.QtNetworkAuth", "PySide6.QtNfc",
    "PySide6.QtOpenGL", "PySide6.QtOpenGLWidgets", "PySide6.QtPdf",
    "PySide6.QtPdfWidgets", "PySide6.QtPositioning", "PySide6.QtQml",
    "PySide6.QtQuick", "PySide6.QtQuick3D", "PySide6.QtQuickControls2",
    "PySide6.QtQuickWidgets", "PySide6.QtRemoteObjects", "PySide6.QtSensors",
    "PySide6.QtSerialPort", "PySide6.QtSpatialAudio", "PySide6.QtSql",
    "PySide6.QtStateMachine", "PySide6.QtTest", "PySide6.QtTextToSpeech",
    "PySide6.QtWebChannel", "PySide6.QtWebEngineCore", "PySide6.QtWebEngineQuick",
    "PySide6.QtWebEngineWidgets", "PySide6.QtWebSockets", "PySide6.QtXml",
    "tkinter", "unittest", "pydoc", "doctest", "test",
]

README_TEXT = """密码保险箱 —— 本地加密的账号密码管理器

【怎么用】
  双击「密码保险箱.exe」启动。
  第一次运行会让你创建保险箱：先给保险箱起个名字，再设置主密码。
  主密码是解密数据的唯一钥匙，程序不保存任何副本，忘记无法找回。

【数据在哪】
  程序目录下的 data\\ 文件夹，扩展名为 .psvault，是整体加密的。
  每次保存还会生成同名 .bak 备份。直接复制整个 data 文件夹即可搬家/备份。

【出问题怎么办】
  在命令行里执行：密码保险箱.exe --selftest
  它会把运行环境自检结果写到同目录的 selftest.log，便于定位问题。

【注意】
  整个文件夹要一起拷贝，不能只拿 exe —— 运行库在 _internal 目录里。
  建议把整个「密码保险箱」文件夹放到自己熟悉的位置（例如 D:\\软件\\），
  不要放在 C:\\Program Files 这类需要管理员权限的目录。
"""


def run(command: list[str]) -> int:
    """执行外部命令并实时回显。"""
    print("  $ " + " ".join(command))
    return subprocess.call(command, cwd=str(ROOT))


def main() -> int:
    skip_clean = "--no-clean" in sys.argv

    print("[1/4] 生成应用图标…")
    if run([sys.executable, str(ROOT / "tools" / "make_icon.py")]) != 0:
        print("图标生成失败。")
        return 1
    if not ICON.exists():
        print(f"找不到图标文件：{ICON}")
        return 1

    if not skip_clean:
        print("[2/4] 清理旧的构建产物…")
        for folder in (BUILD, DIST):
            if folder.exists():
                shutil.rmtree(folder)
                print(f"  已删除 {folder.relative_to(ROOT)}")
    else:
        print("[2/4] 跳过清理")

    print("[3/4] 调用 PyInstaller 打包（首次执行需要几分钟）…")
    command = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm", "--clean",
        "--windowed",              # 不弹控制台窗口
        "--onedir",                # 单目录形式
        "--name", APP_NAME,
        "--icon", str(ICON),
        "--version-file", str(VERSION_FILE),
        "--distpath", str(DIST),
        "--workpath", str(BUILD),
        "--specpath", str(BUILD),
    ]
    for module in EXCLUDES:
        command += ["--exclude-module", module]
    command.append(str(ROOT / "main.py"))

    if run(command) != 0:
        print("打包失败，请查看上面的错误信息。")
        return 1

    target = DIST / APP_NAME
    exe = target / f"{APP_NAME}.exe"
    if not exe.exists():
        print(f"打包结束但没找到 {exe}")
        return 1

    (target / "使用说明.txt").write_text(README_TEXT, encoding="utf-8")

    total = sum(f.stat().st_size for f in target.rglob("*") if f.is_file())
    print("[4/4] 完成")
    print(f"  输出目录：{target}")
    print(f"  主程序  ：{exe}  ({exe.stat().st_size / 1024 / 1024:.1f} MB)")
    print(f"  总体积  ：{total / 1024 / 1024:.1f} MB")
    return 0


if __name__ == "__main__":
    sys.exit(main())
