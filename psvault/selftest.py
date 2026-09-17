"""打包后的健康自检。

打包成 exe 后最怕"双击没反应"—— GUI 程序没有控制台，出错也看不到。
因此提供一个隐藏参数：

    密码保险箱.exe --selftest

它会依次验证数据目录可写、加解密往返、图标渲染、主界面构建，
把结果写进 exe 同级的 selftest.log，并用退出码表示成功（0）或失败（1）。
"""

from __future__ import annotations

import sys
import tempfile
import traceback
from pathlib import Path

LOG_NAME = "selftest.log"


def _log_path() -> Path:
    """自检日志写到程序根目录（打包后即 exe 所在目录）。"""
    from .core.storage import application_root

    return application_root() / LOG_NAME


def emit(text: str) -> None:
    """往控制台输出。

    打包成 --windowed 的程序没有控制台，sys.stdout 会是 None，
    这里必须容错，否则自检本身会因打印而崩溃。
    """
    stream = sys.stdout
    if stream is None:
        return
    try:
        stream.write(text + "\n")
        stream.flush()
    except (OSError, ValueError, AttributeError):
        pass


def run_selftest(argv: list[str] | None = None) -> int:
    """执行自检，返回退出码。"""
    lines: list[str] = []
    failed = False

    def record(message: str) -> None:
        lines.append(message)

    def step(title: str) -> None:
        lines.append(f"[ 通过 ] {title}")

    try:
        record("密码保险箱 — 运行环境自检")
        record("=" * 46)
        record(f"Python      : {sys.version.split()[0]}")
        record(f"可执行文件  : {sys.executable}")
        record(f"打包模式    : {'是' if getattr(sys, 'frozen', False) else '否（源码运行）'}")

        # 1. 依赖
        import cryptography
        import PySide6

        record(f"PySide6     : {PySide6.__version__}")
        record(f"cryptography: {cryptography.__version__}")
        step("依赖模块导入")

        # 2. 程序目录与数据目录
        from .core import crypto, totp
        from .core.storage import DEFAULT_DATA_DIR, Vault, application_root

        root = application_root()
        record(f"程序目录    : {root}")
        record(f"数据目录    : {DEFAULT_DATA_DIR}")

        DEFAULT_DATA_DIR.mkdir(parents=True, exist_ok=True)
        probe = DEFAULT_DATA_DIR / ".write-probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        step("数据目录可写")

        # 3. 加解密往返
        salt = crypto.new_salt()
        kdf = crypto.kdf_parameters(salt)
        key = crypto.derive_key("自检密码#2024", salt)
        container = crypto.encrypt_payload("自检数据".encode("utf-8"), key, kdf)
        assert crypto.decrypt_payload(container, key) == "自检数据".encode("utf-8")
        try:
            crypto.decrypt_payload(container, crypto.derive_key("错误密码", salt))
            raise AssertionError("错误密码竟然解密成功")
        except crypto.InvalidPassword:
            pass
        step("AES-256-GCM 加解密与密码校验")

        # 4. 保险箱读写
        with tempfile.TemporaryDirectory(prefix="psvault-selftest-") as tmp:
            from .core.models import Entry

            path = Path(tmp) / "selftest.psvault"
            vault = Vault.create(path, "自检密码#2024", name="自检保险箱")
            vault.settings.backup_external_dir = str(Path(tmp) / "external")   # 不写到用户目录
            vault.add_entry(Entry(title="自检条目", username="tester",
                                  password="Self#Check2024", phone="13800000000"))
            vault.save()
            reopened = Vault.open(path, "自检密码#2024")
            assert reopened.name == "自检保险箱"
            assert reopened.active_entries()[0].phone == "13800000000"
            assert "密钥" in reopened.categories
        step("保险箱创建 / 保存 / 重新打开")

        # 5. TOTP
        assert totp.generate_code("JBSWY3DPEHPK3PXP", at=59).isdigit()
        step("两步验证口令生成")

        # 6. 界面（真实图形平台，能验证 Qt 插件是否齐全）
        from PySide6.QtWidgets import QApplication

        from .ui import icons
        from .ui.main_window import MainWindow
        from .ui.theme import Theme

        app = QApplication.instance() or QApplication(argv or ["selftest"])
        theme = Theme.instance()
        theme.apply(app)
        record(f"Qt 平台插件 : {app.platformName()}")

        icon = icons.app_icon()
        assert not icon.isNull(), "应用图标为空"
        logo = icons.build_logo(theme.hex("accent"), 32)
        assert not logo.isNull(), "矢量标志渲染失败（QtSvg 可能缺失）"
        step("矢量图标渲染（QtSvg）")

        with tempfile.TemporaryDirectory(prefix="psvault-selftest-") as tmp:
            path = Path(tmp) / "ui.psvault"
            vault = Vault.create(path, "自检密码#2024", name="自检保险箱")
            vault.settings.backup_external_dir = str(Path(tmp) / "external")
            vault.add_entry(Entry(title="界面自检", username="tester",
                                  password="Ui#Check2024", totp_secret="JBSWY3DPEHPK3PXP"))
            window = MainWindow(vault)
            window.resize(1180, 760)
            window.select_entry(vault.active_entries()[0].id)
            window.show()
            for _ in range(4):
                app.processEvents()
            assert window.isVisible(), "主窗口不可见"
            assert window.totp_label.text().replace(" ", "").isdigit(), "动态口令未刷新"
            shot = Path(tempfile.gettempdir()) / "psvault-selftest.png"
            window.grab().save(str(shot), "PNG")
            record(f"界面截图    : {shot}")
            window.hide()
        step("主界面构建与渲染")

        record("=" * 46)
        record("自检结果    : 全部通过 ✓")

    except Exception as exc:  # noqa: BLE001 - 自检要吞掉所有异常并记录
        failed = True
        record("=" * 46)
        record(f"自检失败    : {type(exc).__name__}: {exc}")
        record("")
        record(traceback.format_exc())

    text = "\n".join(lines) + "\n"
    target = _log_path()
    try:
        target.write_text(text, encoding="utf-8")
    except OSError as exc:
        text += f"\n（日志写入失败：{exc}）\n"

    emit(text)
    emit(f"日志已写入：{target}")
    return 1 if failed else 0
