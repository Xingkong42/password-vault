"""核心逻辑单元测试：密码学、存储、生成器、强度评估、TOTP、导入导出。

运行：python -m unittest discover -s tests -v
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from psvault.core import crypto, generator, porting, storage, strength, totp  # noqa: E402
from psvault.core.backup import BackupManager  # noqa: E402
from psvault.core.models import Entry, Settings  # noqa: E402
from psvault.core.storage import Vault  # noqa: E402


class CryptoTest(unittest.TestCase):
    """加解密与主密码校验。"""

    def test_roundtrip(self) -> None:
        salt = crypto.new_salt()
        kdf = crypto.kdf_parameters(salt)
        key = crypto.derive_key("正确密码123", salt)
        container = crypto.encrypt_payload("机密内容".encode(), key, kdf)
        self.assertEqual(crypto.decrypt_payload(container, key), "机密内容".encode())

    def test_wrong_password(self) -> None:
        salt = crypto.new_salt()
        kdf = crypto.kdf_parameters(salt)
        key = crypto.derive_key("正确密码", salt)
        container = crypto.encrypt_payload(b"data", key, kdf)
        wrong = crypto.derive_key("错误密码", salt)
        with self.assertRaises(crypto.InvalidPassword):
            crypto.decrypt_payload(container, wrong)

    def test_tamper_detected(self) -> None:
        """篡改密文必须被 GCM 认证标签发现。"""
        salt = crypto.new_salt()
        kdf = crypto.kdf_parameters(salt)
        key = crypto.derive_key("pw", salt)
        container = crypto.encrypt_payload(b"hello", key, kdf)
        raw = bytearray(container["payload"].encode())
        raw[5] = ord("A") if raw[5] != ord("A") else ord("B")
        container["payload"] = raw.decode()
        with self.assertRaises(crypto.VaultError):
            crypto.decrypt_payload(container, key)

    def test_header_protected(self) -> None:
        """降低 scrypt 强度参数会导致认证失败。"""
        salt = crypto.new_salt()
        kdf = crypto.kdf_parameters(salt)
        key = crypto.derive_key("pw", salt)
        container = crypto.encrypt_payload(b"hello", key, kdf)
        container["kdf"]["n"] = 2
        with self.assertRaises(crypto.InvalidPassword):
            crypto.decrypt_payload(container, key)


class VaultTest(unittest.TestCase):
    """保险箱读写与条目操作。"""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "v.psvault"
        self.vault = Vault.create(self.path, "Master#2024")
        # 备份目录一律指向临时目录，任何测试都不该碰真实的「文档」目录
        self.vault.settings.backup_external_dir = str(Path(self.tmp.name) / "external")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_history_limit_setting_is_respected(self) -> None:
        """回归用例：设置里的"保留几条历史密码"必须真的生效。

        之前 apply_password 写死用模块常量 10，设置项形同虚设。
        """
        self.vault.settings.history_limit = 3
        entry = self.vault.add_entry(Entry(title="A", password="p0"))
        for index in range(1, 8):
            self.vault.update_entry(entry.id, {}, new_password=f"p{index}")
        self.assertEqual(len(entry.history), 3)
        self.assertEqual(entry.history[0].password, "p6")

    def test_history_limit_zero_keeps_nothing(self) -> None:
        self.vault.settings.history_limit = 0
        entry = self.vault.add_entry(Entry(title="A", password="old"))
        self.vault.update_entry(entry.id, {}, new_password="new")
        self.assertEqual(entry.history, [])

    def test_prune_history_trims_existing_records(self) -> None:
        """把保留份数调小时，已有记录的历史应立即被裁剪。"""
        self.vault.settings.history_limit = 10
        entry = self.vault.add_entry(Entry(title="A", password="p0"))
        for index in range(1, 6):
            self.vault.update_entry(entry.id, {}, new_password=f"p{index}")
        self.assertEqual(len(entry.history), 5)

        self.vault.settings.history_limit = 2
        self.assertEqual(self.vault.prune_history(), 3)
        self.assertEqual(len(entry.history), 2)
        self.assertEqual(entry.history[0].password, "p4")

    def test_update_entry_tolerates_none_values(self) -> None:
        """字段传 None 时应存成空值，而不是字面量 "None"。"""
        entry = self.vault.add_entry(Entry(title="A", password="p", notes="原有备注"))
        self.vault.update_entry(entry.id, {"title": None, "notes": None, "tags": None})
        updated = self.vault.find(entry.id)
        self.assertEqual(updated.title, "")
        self.assertEqual(updated.notes, "")
        self.assertEqual(updated.tags, [])

    def test_create_and_open(self) -> None:
        self.vault.add_entry(Entry(title="GitHub", username="me", password="s3cret"))
        self.vault.save()
        reopened = Vault.open(self.path, "Master#2024")
        self.assertEqual(len(reopened.active_entries()), 1)
        self.assertEqual(reopened.active_entries()[0].title, "GitHub")

    def test_open_wrong_password(self) -> None:
        with self.assertRaises(crypto.InvalidPassword):
            Vault.open(self.path, "错误主密码")

    def test_plaintext_not_leaked(self) -> None:
        """落盘内容不得包含任何明文密码或标题。"""
        self.vault.add_entry(Entry(title="银行", username="user1", password="P@ssw0rd!"))
        self.vault.save()
        raw = self.path.read_text(encoding="utf-8")
        for secret in ("银行", "user1", "P@ssw0rd!"):
            self.assertNotIn(secret, raw)

    def test_password_history(self) -> None:
        entry = self.vault.add_entry(Entry(title="A", password="old"))
        self.vault.update_entry(entry.id, {}, new_password="new")
        self.assertEqual(entry.password, "new")
        self.assertEqual(entry.history[0].password, "old")

    def test_trash_and_restore(self) -> None:
        entry = self.vault.add_entry(Entry(title="A"))
        self.vault.trash_entry(entry.id)
        self.assertEqual(len(self.vault.active_entries()), 0)
        self.assertEqual(len(self.vault.trashed_entries()), 1)
        self.vault.restore_entry(entry.id)
        self.assertEqual(len(self.vault.active_entries()), 1)
        self.vault.trash_entry(entry.id)
        self.assertEqual(self.vault.empty_trash(), 1)
        self.assertEqual(len(self.vault.entries), 0)

    def test_category_rename_and_remove(self) -> None:
        self.vault.add_category("工作")
        entry = self.vault.add_entry(Entry(title="A", category="工作"))
        self.vault.rename_category("工作", "办公")
        self.assertEqual(entry.category, "办公")
        self.vault.remove_category("办公")
        self.assertEqual(entry.category, "未分类")

    def test_change_master_password(self) -> None:
        self.vault.add_entry(Entry(title="A", password="x"))
        self.vault.change_master_password("新主密码!234")
        with self.assertRaises(crypto.InvalidPassword):
            Vault.open(self.path, "Master#2024")
        reopened = Vault.open(self.path, "新主密码!234")
        self.assertEqual(len(reopened.entries), 1)

    def _prepare_backups(self) -> None:
        """把备份目录指到临时目录并先造出几份旧密码的备份。"""
        self.vault.settings.backup_external_dir = str(Path(self.tmp.name) / "ext")
        self.vault.settings.backup_external_enabled = True
        self.vault.add_entry(Entry(title="A", password="x"))
        self.vault.save()
        self.vault.backup_manager().backup(force=True)

    def test_change_master_password_refreshes_backups(self) -> None:
        """改密后必须有一份新密码的备份，旧密码的备份被清理。"""
        self._prepare_backups()
        self.vault.settings.rekey_purges_old_backups = True
        self.assertTrue(self.vault.backup_manager().list())

        removed = self.vault.change_master_password("新主密码!234")
        self.assertGreater(removed, 0, "应清理掉旧密码的备份")

        backups = self.vault.backup_manager().list()
        self.assertTrue(backups, "至少要留下一份能用的备份")
        for info in backups:
            reopened = Vault.open(info.path, "新主密码!234")
            self.assertEqual(len(reopened.entries), 1)

    def test_change_master_password_can_keep_old_backups(self) -> None:
        self._prepare_backups()
        removed = self.vault.change_master_password("新主密码!234",
                                                    purge_old_backups=False)
        self.assertEqual(removed, 0)
        self.assertGreater(len(self.vault.backup_manager().list()), 1)

    def test_editing_notes_keeps_password_age(self) -> None:
        entry = self.vault.add_entry(Entry(title="A", password="Xk7#mQ2!vL9$pR4@"))
        entry.password_changed_at = (datetime.now().astimezone()
                                     - timedelta(days=400)).isoformat(timespec="seconds")
        self.vault.update_entry(entry.id, {"notes": "只是改了个备注"})
        self.assertGreaterEqual(self.vault.find(entry.id).password_age_days(), 399)

    def test_search(self) -> None:
        self.vault.add_entry(Entry(title="淘宝", username="shop", tags=["购物"]))
        self.vault.add_entry(Entry(title="GitHub", notes="代码托管"))
        hits = [e for e in self.vault.active_entries() if e.matches("代码")]
        self.assertEqual(len(hits), 1)

    def test_statistics(self) -> None:
        self.vault.add_entry(Entry(title="A", favorite=True, totp_secret="JBSWY3DPEHPK3PXP"))
        stats = self.vault.statistics()
        self.assertEqual(stats["total"], 1)
        self.assertEqual(stats["favorite"], 1)
        self.assertEqual(stats["with_totp"], 1)


class GeneratorTest(unittest.TestCase):
    """密码生成器。"""

    def test_length_and_charset(self) -> None:
        options = generator.GeneratorOptions(length=24)
        for _ in range(20):
            pwd = generator.generate_password(options)
            self.assertEqual(len(pwd), 24)
            self.assertTrue(any(c.islower() for c in pwd))
            self.assertTrue(any(c.isupper() for c in pwd))
            self.assertTrue(any(c.isdigit() for c in pwd))
            self.assertTrue(any(c in generator.SYMBOLS for c in pwd))

    def test_exclude_ambiguous(self) -> None:
        options = generator.GeneratorOptions(length=60, exclude_ambiguous=True, require_each_type=False)
        pwd = generator.generate_password(options)
        self.assertFalse(set(pwd) & set(generator.AMBIGUOUS))

    def test_digits_only(self) -> None:
        options = generator.GeneratorOptions(
            length=10, use_lowercase=False, use_uppercase=False, use_digits=True, use_symbols=False
        )
        self.assertTrue(generator.generate_password(options).isdigit())

    def test_no_charset(self) -> None:
        options = generator.GeneratorOptions(
            length=10, use_lowercase=False, use_uppercase=False, use_digits=False, use_symbols=False
        )
        with self.assertRaises(generator.GeneratorError):
            generator.generate_password(options)

    def test_passphrase(self) -> None:
        phrase = generator.generate_passphrase(words=5)
        self.assertEqual(len(phrase.split("-")), 6)

    def test_uniqueness(self) -> None:
        options = generator.GeneratorOptions(length=16)
        self.assertEqual(len(set(generator.generate_batch(options, 20))), 20)


class StrengthTest(unittest.TestCase):
    """强度评估。"""

    def test_weak(self) -> None:
        self.assertLessEqual(strength.evaluate("123456").score, 1)
        self.assertLessEqual(strength.evaluate("password").score, 1)

    def test_strong(self) -> None:
        self.assertGreaterEqual(strength.evaluate("Xk7#mQ2!vL9$pR4@").score, 3)

    def test_entropy_monotonic(self) -> None:
        self.assertGreater(strength.estimate_entropy("abcdefghij"), strength.estimate_entropy("abc"))

    def test_audit_groups(self) -> None:
        entries = [
            Entry(title="A", password="123456"),
            Entry(title="B", password="same-pass-8888"),
            Entry(title="C", password="same-pass-8888"),
            Entry(title="D", password=""),
        ]
        result = strength.audit(entries)
        self.assertTrue(any(e.title == "A" for e in result["weak"]))
        self.assertEqual({e.title for e in result["reused"]}, {"B", "C"})
        self.assertEqual(len(result["empty"]), 1)


class TotpTest(unittest.TestCase):
    """TOTP 生成（RFC 6238 附录 B 测试向量）。"""

    SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"  # "12345678901234567890"

    def test_rfc_vector(self) -> None:
        self.assertEqual(totp.generate_code(self.SECRET, digits=8, at=59), "94287082")
        self.assertEqual(totp.generate_code(self.SECRET, digits=8, at=1111111109), "07081804")

    def test_six_digits(self) -> None:
        code = totp.generate_code("JBSWY3DPEHPK3PXP")
        self.assertEqual(len(code), 6)
        self.assertTrue(code.isdigit())

    def test_otpauth_parse(self) -> None:
        uri = ("otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP"
               "&issuer=GitHub&digits=6&period=60&algorithm=SHA256")
        config = totp.parse_otpauth(uri)
        self.assertIsNotNone(config)
        self.assertEqual(config.issuer, "GitHub")
        self.assertEqual(config.account, "alice")
        self.assertEqual(config.period, 60)
        self.assertEqual(config.algorithm, "SHA256")

    def test_secret_validation(self) -> None:
        self.assertTrue(totp.is_valid_secret("JBSWY3DPEHPK3PXP"))
        self.assertFalse(totp.is_valid_secret("!!!"))
        self.assertTrue(totp.is_valid_secret("jbs w y3dp ehpk 3pxp"))

    def test_remaining(self) -> None:
        self.assertEqual(totp.seconds_remaining(30, at=0.0), 30)
        self.assertEqual(totp.seconds_remaining(30, at=29.0), 1)

    def test_bad_numeric_params_return_none(self) -> None:
        """畸形的 digits / period 应该判为不可解析，而不是抛 ValueError。"""
        for uri in (
            "otpauth://totp/Test:alice?secret=JBSWY3DPEHPK3PXP&digits=abc",
            "otpauth://totp/Test:alice?secret=JBSWY3DPEHPK3PXP&period=xyz",
            "otpauth://totp/Test:alice?secret=JBSWY3DPEHPK3PXP&digits=0",
            "otpauth://totp/Test:alice?secret=JBSWY3DPEHPK3PXP&period=0",
        ):
            self.assertIsNone(totp.parse_secret_input(uri), uri)

    def test_missing_params_use_defaults(self) -> None:
        config = totp.parse_secret_input("otpauth://totp/Test:alice?secret=JBSWY3DPEHPK3PXP")
        self.assertIsNotNone(config)
        self.assertEqual(config.digits, 6)
        self.assertEqual(config.period, 30)

    def test_garbage_input_never_raises(self) -> None:
        """解析入口绝不抛异常——它会被输入框的 textChanged 直接调用。"""
        for text in ("这不是密钥", "abc!!!", "otpauth://", "otpauth://totp/",
                     "otpauth://totp/x?secret=", "!!!@@@###", "otpauth://totp/x?secret=???"):
            self.assertIsNone(totp.parse_secret_input(text), text)


class PortingTest(unittest.TestCase):
    """CSV / JSON 导入导出。"""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_csv_roundtrip(self) -> None:
        entries = [Entry(title="淘宝", username="me", password="p1", url="https://taobao.com",
                         category="购物", tags=["a", "b"], notes="备注")]
        path = self.dir / "out.csv"
        self.assertEqual(porting.export_csv(entries, path), 1)
        back = porting.import_csv(path)
        self.assertEqual(len(back), 1)
        self.assertEqual(back[0].title, "淘宝")
        self.assertEqual(back[0].tags, ["a", "b"])

    def test_csv_chinese_header(self) -> None:
        path = self.dir / "cn.csv"
        path.write_text("名称,用户名,密码,网址\n知乎,user,pass123,https://zhihu.com\n",
                        encoding="utf-8-sig")
        back = porting.import_csv(path)
        self.assertEqual(back[0].title, "知乎")
        self.assertEqual(back[0].username, "user")

    def test_csv_chrome_format(self) -> None:
        path = self.dir / "chrome.csv"
        path.write_text("name,url,username,password\nExample,https://e.com,me,pw\n", encoding="utf-8")
        back = porting.import_csv(path)
        self.assertEqual(back[0].title, "Example")
        self.assertEqual(back[0].url, "https://e.com")

    def test_json_roundtrip(self) -> None:
        entries = [Entry(title="X", password="p")]
        path = self.dir / "out.json"
        porting.export_json(entries, path)
        back = porting.import_json(path)
        self.assertEqual(back[0].title, "X")
        self.assertEqual(back[0].password, "p")

    def test_csv_keeps_reserved_phone_and_email(self) -> None:
        """导出再导入时，预留电话/邮箱不能与登录账号串位。"""
        entries = [Entry(title="T", username="login_name", password="p",
                         phone="13800000000", email="backup@example.com")]
        path = self.dir / "contact.csv"
        porting.export_csv(entries, path)
        back = porting.import_csv(path)
        self.assertEqual(back[0].username, "login_name")
        self.assertEqual(back[0].phone, "13800000000")
        self.assertEqual(back[0].email, "backup@example.com")

    def test_csv_chinese_contact_headers(self) -> None:
        path = self.dir / "contact_cn.csv"
        path.write_text("名称,用户名,密码,手机号,备用邮箱\n某站,user,pw,13900000000,spare@x.com\n",
                        encoding="utf-8-sig")
        back = porting.import_csv(path)
        self.assertEqual(back[0].username, "user")
        self.assertEqual(back[0].phone, "13900000000")
        self.assertEqual(back[0].email, "spare@x.com")


class EntryFieldsTest(unittest.TestCase):
    """新增字段（预留电话 / 预留邮箱）的兼容性。"""

    def test_roundtrip(self) -> None:
        entry = Entry(title="A", phone="13800000000", email="a@example.com")
        restored = Entry.from_dict(entry.to_dict())
        self.assertEqual(restored.phone, "13800000000")
        self.assertEqual(restored.email, "a@example.com")

    def test_legacy_entry_without_new_fields(self) -> None:
        """老数据没有这两个字段时应正常加载为空值。"""
        entry = Entry.from_dict({"title": "旧记录", "username": "u", "password": "p"})
        self.assertEqual(entry.phone, "")
        self.assertEqual(entry.email, "")

    def test_search_covers_contact_fields(self) -> None:
        entry = Entry(title="A", phone="13800000000", email="backup@example.com")
        self.assertTrue(entry.matches("1380"))
        self.assertTrue(entry.matches("backup"))


class VaultNameTest(unittest.TestCase):
    """保险箱名称与默认分类。"""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "named.psvault"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_default_categories_include_key(self) -> None:
        vault = Vault.create(self.path, "Master#2024")
        self.assertIn("密钥", vault.categories)
        self.assertIn("邮箱", vault.categories)

    def test_create_with_name(self) -> None:
        vault = Vault.create(self.path, "Master#2024", name="我的密码库")
        self.assertEqual(vault.name, "我的密码库")
        reopened = Vault.open(self.path, "Master#2024")
        self.assertEqual(reopened.name, "我的密码库")

    def test_name_falls_back_to_filename(self) -> None:
        vault = Vault.create(self.path, "Master#2024")
        self.assertEqual(vault.name, "named")

    def test_set_name(self) -> None:
        vault = Vault.create(self.path, "Master#2024")
        vault.set_name("工作保险箱")
        vault.save()
        self.assertEqual(Vault.open(self.path, "Master#2024").name, "工作保险箱")

    def test_sanitize_filename(self) -> None:
        self.assertEqual(storage.sanitize_filename('我的/密码:库*?"'), "我的密码库")
        self.assertEqual(storage.sanitize_filename("   "), "vault")

    def test_legacy_vault_gets_new_categories_once(self) -> None:
        """老文件补齐新增分类，且用户删除后不会被再次补回。"""
        vault = Vault.create(self.path, "Master#2024")
        vault.categories = ["未分类", "邮箱"]
        vault.meta.pop("schema_version", None)
        vault.save()

        reopened = Vault.open(self.path, "Master#2024")
        self.assertIn("密钥", reopened.categories)
        self.assertTrue(reopened.dirty)

        reopened.remove_category("密钥")
        reopened.save()

        again = Vault.open(self.path, "Master#2024")
        self.assertNotIn("密钥", again.categories)
        self.assertFalse(again.dirty)

    def test_user_can_add_and_remove_categories(self) -> None:
        vault = Vault.create(self.path, "Master#2024")
        self.assertTrue(vault.add_category("设备"))
        self.assertFalse(vault.add_category("设备"))          # 去重
        entry = vault.add_entry(Entry(title="路由器", category="设备"))
        self.assertTrue(vault.remove_category("设备"))
        self.assertEqual(entry.category, "未分类")
        self.assertFalse(vault.remove_category("未分类"))       # 系统分类不可删


class EntryIssuesTest(unittest.TestCase):
    """单条记录体检：必须指出问题类型与具体原因。"""

    def test_weak_password_has_reason(self) -> None:
        entry = Entry(title="A", password="123456")
        issues = strength.entry_issues(entry, [entry])
        weak = next((i for i in issues if i.kind == "weak"), None)
        self.assertIsNotNone(weak)
        self.assertEqual(weak.severity, "high")
        self.assertTrue(weak.detail, "必须给出具体原因，而不是只说'有风险'")
        self.assertTrue(weak.short_label)

    def test_reused_points_to_other_accounts(self) -> None:
        first = Entry(title="甲站", password="same-pass-1234")
        second = Entry(title="乙站", password="same-pass-1234")
        issues = strength.entry_issues(first, [first, second])
        reused = next((i for i in issues if i.kind == "reused"), None)
        self.assertIsNotNone(reused)
        self.assertIn("乙站", reused.detail)

    def test_aged_password(self) -> None:
        entry = Entry(title="A", password="Xk7#mQ2!vL9$pR4@")
        old = datetime.now().astimezone() - timedelta(days=400)
        entry.password_changed_at = old.isoformat(timespec="seconds")
        issues = strength.entry_issues(entry, [entry], max_age_days=180)
        aged = next((i for i in issues if i.kind == "aged"), None)
        self.assertIsNotNone(aged)
        self.assertIn("400", aged.title)

    def test_editing_other_fields_does_not_reset_password_age(self) -> None:
        """回归用例：改备注会刷新 updated_at，但不该把密码年龄清零。"""
        entry = Entry(title="A", password="Xk7#mQ2!vL9$pR4@")
        old = datetime.now().astimezone() - timedelta(days=400)
        entry.password_changed_at = old.isoformat(timespec="seconds")
        entry.touch()                       # 模拟"只改了个备注"
        self.assertEqual(entry.age_days(), 0)
        self.assertGreaterEqual(entry.password_age_days(), 399)
        self.assertIn("aged", [i.kind for i in
                               strength.entry_issues(entry, [entry], max_age_days=180)])

    def test_changing_password_resets_age(self) -> None:
        entry = Entry(title="A", password="OldPass#1234")
        entry.password_changed_at = (datetime.now().astimezone()
                                     - timedelta(days=400)).isoformat(timespec="seconds")
        entry.apply_password("NewPass#9876")
        self.assertEqual(entry.password_age_days(), 0)

    def test_legacy_entry_falls_back_to_updated_at(self) -> None:
        """老数据没有 password_changed_at，用修改时间兜底，不能全部误报过期。"""
        recent = datetime.now().astimezone() - timedelta(days=3)
        entry = Entry.from_dict({
            "title": "旧记录", "password": "Xk7#mQ2!vL9$pR4@",
            "updated_at": recent.isoformat(timespec="seconds"),
        })
        self.assertLessEqual(entry.password_age_days(), 4)

    def test_entry_roundtrip_keeps_password_changed_at(self) -> None:
        entry = Entry(title="A", password="p")
        entry.password_changed_at = "2025-01-02T03:04:05+08:00"
        restored = Entry.from_dict(entry.to_dict())
        self.assertEqual(restored.password_changed_at, "2025-01-02T03:04:05+08:00")

    def test_empty_password(self) -> None:
        entry = Entry(title="A", password="")
        issues = strength.entry_issues(entry, [entry])
        self.assertEqual(issues[0].kind, "empty")
        self.assertTrue(issues[0].is_risk)

    def test_healthy_entry_has_no_risk(self) -> None:
        entry = Entry(title="A", password="Xk7#mQ2!vL9$pR4@",
                      totp_secret="JBSWY3DPEHPK3PXP")
        issues = strength.entry_issues(entry, [entry])
        self.assertEqual([i for i in issues if i.is_risk], [])

    def test_risk_entries_filters(self) -> None:
        good = Entry(title="好", password="Xk7#mQ2!vL9$pR4@",
                     totp_secret="JBSWY3DPEHPK3PXP")
        bad = Entry(title="坏", password="123456")
        result = strength.risk_entries([good, bad])
        self.assertEqual([e.title for e in result], ["坏"])


    def test_guessable_by_site_name(self) -> None:
        """密码里含网站名：强度可能达标，但仍要单独提示。"""
        entry = Entry(title="GitHub", username="xingkong42",
                      password="Github@2024#Secure", url="https://github.com")
        hit = next((i for i in strength.entry_issues(entry, [entry])
                    if i.kind == "guessable"), None)
        self.assertIsNotNone(hit)
        self.assertIn("网站名", hit.title)
        self.assertIn("网站名", hit.detail)

    def test_guessable_by_username(self) -> None:
        entry = Entry(title="某站", username="zhangsan@example.com",
                      password="zhangsan_2024!")
        hit = next((i for i in strength.entry_issues(entry, [entry])
                    if i.kind == "guessable"), None)
        self.assertIsNotNone(hit)
        self.assertIn("账号名", hit.title)

    def test_unrelated_password_not_flagged(self) -> None:
        entry = Entry(title="GitHub", username="xingkong42",
                      password="Xk7#mQ2!vL9$pR4@")
        self.assertNotIn("guessable", [i.kind for i in
                                       strength.entry_issues(entry, [entry])])

    def test_generic_subdomain_is_not_a_site_name(self) -> None:
        """www / mail 这类通用子域不该拿来判定"密码含网站名"。"""
        entry = Entry(title="邮箱", username="someone",
                      password="Mail#2024!Secure", url="https://mail.example.com")
        self.assertNotIn("guessable", [i.kind for i in
                                       strength.entry_issues(entry, [entry])])

    def test_insecure_http_flagged(self) -> None:
        entry = Entry(title="老站", password="Xk7#mQ2!vL9$pR4@",
                      url="http://old-site.example.com/login")
        self.assertIn("insecure", [i.kind for i in
                                   strength.entry_issues(entry, [entry])])

    def test_https_not_flagged(self) -> None:
        entry = Entry(title="新站", password="Xk7#mQ2!vL9$pR4@",
                      url="https://new-site.example.com")
        self.assertNotIn("insecure", [i.kind for i in
                                      strength.entry_issues(entry, [entry])])

    def test_internal_http_not_flagged(self) -> None:
        """内网与本机地址用 http 是正常的，不该报警。"""
        for url in ("http://192.168.1.1", "http://10.0.0.5/admin",
                    "http://127.0.0.1:8080", "http://localhost:3000",
                    "http://router.local", "http://172.16.0.1",
                    "http://172.31.255.9", "http://169.254.1.1"):
            entry = Entry(title="内网设备", password="Xk7#mQ2!vL9$pR4@", url=url)
            self.assertNotIn("insecure", [i.kind for i in
                                          strength.entry_issues(entry, [entry])],
                             f"{url} 不应被判为明文传输风险")

    def test_public_172_address_is_flagged(self) -> None:
        """172.32 已经不属于内网段，应照常提醒。"""
        entry = Entry(title="公网站点", password="Xk7#mQ2!vL9$pR4@",
                      url="http://172.32.0.1")
        self.assertIn("insecure", [i.kind for i in
                                   strength.entry_issues(entry, [entry])])

    def test_insecure_http_reported_even_without_password(self) -> None:
        entry = Entry(title="空密码站", password="", url="http://plain.example.com")
        self.assertIn("insecure", [i.kind for i in
                                   strength.entry_issues(entry, [entry])])

    def test_analyze_matches_single_entry_api(self) -> None:
        """批量接口与逐条接口必须给出完全一致的结果。"""
        entries = [
            Entry(title="甲", password="same-pass-1234"),
            Entry(title="乙", password="same-pass-1234"),
            Entry(title="丙", password="123456"),
            Entry(title="丁", password=""),
            Entry(title="戊", password="Xk7#mQ2!vL9$pR4@",
                  totp_secret="JBSWY3DPEHPK3PXP"),
        ]
        analyzed = strength.analyze_entries(entries)
        self.assertEqual(set(analyzed), {e.id for e in entries})
        for entry in entries:
            single = strength.entry_issues(entry, entries)
            batch = analyzed[entry.id]
            self.assertEqual([i.kind for i in single], [i.kind for i in batch])
            for one, other in zip(single, batch):
                self.assertEqual(one.title, other.title)
                self.assertEqual(one.detail, other.detail)
                self.assertEqual(one.severity, other.severity)
                self.assertEqual(one.ignored, other.ignored)

    def test_analyze_respects_ignored(self) -> None:
        first = Entry(title="甲", password="123456")
        second = Entry(title="乙", password="123456")
        first.ignore_issue("weak")
        analyzed = strength.analyze_entries([first, second])
        weak = next(i for i in analyzed[first.id] if i.kind == "weak")
        self.assertTrue(weak.ignored)

    def test_analyze_is_not_slower_than_per_entry_calls(self) -> None:
        """批量接口不该慢于逐条调用。

        注意：实际耗时里密码强度评估占大头，重复比较只是其中一部分，
        所以这里只断言"没有倒退"，不追求倍数。
        """
        entries = [Entry(title=f"站点{i}", password=f"Pass#{i:05d}x")
                   for i in range(1200)]
        for index in range(0, 1200, 2):          # 一半记录共用同一个密码
            entries[index].password = "Shared#Pass123"

        start = time.perf_counter()
        analyzed = strength.analyze_entries(entries)
        batch_elapsed = time.perf_counter() - start

        start = time.perf_counter()
        for entry in entries:
            strength.entry_issues(entry, entries)
        per_entry_elapsed = time.perf_counter() - start

        self.assertEqual(len(analyzed), 1200)
        self.assertLessEqual(batch_elapsed, per_entry_elapsed)


class BackupTest(unittest.TestCase):
    """自动备份、清理与恢复。"""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.path = self.dir / "v.psvault"
        self.external = self.dir / "external"
        self.vault = Vault.create(self.path, "Master#2024")
        self.vault.settings.backup_external_dir = str(self.external)
        self.vault.settings.backup_external_enabled = True

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_save_backs_up_the_new_version(self) -> None:
        """回归用例：备份里必须有"刚保存的最新状态"。

        从前备份的是被覆盖的旧版本，于是文件误删后恢复只能拿到上一版，
        最新那条记录在任何备份里都不存在。
        """
        for index in range(1, 4):
            self.vault.add_entry(Entry(title=f"记录{index}", password="p"))
            self.vault.save()

        newest = self.vault.backup_manager().latest()
        self.assertIsNotNone(newest)
        reopened = Vault.open(newest.path, "Master#2024")
        self.assertEqual([e.title for e in reopened.active_entries()],
                         ["记录1", "记录2", "记录3"])

    def test_latest_is_really_the_newest_within_same_second(self) -> None:
        """同一秒内产生的多份备份，latest() 选出的必须真的是最新的那份。

        备份列表此前按文件 mtime 排序，同秒多份的顺序不稳定，用户按"最新"选
        可能正好选中空库——这正是上一次踩的坑。
        """
        for index in range(1, 5):
            self.vault.add_entry(Entry(title=f"记录{index}", password="p"))
            self.vault.save()

        newest = self.vault.backup_manager().latest()
        self.assertIsNotNone(newest)
        reopened = Vault.open(newest.path, "Master#2024")
        self.assertEqual(len(reopened.active_entries()), 4)

    def test_disaster_recovery_returns_latest_data(self) -> None:
        """端到端演练：整个数据目录被删后，从备份恢复要能拿回最新数据。

        外部备份必须放在数据目录**之外**（真实场景是「文档」目录），
        否则删了 data 连它一起没，也就没有这次演练的意义了。
        """
        outside = Path(tempfile.mkdtemp(prefix="psvault-outside-"))
        self.addCleanup(shutil.rmtree, outside, ignore_errors=True)
        self.vault.settings.backup_external_dir = str(outside)

        for index in range(1, 4):
            self.vault.add_entry(Entry(title=f"记录{index}", password="p"))
            self.vault.save()
        expected = [e.title for e in self.vault.active_entries()]

        shutil.rmtree(self.path.parent)             # 连同本地 backups 一起删掉
        self.assertFalse(self.path.exists())

        manager = BackupManager(self.path, external_dir=outside)
        backups = manager.list()
        self.assertTrue(backups, "外部备份应当还在")
        manager.restore(backups[0].path)

        reopened = Vault.open(self.path, "Master#2024")
        self.assertEqual([e.title for e in reopened.active_entries()], expected)

    def test_failed_save_does_not_create_backup(self) -> None:
        """校验失败的保存不该留下备份——备份里只能是能打开的好文件。"""
        self.vault.add_entry(Entry(title="第一版", password="p"))
        self.vault.save()
        before = len(self.vault.backup_manager().list())

        self.vault.add_entry(Entry(title="第二版", password="p"))
        original = Vault.verify_file
        calls = {"count": 0}

        def flaky(inner_self, path=None):
            calls["count"] += 1
            if calls["count"] == 1:
                raise ValueError("模拟写入异常")
            return original(inner_self, path)

        Vault.verify_file = flaky
        try:
            with self.assertRaises(crypto.VaultError):
                self.vault.save()
        finally:
            Vault.verify_file = original

        self.assertEqual(len(self.vault.backup_manager().list()), before,
                         "校验失败不该产生新备份")

    def test_backup_skips_unchanged_content(self) -> None:
        self.vault.add_entry(Entry(title="A", password="p"))
        self.vault.save()
        manager = self.vault.backup_manager()
        manager.backup(force=True)                  # 先给当前内容留一份
        self.assertEqual(manager.backup(), [], "内容没变时不该重复备份")

        self.vault.add_entry(Entry(title="B", password="p"))
        self.vault.save()                           # 保存时又会留一份历史版本
        self.assertGreater(len(manager.list()), 0)

    def test_backup_written_to_two_locations(self) -> None:
        self.vault.add_entry(Entry(title="A", password="p"))
        self.vault.save()
        locations = {info.location for info in self.vault.backup_manager().list()}
        self.assertEqual(locations, {"本地", "外部"})
        self.assertTrue((self.dir / "backups").is_dir())
        self.assertTrue(self.external.is_dir())

    def test_prune_keeps_limit(self) -> None:
        self.vault.settings.backup_keep = 3
        for index in range(6):
            self.vault.add_entry(Entry(title=f"E{index}", password="p"))
            self.vault.save()
        local = [i for i in self.vault.backup_manager().list() if i.location == "本地"]
        self.assertLessEqual(len(local), 3)

    def test_deleted_file_can_be_recovered(self) -> None:
        """误删保险箱文件后，可以从备份目录恢复出来。"""
        self.vault.add_entry(Entry(title="重要", password="p"))
        self.vault.save()
        manager = self.vault.backup_manager()
        manager.backup(force=True)          # 让备份里确实含有这条数据
        self.path.unlink()

        backups = manager.list()
        self.assertTrue(backups, "应该有可用的备份")
        manager.restore(backups[0].path)

        self.assertTrue(self.path.exists())
        reopened = Vault.open(self.path, "Master#2024")
        self.assertEqual(reopened.active_entries()[0].title, "重要")

    def test_modified_file_is_detected(self) -> None:
        """文件被改动后必须解密失败，绝不能静默读出错误数据。"""
        self.vault.add_entry(Entry(title="A", password="p"))
        self.vault.save()

        raw = json.loads(self.path.read_text(encoding="utf-8"))
        payload = bytearray(raw["payload"].encode())
        payload[10] = ord("A") if payload[10] != ord("A") else ord("B")
        raw["payload"] = payload.decode()
        self.path.write_text(json.dumps(raw), encoding="utf-8")

        with self.assertRaises(crypto.VaultError):
            Vault.open(self.path, "Master#2024")
        # 此时仍能从备份把数据找回来
        backups = self.vault.backup_manager().list()
        self.assertTrue(backups)

    def test_restore_rolls_data_back(self) -> None:
        self.vault.add_entry(Entry(title="保留", password="p"))
        self.vault.save()
        manager = self.vault.backup_manager()
        manager.backup(force=True)                  # 备份一份含"保留"的版本
        snapshot = manager.latest()
        self.assertIsNotNone(snapshot)

        self.vault.add_entry(Entry(title="后来加的", password="p"))
        self.vault.save()

        self.vault.restore_backup(snapshot.path)
        titles = [e.title for e in self.vault.active_entries()]
        self.assertIn("保留", titles)
        self.assertNotIn("后来加的", titles)
        # 磁盘上的文件也确实回去了
        reopened = Vault.open(self.path, "Master#2024")
        self.assertEqual([e.title for e in reopened.active_entries()], ["保留"])

    def test_failed_write_verification_rolls_back(self) -> None:
        """写入后校验不通过时，应自动回滚到上一个可用版本。"""
        self.vault.add_entry(Entry(title="第一版", password="p"))
        self.vault.save()
        self.vault.add_entry(Entry(title="第二版", password="p"))

        original = Vault.verify_file
        calls = {"count": 0}

        def flaky(inner_self, path=None):
            calls["count"] += 1
            if calls["count"] == 1:
                raise ValueError("模拟磁盘写入异常")
            return original(inner_self, path)

        Vault.verify_file = flaky
        try:
            with self.assertRaises(crypto.VaultError):
                self.vault.save()
        finally:
            Vault.verify_file = original

        reopened = Vault.open(self.path, "Master#2024")
        self.assertEqual([e.title for e in reopened.active_entries()], ["第一版"])

    def test_rollback_works_without_auto_backup(self) -> None:
        """回归用例：关掉自动备份时，校验失败也必须能回到上一版。

        回滚靠的是"覆盖前另存的那一份"，而不是历史备份——否则用户一关
        自动备份就失去了这条保命机制。
        """
        self.vault.settings.auto_backup = False
        self.vault.add_entry(Entry(title="第一版", password="p"))
        self.vault.save()
        self.vault.add_entry(Entry(title="第二版", password="p"))

        original = Vault.verify_file
        calls = {"count": 0}

        def flaky(inner_self, path=None):
            calls["count"] += 1
            if calls["count"] == 1:
                raise ValueError("模拟磁盘写入异常")
            return original(inner_self, path)

        Vault.verify_file = flaky
        try:
            with self.assertRaises(crypto.VaultError):
                self.vault.save()
        finally:
            Vault.verify_file = original

        reopened = Vault.open(self.path, "Master#2024")
        self.assertEqual([e.title for e in reopened.active_entries()], ["第一版"])

    def test_temp_files_use_unique_names(self) -> None:
        """临时文件必须一次一名。

        固定名（vault.psvault.tmp）会让两个进程同时保存时往同一个文件里写，
        互相踩坏内容——os.replace 的原子性挡不住这种覆盖。
        """
        names = set()
        for _ in range(6):
            path = self.vault._unique_sibling(".tmp")
            names.add(path.name)
            path.unlink()
        self.assertEqual(len(names), 6)

    def test_save_leaves_no_leftover_files(self) -> None:
        self.vault.add_entry(Entry(title="A", password="p"))
        self.vault.save()
        leftovers = sorted(p.name for p in self.path.parent.glob(f"{self.path.name}.*"))
        self.assertEqual(leftovers, [], f"保存后不该留下临时文件：{leftovers}")

    def test_verify_failure_leaves_no_leftover_files(self) -> None:
        self.vault.add_entry(Entry(title="A", password="p"))
        self.vault.save()
        self.vault.add_entry(Entry(title="B", password="p"))

        original = Vault.verify_file
        calls = {"count": 0}

        def flaky(inner_self, path=None):
            calls["count"] += 1
            if calls["count"] == 1:
                raise ValueError("模拟写入异常")
            return original(inner_self, path)

        Vault.verify_file = flaky
        try:
            with self.assertRaises(crypto.VaultError):
                self.vault.save()
        finally:
            Vault.verify_file = original

        leftovers = sorted(p.name for p in self.path.parent.glob(f"{self.path.name}.*"))
        self.assertEqual(leftovers, [], f"回滚后不该留下临时文件：{leftovers}")

    def test_cleanup_removes_only_stale_temp_files(self) -> None:
        """崩溃残留的临时文件会被清掉，但刚写出来的不动（可能正被别的进程用）。"""
        fresh = self.vault._unique_sibling(".tmp")
        stale = self.vault._unique_sibling(".tmp")
        old_time = time.time() - 48 * 3600
        os.utime(stale, (old_time, old_time))

        removed = self.vault.cleanup_temp_files(older_than_hours=24)
        self.assertEqual(removed, 1)
        self.assertTrue(fresh.exists(), "新鲜的临时文件不该被删")
        self.assertFalse(stale.exists())
        fresh.unlink()

    def test_concurrent_saves_keep_file_intact(self) -> None:
        """两个已解锁实例并发保存：文件必须始终可解密（数据归属由锁去管）。

        注意这条只保证"不损坏"。"后写覆盖先写"要靠 main.py 的独占锁避免，
        单元测试里无法验证跨进程锁。
        """
        import threading

        self.vault.add_entry(Entry(title="初始", password="p"))
        self.vault.save()

        other = Vault.open(self.path, "Master#2024")
        other.settings.backup_external_dir = self.vault.settings.backup_external_dir
        errors: list[Exception] = []

        def writer(vault, tag: str) -> None:
            for index in range(6):
                vault.update_entry(vault.entries[0].id, {"notes": f"{tag}{index}"})
                try:
                    vault.save()
                except Exception as exc:      # noqa: BLE001 - 记录下来供断言
                    errors.append(exc)

        threads = [threading.Thread(target=writer, args=(self.vault, "A")),
                   threading.Thread(target=writer, args=(other, "B"))]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        # Windows 下并发写同一文件会因占用被直接拒绝，这是可接受的失败方式；
        # 不可接受的是文件损坏。真正的"后写覆盖先写"由 main.py 的独占锁避免。
        for exc in errors:
            self.assertIsInstance(exc, (OSError, crypto.VaultError),
                                  f"并发失败应当是 IO 层面或受控错误：{exc!r}")
        reopened = Vault.open(self.path, "Master#2024")
        self.assertEqual(len(reopened.active_entries()), 1)

    def test_rollback_point_is_cleaned_up(self) -> None:
        """回滚点是临时文件，正常保存后不该留在数据目录里。"""
        self.vault.add_entry(Entry(title="A", password="p"))
        self.vault.save()
        rollback = self.path.with_name(self.path.name + ".rollback")
        self.assertFalse(rollback.exists())

    def test_default_external_dir_uses_documents(self) -> None:
        from psvault.core.backup import default_external_dir

        target = default_external_dir()
        self.assertIn("密码保险箱备份", str(target))


class IgnoreIssueTest(unittest.TestCase):
    """忽略风险提示：精确到问题类型，且随时可以恢复。"""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "v.psvault"
        self.vault = Vault.create(self.path, "Master#2024")
        self.vault.settings.backup_external_dir = str(Path(self.tmp.name) / "ext")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _risk_ids(self) -> set[str]:
        return {e.id for e in strength.risk_entries(self.vault.active_entries())}

    def test_ignore_removes_from_risk_list(self) -> None:
        entry = self.vault.add_entry(Entry(title="弱", password="123456"))
        self.assertIn(entry.id, self._risk_ids())
        self.assertTrue(self.vault.ignore_issue(entry.id, "weak"))
        self.assertNotIn(entry.id, self._risk_ids())

    def test_ignored_issue_is_flagged_but_severity_kept(self) -> None:
        entry = self.vault.add_entry(Entry(title="弱", password="123456"))
        self.vault.ignore_issue(entry.id, "weak")
        issues = strength.entry_issues(entry, self.vault.active_entries())
        weak = next(i for i in issues if i.kind == "weak")
        self.assertTrue(weak.ignored)
        self.assertFalse(weak.is_risk)          # 不再计入风险
        self.assertTrue(weak.severity_risk)     # 但严重程度本身没被改写

    def test_ignore_is_per_kind(self) -> None:
        """忽略"弱密码"不该顺手把"重复使用"也屏蔽掉。"""
        first = self.vault.add_entry(Entry(title="甲", password="123456"))
        self.vault.add_entry(Entry(title="乙", password="123456"))
        self.vault.ignore_issue(first.id, "weak")

        issues = strength.entry_issues(first, self.vault.active_entries())
        weak = next(i for i in issues if i.kind == "weak")
        reused = next(i for i in issues if i.kind == "reused")
        self.assertTrue(weak.ignored)
        self.assertFalse(reused.ignored)
        self.assertIn(first.id, self._risk_ids())

    def test_restore_brings_it_back(self) -> None:
        entry = self.vault.add_entry(Entry(title="弱", password="123456"))
        self.vault.ignore_issue(entry.id, "weak")
        self.assertTrue(self.vault.unignore_issue(entry.id, "weak"))
        self.assertFalse(self.vault.unignore_issue(entry.id, "weak"))   # 重复恢复
        self.assertIn(entry.id, self._risk_ids())

    def test_ignore_survives_save_and_reopen(self) -> None:
        entry = self.vault.add_entry(Entry(title="弱", password="123456"))
        self.vault.ignore_issue(entry.id, "weak")
        self.vault.save()
        reopened = Vault.open(self.path, "Master#2024")
        self.assertEqual(reopened.find(entry.id).ignored_issues, ["weak"])
        self.assertNotIn(entry.id, {e.id for e in strength.risk_entries(
            reopened.active_entries())})

    def test_unignore_all(self) -> None:
        first = self.vault.add_entry(Entry(title="甲", password="123456"))
        second = self.vault.add_entry(Entry(title="乙", password=""))
        self.vault.ignore_issue(first.id, "weak")
        self.vault.ignore_issue(second.id, "empty")
        self.assertEqual(self.vault.unignore_all(), 2)
        self.assertEqual(self.vault.unignore_all(), 0)

    def test_ignored_list_feeds_restore_ui(self) -> None:
        entry = self.vault.add_entry(Entry(title="弱", password="123456"))
        self.vault.ignore_issue(entry.id, "weak")
        items = strength.ignored_issues(self.vault.active_entries())
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0][0].id, entry.id)
        self.assertEqual(items[0][1].kind, "weak")

    def test_audit_excludes_ignored(self) -> None:
        entry = self.vault.add_entry(Entry(title="弱", password="123456"))
        self.assertTrue(strength.audit(self.vault.active_entries())["weak"])
        self.vault.ignore_issue(entry.id, "weak")
        self.assertEqual(strength.audit(self.vault.active_entries())["weak"], [])

    def test_ignoring_one_of_two_duplicates_keeps_the_other_flagged(self) -> None:
        """只忽略其中一条的重复提示，另一条仍应被提醒。"""
        first = self.vault.add_entry(Entry(title="甲", password="same-pass-1234"))
        second = self.vault.add_entry(Entry(title="乙", password="same-pass-1234"))
        self.vault.ignore_issue(first.id, "reused")
        ids = self._risk_ids()
        self.assertNotIn(first.id, ids)
        self.assertIn(second.id, ids)

    def test_legacy_entry_without_ignore_field(self) -> None:
        entry = Entry.from_dict({"title": "旧记录", "password": "p"})
        self.assertEqual(entry.ignored_issues, [])
        self.assertFalse(entry.is_issue_ignored("weak"))


class BackupManagerUnitTest(unittest.TestCase):
    """备份管理器的独立行为。"""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_missing_vault_returns_empty(self) -> None:
        manager = BackupManager(self.dir / "不存在.psvault")
        self.assertEqual(manager.backup(), [])
        self.assertEqual(manager.list(), [])
        self.assertIsNone(manager.latest())

    def test_restore_missing_backup_raises(self) -> None:
        manager = BackupManager(self.dir / "v.psvault")
        with self.assertRaises(FileNotFoundError):
            manager.restore(self.dir / "没有这个文件.psvault")


class SourceHygieneTest(unittest.TestCase):
    """源码卫生检查：防止重构时留下永远不会执行的代码。

    这类问题的典型成因是把新函数插进了旧函数中间——后面的语句就被
    "吞"进了新函数、落在 return 之后，既不报错也不执行。
    """

    TERMINATORS = ("Return", "Raise", "Break", "Continue")

    def test_no_statement_after_terminator(self) -> None:
        import ast

        root = Path(__file__).resolve().parent.parent / "psvault"
        offenders: list[str] = []
        for path in sorted(root.rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                for _field, value in ast.iter_fields(node):
                    if not isinstance(value, list) or not value:
                        continue
                    if not all(isinstance(item, ast.stmt) for item in value):
                        continue
                    for index, stmt in enumerate(value[:-1]):
                        if type(stmt).__name__ in self.TERMINATORS:
                            dead = value[index + 1]
                            offenders.append(
                                f"{path.relative_to(root.parent)}:{stmt.lineno} "
                                f"（第 {dead.lineno} 行起永远不会执行）")
                            break
        self.assertEqual(offenders, [], "发现死代码：" + "；".join(offenders))


class SettingsTest(unittest.TestCase):
    """设置项容错。"""

    def test_roundtrip(self) -> None:
        settings = Settings(auto_lock_minutes=10, clipboard_clear_seconds=0, theme="dark")
        restored = Settings.from_dict(settings.to_dict())
        self.assertEqual(restored.auto_lock_minutes, 10)
        self.assertEqual(restored.theme, "dark")
        self.assertEqual(restored.clipboard_clear_seconds, 0)

    def test_invalid_theme(self) -> None:
        self.assertEqual(Settings.from_dict({"theme": "霓虹"}).theme, "light")

    def test_sort_key_is_validated(self) -> None:
        self.assertEqual(Settings().sort_key, "title")
        self.assertEqual(Settings.from_dict({"sort_key": "created"}).sort_key, "created")
        self.assertEqual(Settings.from_dict({"sort_key": "乱写的"}).sort_key, "title")

    def test_rekey_purge_flag_roundtrip(self) -> None:
        settings = Settings(rekey_purges_old_backups=False)
        restored = Settings.from_dict(settings.to_dict())
        self.assertFalse(restored.rekey_purges_old_backups)


if __name__ == "__main__":
    unittest.main(verbosity=2)
