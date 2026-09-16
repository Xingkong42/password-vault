"""核心逻辑单元测试：密码学、存储、生成器、强度评估、TOTP、导入导出。

运行：python -m unittest discover -s tests -v
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from psvault.core import crypto, generator, porting, storage, strength, totp  # noqa: E402
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

    def tearDown(self) -> None:
        self.tmp.cleanup()

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
        self.assertEqual(len(result["reused"]), 1)
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
