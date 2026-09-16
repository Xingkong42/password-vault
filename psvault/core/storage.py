"""保险箱存储层：负责加密文件的读写、条目增删改查与回收站管理。

对外只有一个 `Vault` 类：
    vault = Vault.create(path, "主密码")     # 新建
    vault = Vault.open(path, "主密码")       # 打开（主密码错误会抛 InvalidPassword）
    vault.add_entry(...); vault.save()       # 修改后保存
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import uuid
from pathlib import Path
from typing import Any, Iterable

from . import crypto
from .models import DEFAULT_CATEGORY, Entry, Settings, now_iso


def application_root() -> Path:
    """程序根目录。

    源码运行时是项目目录；PyInstaller 打包后是 exe 所在目录——这样数据文件
    始终和程序放在一起，用户看得见、方便备份，也不会写进只读的安装目录。
    """
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent.parent


# 默认数据文件位置：程序目录下的 data/vault.psvault
DEFAULT_DATA_DIR = application_root() / "data"
DEFAULT_VAULT_NAME = "vault.psvault"

# 新建保险箱时自带的分类（"未分类"不可删除）
DEFAULT_CATEGORIES = ["未分类", "密钥", "邮箱", "社交", "金融", "开发", "购物"]

# 数据格式版本：老文件打开时会按需补齐新增的默认分类
SCHEMA_VERSION = 2


def default_vault_path() -> Path:
    """返回默认保险箱文件路径。"""
    return DEFAULT_DATA_DIR / DEFAULT_VAULT_NAME


def sanitize_filename(name: str) -> str:
    """把保险箱名称转成安全的文件名（去掉 Windows 不允许的字符）。"""
    cleaned = "".join(ch for ch in name.strip() if ch not in '\\/:*?"<>|')
    cleaned = cleaned.strip(" .")
    return cleaned or "vault"


class Vault:
    """一个已解锁的保险箱实例。锁定后应丢弃该对象。"""

    def __init__(
        self,
        path: Path,
        key: bytes,
        kdf: dict[str, Any],
        entries: list[Entry],
        categories: list[str],
        settings: Settings,
        meta: dict[str, Any] | None = None,
    ) -> None:
        self.path = Path(path)
        self._key = key
        self._kdf = kdf
        self.entries = entries
        self.categories = categories
        self.settings = settings
        self.meta = meta or {}
        self.dirty = False

    # ------------------------------------------------------------ 生命周期

    @classmethod
    def create(
        cls,
        path: str | Path,
        password: str,
        *,
        settings: Settings | None = None,
        name: str = "",
    ) -> Vault:
        """新建一个空保险箱并立即落盘。name 为保险箱名称（可选）。"""
        salt = crypto.new_salt()
        kdf = crypto.kdf_parameters(salt)
        key = crypto.derive_key(password, salt)
        vault = cls(
            path=Path(path),
            key=key,
            kdf=kdf,
            entries=[],
            categories=list(DEFAULT_CATEGORIES),
            settings=settings or Settings(),
            meta={
                "created_at": now_iso(),
                "schema_version": SCHEMA_VERSION,
                "name": name.strip(),
            },
        )
        vault.save()
        return vault

    @classmethod
    def open(cls, path: str | Path, password: str) -> Vault:
        """打开已有保险箱；主密码错误时抛 crypto.InvalidPassword。"""
        path = Path(path)
        if not path.exists():
            raise crypto.CorruptedVault(f"找不到保险箱文件：{path}")
        try:
            container = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise crypto.CorruptedVault("保险箱文件不是合法 JSON，可能已损坏") from exc

        container = crypto.validate_container(container)
        key = crypto.key_from_container(container, password)
        plaintext = crypto.decrypt_payload(container, key)
        try:
            payload = json.loads(plaintext.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise crypto.CorruptedVault("解密后的数据无法解析") from exc

        entries = [Entry.from_dict(item) for item in payload.get("entries", [])]
        categories = [str(c) for c in payload.get("categories", [])] or [DEFAULT_CATEGORY]
        if DEFAULT_CATEGORY not in categories:
            categories.insert(0, DEFAULT_CATEGORY)
        settings = Settings.from_dict(payload.get("settings", {}))
        meta = payload.get("meta", {}) or {}

        vault = cls(
            path=path,
            key=key,
            kdf=container["kdf"],
            entries=entries,
            categories=categories,
            settings=settings,
            meta=meta,
        )
        vault._migrate()
        return vault

    def _migrate(self) -> None:
        """老版本数据升级：补齐新增的默认分类，并标记格式版本。"""
        try:
            version = int(self.meta.get("schema_version", 1) or 1)
        except (TypeError, ValueError):
            version = 1
        if version >= SCHEMA_VERSION:
            return
        for category in DEFAULT_CATEGORIES:
            if category not in self.categories:
                self.categories.append(category)
        self.meta["schema_version"] = SCHEMA_VERSION
        self.dirty = True      # 由调用方在合适的时机落盘

    def lock(self) -> None:
        """清除内存中的密钥与数据引用。"""
        self._key = b""
        self.entries = []

    @property
    def is_locked(self) -> bool:
        """密钥是否已被清除。"""
        return not self._key

    # ------------------------------------------------------------ 名称

    @property
    def name(self) -> str:
        """保险箱名称；未命名时退回文件名，保证界面总有东西可显示。"""
        stored = str(self.meta.get("name") or "").strip()
        return stored or self.path.stem

    def set_name(self, name: str) -> None:
        """设置保险箱名称（空字符串表示恢复为文件名）。"""
        self.meta["name"] = name.strip()
        self.dirty = True

    # ------------------------------------------------------------ 持久化

    def to_payload(self) -> dict[str, Any]:
        """组装明文数据负载。"""
        return {
            "entries": [entry.to_dict() for entry in self.entries],
            "categories": list(self.categories),
            "settings": self.settings.to_dict(),
            "meta": {**self.meta, "updated_at": now_iso()},
        }

    def save(self) -> None:
        """加密并原子写入磁盘（同时保留一份 .bak 备份）。"""
        if self.is_locked:
            raise crypto.VaultError("保险箱已锁定，无法保存")
        plaintext = json.dumps(self.to_payload(), ensure_ascii=False).encode("utf-8")
        container = crypto.encrypt_payload(plaintext, self._key, self._kdf)

        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = self.path.with_name(self.path.name + ".tmp")
        data = json.dumps(container, ensure_ascii=False, indent=2)
        tmp_path.write_text(data, encoding="utf-8")

        # 覆盖前留一份备份，避免写入过程被打断导致数据全失
        if self.path.exists():
            backup = self.path.with_name(self.path.name + ".bak")
            try:
                shutil.copy2(self.path, backup)
            except OSError:
                pass
        os.replace(tmp_path, self.path)
        self.dirty = False

    def change_master_password(self, new_password: str) -> None:
        """更换主密码：换盐、重新派生密钥并落盘。"""
        salt = crypto.new_salt()
        self._kdf = crypto.kdf_parameters(salt)
        self._key = crypto.derive_key(new_password, salt)
        self.meta["password_changed_at"] = now_iso()
        self.save()

    def export_encrypted(self, target: str | Path, password: str | None = None) -> None:
        """导出加密备份。password 为 None 时沿用当前主密钥。"""
        target = Path(target)
        if password is None:
            container = crypto.encrypt_payload(
                json.dumps(self.to_payload(), ensure_ascii=False).encode("utf-8"),
                self._key,
                self._kdf,
            )
        else:
            salt = crypto.new_salt()
            kdf = crypto.kdf_parameters(salt)
            key = crypto.derive_key(password, salt)
            container = crypto.encrypt_payload(
                json.dumps(self.to_payload(), ensure_ascii=False).encode("utf-8"),
                key,
                kdf,
            )
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(container, ensure_ascii=False, indent=2), encoding="utf-8")

    # ------------------------------------------------------------ 条目操作

    def find(self, entry_id: str) -> Entry | None:
        """按 id 查找条目。"""
        return next((e for e in self.entries if e.id == entry_id), None)

    def active_entries(self) -> list[Entry]:
        """回收站之外的条目。"""
        return [e for e in self.entries if not e.is_deleted]

    def trashed_entries(self) -> list[Entry]:
        """回收站中的条目。"""
        return [e for e in self.entries if e.is_deleted]

    def add_entry(self, entry: Entry) -> Entry:
        """新增条目并标记为待保存。"""
        if not entry.title:
            entry.title = "未命名"
        if entry.category not in self.categories:
            self.categories.append(entry.category)
        self.entries.append(entry)
        self.dirty = True
        return entry

    def update_entry(self, entry_id: str, data: dict[str, Any], *, new_password: str | None = None) -> Entry | None:
        """用字典更新条目字段；传入 new_password 时会写入密码历史。"""
        entry = self.find(entry_id)
        if entry is None:
            return None
        for field_name in ("title", "username", "phone", "email", "url", "notes",
                           "category", "totp_secret"):
            if field_name in data:
                setattr(entry, field_name, str(data[field_name]))
        if "tags" in data:
            entry.tags = [str(t) for t in data["tags"] if str(t).strip()]
        if "favorite" in data:
            entry.favorite = bool(data["favorite"])
        if new_password is not None:
            entry.apply_password(new_password)
        elif "password" in data:
            entry.password = str(data["password"])
        entry.touch()
        if entry.category and entry.category not in self.categories:
            self.categories.append(entry.category)
        self.dirty = True
        return entry

    def trash_entry(self, entry_id: str) -> bool:
        """把条目移入回收站（软删除）。"""
        entry = self.find(entry_id)
        if entry is None:
            return False
        entry.deleted_at = now_iso()
        self.dirty = True
        return True

    def restore_entry(self, entry_id: str) -> bool:
        """从回收站恢复。"""
        entry = self.find(entry_id)
        if entry is None:
            return False
        entry.deleted_at = ""
        entry.touch()
        self.dirty = True
        return True

    def purge_entry(self, entry_id: str) -> bool:
        """彻底删除条目。"""
        before = len(self.entries)
        self.entries = [e for e in self.entries if e.id != entry_id]
        changed = len(self.entries) != before
        self.dirty = self.dirty or changed
        return changed

    def empty_trash(self) -> int:
        """清空回收站，返回删除条数。"""
        count = len(self.trashed_entries())
        self.entries = self.active_entries()
        self.dirty = self.dirty or count > 0
        return count

    def toggle_favorite(self, entry_id: str) -> bool:
        """切换收藏状态。"""
        entry = self.find(entry_id)
        if entry is None:
            return False
        entry.favorite = not entry.favorite
        self.dirty = True
        return entry.favorite

    # ------------------------------------------------------------ 分类与标签

    def add_category(self, name: str) -> bool:
        """新增分类（去重、去空）。"""
        name = name.strip()
        if not name or name in self.categories:
            return False
        self.categories.append(name)
        self.dirty = True
        return True

    def rename_category(self, old: str, new: str) -> bool:
        """重命名分类，并同步更新条目。"""
        new = new.strip()
        if not new or new == old or old not in self.categories:
            return False
        if new in self.categories:
            return False
        index = self.categories.index(old)
        self.categories[index] = new
        for entry in self.entries:
            if entry.category == old:
                entry.category = new
        self.dirty = True
        return True

    def remove_category(self, name: str) -> bool:
        """删除分类，其下条目归入"未分类"。"""
        if name == DEFAULT_CATEGORY or name not in self.categories:
            return False
        self.categories.remove(name)
        for entry in self.entries:
            if entry.category == name:
                entry.category = DEFAULT_CATEGORY
        self.dirty = True
        return True

    def category_counts(self) -> dict[str, int]:
        """统计各分类下的有效条目数。"""
        counts = {name: 0 for name in self.categories}
        for entry in self.active_entries():
            counts[entry.category] = counts.get(entry.category, 0) + 1
        return counts

    def all_tags(self) -> list[str]:
        """收集全部标签并统计出现次数（按次数降序）。"""
        counter: dict[str, int] = {}
        for entry in self.active_entries():
            for tag in entry.tags:
                counter[tag] = counter.get(tag, 0) + 1
        return sorted(counter, key=lambda t: (-counter[t], t))

    # ------------------------------------------------------------ 批量导入

    def import_entries(self, entries: Iterable[Entry], *, replace: bool = False) -> int:
        """批量导入条目，按标题+用户名判重。返回新增条数。"""
        if replace:
            self.entries = []
        existing = {(e.title.strip().lower(), e.username.strip().lower()) for e in self.entries}
        added = 0
        for entry in entries:
            key = (entry.title.strip().lower(), entry.username.strip().lower())
            if key in existing:
                continue
            if not entry.id or any(e.id == entry.id for e in self.entries):
                entry.id = uuid.uuid4().hex
            self.add_entry(entry)
            existing.add(key)
            added += 1
        return added

    # ------------------------------------------------------------ 统计

    def statistics(self) -> dict[str, int]:
        """返回界面顶部概览用的统计数字。"""
        active = self.active_entries()
        return {
            "total": len(active),
            "favorite": sum(1 for e in active if e.favorite),
            "trash": len(self.trashed_entries()),
            "categories": len(self.categories),
            "tags": len(self.all_tags()),
            "with_totp": sum(1 for e in active if e.totp_secret),
        }

    def backups(self) -> list[Path]:
        """列出同目录下的备份文件。"""
        return sorted(self.path.parent.glob(self.path.name + "*"))
