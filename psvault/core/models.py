"""数据模型：单条账号记录、密码历史、全局设置。

所有模型都能无损地转成 JSON 可序列化的字典，方便整体加密后落盘。
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

# 未分类的固定名称，界面上不可删除
DEFAULT_CATEGORY = "未分类"

# 密码历史保留条数上限
HISTORY_LIMIT = 10

# 记录列表可选的排序方式
SORT_KEYS = ("title", "updated", "created")
SORT_LABELS = {
    "title": "名称（收藏优先）",
    "updated": "最近修改",
    "created": "最近创建",
}


def now_iso() -> str:
    """当前本地时间的 ISO 字符串（精确到秒，带时区偏移）。"""
    return datetime.now().astimezone().isoformat(timespec="seconds")


def parse_iso(text: str) -> datetime | None:
    """宽松解析 ISO 时间字符串，失败返回 None。"""
    if not text:
        return None
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


@dataclass
class HistoryItem:
    """一条旧的密码记录，用于回溯改密历史。"""

    password: str = ""
    changed_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"password": self.password, "changed_at": self.changed_at}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> HistoryItem:
        return cls(
            password=str(data.get("password", "")),
            changed_at=str(data.get("changed_at", "")),
        )


@dataclass
class Entry:
    """一条账号密码记录。"""

    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    title: str = ""
    username: str = ""
    password: str = ""
    phone: str = ""          # 预留电话
    email: str = ""          # 预留邮箱
    url: str = ""
    notes: str = ""
    category: str = DEFAULT_CATEGORY
    tags: list[str] = field(default_factory=list)
    favorite: bool = False
    totp_secret: str = ""
    created_at: str = field(default_factory=now_iso)
    updated_at: str = field(default_factory=now_iso)
    password_changed_at: str = field(default_factory=now_iso)   # 上次更换密码的时间
    deleted_at: str = ""
    history: list[HistoryItem] = field(default_factory=list)
    # 用户在安全审计里主动忽略的问题类型（weak / reused / aged / empty / suggest）
    ignored_issues: list[str] = field(default_factory=list)

    # ------------------------------------------------------------ 行为方法

    @property
    def is_deleted(self) -> bool:
        """是否位于回收站。"""
        return bool(self.deleted_at)

    def is_issue_ignored(self, kind: str) -> bool:
        """该类问题是否已被忽略。"""
        return kind in self.ignored_issues

    def ignore_issue(self, kind: str) -> bool:
        """忽略某类问题，已忽略时返回 False。"""
        if not kind or kind in self.ignored_issues:
            return False
        self.ignored_issues.append(kind)
        return True

    def unignore_issue(self, kind: str) -> bool:
        """取消忽略，原本就没忽略时返回 False。"""
        if kind not in self.ignored_issues:
            return False
        self.ignored_issues.remove(kind)
        return True

    def touch(self) -> None:
        """刷新修改时间。"""
        self.updated_at = now_iso()

    def apply_password(self, new_password: str) -> None:
        """修改密码，并把旧密码压入历史。"""
        if new_password == self.password:
            return
        if self.password:
            self.history.insert(0, HistoryItem(password=self.password, changed_at=now_iso()))
            del self.history[HISTORY_LIMIT:]
        self.password = new_password
        self.password_changed_at = now_iso()     # 密码年龄从这一刻重新算
        self.touch()

    def subtitle(self) -> str:
        """列表中显示的副标题：优先用户名，其次网址、分类。"""
        for candidate in (self.username, self.url):
            if candidate:
                return candidate
        return self.category

    def domain(self) -> str:
        """从网址中提取域名，用于列表上的小字展示与图标取字母。"""
        raw = self.url.strip()
        if not raw:
            return ""
        raw = raw.split("//", 1)[-1]
        raw = raw.split("/", 1)[0]
        raw = raw.split("?", 1)[0]
        return raw.lower()

    def initial(self) -> str:
        """取标题首字符，用于生成圆形字母头像。"""
        for text in (self.title, self.domain(), self.username):
            if text:
                return text.strip()[0].upper()
        return "?"

    def search_blob(self) -> str:
        """拼接所有可搜索字段（小写），供关键字过滤使用。"""
        parts = [
            self.title,
            self.username,
            self.phone,
            self.email,
            self.url,
            self.notes,
            self.category,
            " ".join(self.tags),
        ]
        return " ".join(parts).lower()

    def matches(self, keyword: str) -> bool:
        """是否命中搜索关键字（空格分隔的多个关键字需全部命中）。"""
        if not keyword:
            return True
        blob = self.search_blob()
        return all(token in blob for token in keyword.lower().split())

    def age_days(self) -> int:
        """距离上次修改记录的天数（任何字段的修改都算）。"""
        moment = parse_iso(self.updated_at)
        if moment is None:
            return 0
        delta = datetime.now().astimezone() - moment
        return max(delta.days, 0)

    def password_age_days(self) -> int:
        """距离上次**更换密码**的天数。

        必须和 updated_at 区分开：改个备注、加个标签也会刷新 updated_at，
        若拿它当密码年龄，"长期未更换密码"就永远触发不了。
        老数据没有 password_changed_at 字段，退回 updated_at 以免全部误报。
        """
        moment = parse_iso(self.password_changed_at) or parse_iso(self.updated_at)
        if moment is None:
            return 0
        delta = datetime.now().astimezone() - moment
        return max(delta.days, 0)

    # ------------------------------------------------------------ 序列化

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "username": self.username,
            "password": self.password,
            "phone": self.phone,
            "email": self.email,
            "url": self.url,
            "notes": self.notes,
            "category": self.category or DEFAULT_CATEGORY,
            "tags": list(self.tags),
            "favorite": bool(self.favorite),
            "totp_secret": self.totp_secret,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "password_changed_at": self.password_changed_at,
            "deleted_at": self.deleted_at,
            "history": [item.to_dict() for item in self.history],
            "ignored_issues": list(self.ignored_issues),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Entry:
        """从字典还原；对缺字段、类型异常做容错处理。"""
        raw_tags = data.get("tags") or []
        if isinstance(raw_tags, str):
            raw_tags = [t.strip() for t in raw_tags.split(",") if t.strip()]
        raw_history = data.get("history") or []
        entry = cls(
            id=str(data.get("id") or uuid.uuid4().hex),
            title=str(data.get("title", "")),
            username=str(data.get("username", "")),
            password=str(data.get("password", "")),
            phone=str(data.get("phone", "")),
            email=str(data.get("email", "")),
            url=str(data.get("url", "")),
            notes=str(data.get("notes", "")),
            category=str(data.get("category") or DEFAULT_CATEGORY),
            tags=[str(t) for t in raw_tags if str(t).strip()],
            favorite=bool(data.get("favorite", False)),
            totp_secret=str(data.get("totp_secret", "")),
            created_at=str(data.get("created_at") or now_iso()),
            updated_at=str(data.get("updated_at") or now_iso()),
            # 老数据没有这个字段：用 updated_at 兜底，避免升级后所有记录突然"过期"
            password_changed_at=str(
                data.get("password_changed_at") or data.get("updated_at") or now_iso()),
            deleted_at=str(data.get("deleted_at", "")),
        )
        entry.history = [
            HistoryItem.from_dict(item) for item in raw_history if isinstance(item, dict)
        ]
        raw_ignored = data.get("ignored_issues") or []
        if isinstance(raw_ignored, str):
            raw_ignored = [raw_ignored]
        entry.ignored_issues = [str(k) for k in raw_ignored if str(k).strip()]
        return entry


@dataclass
class Settings:
    """可被加密保存的用户偏好。"""

    theme: str = "light"                 # light | dark
    auto_lock_minutes: int = 5           # 空闲自动锁定（分钟），0 表示不自动锁定
    clipboard_clear_seconds: int = 30    # 复制后清空剪贴板（秒），0 表示不清空
    lock_on_minimize: bool = False       # 窗口最小化时锁定
    history_limit: int = HISTORY_LIMIT   # 每条记录保留的密码历史条数
    password_max_age_days: int = 180     # 超过该天数未改密则列入审计提醒

    # 备份策略
    auto_backup: bool = True             # 每次保存前自动留一份历史版本
    backup_keep: int = 10                # 每个备份目录保留的份数
    backup_external_dir: str = ""        # 外部备份目录（空表示尚未确定）
    backup_external_enabled: bool = True # 是否在程序目录之外再存一份
    rekey_purges_old_backups: bool = True  # 改主密码后清理旧密码的备份

    # 记录列表的排序方式：title / updated / created
    sort_key: str = "title"

    def to_dict(self) -> dict[str, Any]:
        return {
            "theme": self.theme,
            "auto_lock_minutes": int(self.auto_lock_minutes),
            "clipboard_clear_seconds": int(self.clipboard_clear_seconds),
            "lock_on_minimize": bool(self.lock_on_minimize),
            "history_limit": int(self.history_limit),
            "password_max_age_days": int(self.password_max_age_days),
            "auto_backup": bool(self.auto_backup),
            "backup_keep": int(self.backup_keep),
            "backup_external_dir": self.backup_external_dir,
            "backup_external_enabled": bool(self.backup_external_enabled),
            "rekey_purges_old_backups": bool(self.rekey_purges_old_backups),
            "sort_key": self.sort_key,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Settings:
        base = cls()
        if not isinstance(data, dict):
            return base
        theme = str(data.get("theme", base.theme))
        return cls(
            theme=theme if theme in ("light", "dark") else base.theme,
            auto_lock_minutes=int(data.get("auto_lock_minutes", base.auto_lock_minutes)),
            clipboard_clear_seconds=int(
                data.get("clipboard_clear_seconds", base.clipboard_clear_seconds)
            ),
            lock_on_minimize=bool(data.get("lock_on_minimize", base.lock_on_minimize)),
            history_limit=int(data.get("history_limit", base.history_limit)),
            password_max_age_days=int(
                data.get("password_max_age_days", base.password_max_age_days)
            ),
            auto_backup=bool(data.get("auto_backup", base.auto_backup)),
            backup_keep=max(1, int(data.get("backup_keep", base.backup_keep))),
            backup_external_dir=str(data.get("backup_external_dir", "")),
            backup_external_enabled=bool(
                data.get("backup_external_enabled", base.backup_external_enabled)
            ),
            rekey_purges_old_backups=bool(
                data.get("rekey_purges_old_backups", base.rekey_purges_old_backups)
            ),
            sort_key=(str(data.get("sort_key", base.sort_key))
                      if str(data.get("sort_key", base.sort_key)) in SORT_KEYS
                      else base.sort_key),
        )
