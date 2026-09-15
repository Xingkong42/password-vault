"""数据迁移：CSV / JSON 的导入导出。

CSV 便于和其他密码管理器（Chrome、Bitwarden、LastPass 等）互通，
但它是明文的，界面上会明确给出风险提示。
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Iterable

from .models import DEFAULT_CATEGORY, Entry

# 导出时的列顺序
CSV_COLUMNS = ["title", "username", "password", "url", "category", "tags", "notes", "totp_secret"]

# 各方面可能出现的列名（含常见中文表头），全部小写匹配
COLUMN_ALIASES: dict[str, tuple[str, ...]] = {
    "title": ("title", "name", "account", "accountname", "item", "login_title",
              "标题", "名称", "条目", "条目名称", "账户", "账号名称"),
    "username": ("username", "user", "userid", "login", "loginname", "email",
                 "e-mail", "account_name", "用户名", "账号", "登录名", "邮箱"),
    "password": ("password", "pass", "pwd", "passwd", "密码", "口令"),
    "url": ("url", "uri", "website", "site", "web", "link", "loginurl",
            "网址", "网站", "链接"),
    "category": ("category", "folder", "group", "type", "分类", "文件夹", "分组"),
    "tags": ("tags", "tag", "标签"),
    "notes": ("notes", "note", "comment", "comments", "description", "memo",
              "备注", "说明", "注释"),
    "totp_secret": ("totp", "otp", "otpsecret", "totp_secret", "otpauth",
                    "twofactor", "2fa", "动态口令"),
}

# 反向索引：列名 -> 字段
_LOOKUP: dict[str, str] = {}
for _field, _names in COLUMN_ALIASES.items():
    for _name in _names:
        _LOOKUP[_name] = _field


def _match_column(header: str) -> str | None:
    """把 CSV 表头映射到内部字段名。"""
    key = header.strip().lower().replace(" ", "").replace("_", "").replace("-", "")
    if key in _LOOKUP:
        return _LOOKUP[key]
    for alias, field in _LOOKUP.items():
        alias_key = alias.replace(" ", "").replace("_", "").replace("-", "")
        if alias_key and alias_key == key:
            return field
    return None


def export_csv(entries: Iterable[Entry], path: str | Path) -> int:
    """把条目导出为 CSV（utf-8-sig，Excel 可直接打开）。返回写出的条数。"""
    path = Path(path)
    count = 0
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for entry in entries:
            writer.writerow({
                "title": entry.title,
                "username": entry.username,
                "password": entry.password,
                "url": entry.url,
                "category": entry.category,
                "tags": ",".join(entry.tags),
                "notes": entry.notes,
                "totp_secret": entry.totp_secret,
            })
            count += 1
    return count


def export_json(entries: Iterable[Entry], path: str | Path) -> int:
    """导出为明文 JSON（结构与本程序内部一致）。"""
    path = Path(path)
    data = {"format": "psvault-plain", "version": 1, "entries": [e.to_dict() for e in entries]}
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return len(data["entries"])


def import_csv(path: str | Path) -> list[Entry]:
    """从 CSV 导入条目，自动识别常见表头。"""
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError:
        text = path.read_text(encoding="gbk", errors="replace")

    rows = list(csv.reader(text.splitlines()))
    if not rows:
        return []

    header = rows[0]
    mapping: dict[int, str] = {}
    for index, cell in enumerate(header):
        field = _match_column(cell)
        if field and field not in mapping.values():
            mapping[index] = field
    start = 1
    if not mapping:
        # 没有可识别的表头时，按 Chrome 导出顺序兜底：name,url,username,password
        mapping = {0: "title", 1: "url", 2: "username", 3: "password"}
        if not any(_match_column(cell) for cell in header):
            start = 0

    entries: list[Entry] = []
    for row in rows[start:]:
        if not any(cell.strip() for cell in row):
            continue
        data: dict[str, Any] = {}
        for index, field in mapping.items():
            if index < len(row):
                data[field] = row[index].strip()
        title = data.get("title") or data.get("url") or data.get("username")
        if not title:
            continue
        tags = [t.strip() for t in (data.get("tags") or "").replace("；", ",").split(",") if t.strip()]
        entries.append(Entry(
            title=title,
            username=data.get("username", ""),
            password=data.get("password", ""),
            url=data.get("url", ""),
            notes=data.get("notes", ""),
            category=data.get("category") or DEFAULT_CATEGORY,
            tags=tags,
            totp_secret=data.get("totp_secret", ""),
        ))
    return entries


def import_json(path: str | Path) -> list[Entry]:
    """从 JSON 导入条目（兼容本程序导出格式与纯数组格式）。"""
    path = Path(path)
    raw = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(raw, dict):
        items = raw.get("entries", [])
    elif isinstance(raw, list):
        items = raw
    else:
        items = []
    return [Entry.from_dict(item) for item in items if isinstance(item, dict)]


def import_file(path: str | Path) -> list[Entry]:
    """按扩展名自动选择导入方式。"""
    path = Path(path)
    suffix = path.suffix.lower()
    if suffix == ".csv":
        return import_csv(path)
    if suffix in (".json", ".txt"):
        return import_json(path)
    raise ValueError(f"不支持的文件类型：{suffix or '（无扩展名）'}")
