"""保险箱的自动备份与恢复。

为什么需要它
------------
保险箱文件虽然被强加密保护（改一个字节就打不开），但这也意味着
**一次误删或一次损坏就等于数据全丢**。因此：

* 每次**保存成功之后**，把新内容按时间戳留一份备份（由 Vault.save 触发）。
  注意备份的是"刚存好的这一版"——早先备份的是被覆盖的旧版本，结果
  备份里永远缺最新状态，误删后恢复只能拿到上一版；
* 除了程序目录内的 backups/，再往用户「文档」目录写一份——
  整个程序文件夹被删掉时外部备份仍然在；
* 备份文件是密文的原样副本，拷到哪都安全；
* 数量超过上限时自动清理最旧的，不会无限增长。
"""

from __future__ import annotations

import hashlib
import re
import shutil
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

# 外部备份目录名（放在用户文档目录下）
APP_BACKUP_FOLDER = "密码保险箱备份"
# 程序目录内的备份子目录
LOCAL_BACKUP_FOLDER = "backups"
TIMESTAMP_FORMAT = "%Y%m%d-%H%M%S"


def _recency_key(info: BackupInfo) -> tuple[int, str, int]:
    """排序键：优先按文件名里的时间戳，而不是文件的修改时间。

    同一秒内可能产生多份备份（文件名带 -1/-2 后缀），它们的 mtime 完全相同，
    按 mtime 排序结果不稳定——用户按"最新"选，可能正好选中那份空库。
    文件名里的时间戳＋序号才是可靠顺序。
    """
    match = re.search(r"-(\d{8})-(\d{6})(?:-(\d+))?$", info.path.stem)
    if match:
        date, clock, sequence = match.groups()
        return (1, f"{date}{clock}", int(sequence or 0))
    return (0, "", 0)                   # 认不出命名规则的（手动放进来的）排在最后


def default_external_dir() -> Path:
    """默认的外部备份目录：用户文档目录下的「密码保险箱备份」。"""
    home = Path.home()
    for name in ("Documents", "文档", "My Documents"):
        candidate = home / name
        if candidate.is_dir():
            return candidate / APP_BACKUP_FOLDER
    return home / APP_BACKUP_FOLDER


def file_digest(path: Path) -> str:
    """计算文件内容的 SHA-256（备份去重靠它）。"""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(64 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass(frozen=True)
class BackupInfo:
    """一份备份的描述。"""

    path: Path
    created_at: datetime
    size: int
    location: str        # 本地 / 外部
    digest: str = ""

    def display_time(self) -> str:
        return self.created_at.strftime("%Y-%m-%d %H:%M:%S")

    def display_size(self) -> str:
        kb = self.size / 1024
        return f"{kb:.1f} KB" if kb < 1024 else f"{kb / 1024:.1f} MB"


class BackupManager:
    """管理某个保险箱文件的备份目录。"""

    def __init__(self, vault_path: str | Path, *, keep: int = 10,
                 external_dir: str | Path | None = None) -> None:
        self.vault_path = Path(vault_path)
        self.keep = max(1, int(keep))
        self.external_dir = Path(external_dir) if external_dir else None

    # ------------------------------------------------------------ 目录

    @property
    def local_dir(self) -> Path:
        """本地备份目录：与保险箱文件同级的 backups/。"""
        return self.vault_path.parent / LOCAL_BACKUP_FOLDER

    def directories(self) -> list[tuple[str, Path]]:
        """返回 (位置名称, 目录) 列表。"""
        result = [("本地", self.local_dir)]
        if self.external_dir is not None:
            result.append(("外部", self.external_dir))
        return result

    def _pattern(self) -> str:
        return f"{self.vault_path.stem}-*{self.vault_path.suffix}"

    # ------------------------------------------------------------ 备份

    def backup(self, *, force: bool = False) -> list[Path]:
        """把当前保险箱文件备份到所有备份目录。

        返回实际写出的备份路径；内容与最新备份相同（且未强制）时返回空列表。
        """
        if not self.vault_path.exists():
            return []

        try:
            digest = file_digest(self.vault_path)
        except OSError:
            return []

        latest = self.latest()
        if not force and latest is not None and latest.digest == digest:
            return []                       # 内容没有变化，不必重复备份

        stamp = datetime.now().strftime(TIMESTAMP_FORMAT)
        written: list[Path] = []
        for _location, directory in self.directories():
            try:
                directory.mkdir(parents=True, exist_ok=True)
                target = directory / f"{self.vault_path.stem}-{stamp}{self.vault_path.suffix}"
                counter = 1
                while target.exists():      # 同一秒内的多次备份
                    target = directory / (
                        f"{self.vault_path.stem}-{stamp}-{counter}{self.vault_path.suffix}")
                    counter += 1
                shutil.copy2(self.vault_path, target)
                written.append(target)
            except OSError:
                continue                    # 某个位置失败不影响其他位置

        if written:
            self.prune()
        return written

    # ------------------------------------------------------------ 查询

    def list(self) -> list[BackupInfo]:
        """列出全部备份，最新的排在前面。"""
        items: list[BackupInfo] = []
        for location, directory in self.directories():
            if not directory.is_dir():
                continue
            for path in directory.glob(self._pattern()):
                if not path.is_file():
                    continue
                try:
                    stat = path.stat()
                except OSError:
                    continue
                items.append(BackupInfo(
                    path=path,
                    created_at=datetime.fromtimestamp(stat.st_mtime),
                    size=stat.st_size,
                    location=location,
                    digest="",             # 按需计算，避免列表时读所有文件
                ))
        items.sort(key=_recency_key, reverse=True)
        return items

    def latest(self) -> BackupInfo | None:
        """最新的一份备份（会补算内容摘要，用于去重比较）。"""
        items = self.list()
        if not items:
            return None
        newest = items[0]
        try:
            digest = file_digest(newest.path)
        except OSError:
            return None
        return BackupInfo(path=newest.path, created_at=newest.created_at,
                          size=newest.size, location=newest.location, digest=digest)

    def total_size(self) -> int:
        return sum(info.size for info in self.list())

    # ------------------------------------------------------------ 清理与恢复

    def prune(self) -> int:
        """每个备份目录各保留最新的 keep 份，返回删除数量。"""
        removed = 0
        for _location, directory in self.directories():
            if not directory.is_dir():
                continue
            files = sorted(
                (p for p in directory.glob(self._pattern()) if p.is_file()),
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            )
            for path in files[self.keep:]:
                try:
                    path.unlink()
                    removed += 1
                except OSError:
                    continue
        return removed

    def restore(self, backup_path: str | Path) -> Path:
        """用指定备份覆盖当前保险箱文件。

        恢复前会先把当前文件另存一份，避免"恢复错了就再也回不去"。
        """
        source = Path(backup_path)
        if not source.is_file():
            raise FileNotFoundError(f"找不到备份文件：{source}")

        if self.vault_path.exists():
            try:
                stamp = datetime.now().strftime(TIMESTAMP_FORMAT)
                safety = self.local_dir / (
                    f"{self.vault_path.stem}-恢复前-{stamp}{self.vault_path.suffix}")
                self.local_dir.mkdir(parents=True, exist_ok=True)
                shutil.copy2(self.vault_path, safety)
            except OSError:
                pass                        # 保险动作失败不阻断恢复

        self.vault_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, self.vault_path)
        return self.vault_path
