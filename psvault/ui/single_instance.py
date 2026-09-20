"""保险箱的进程级独占锁。

为什么需要它
------------
`Vault.save()` 用"写临时文件 + 原子替换"保证**文件不会写坏**，但那只解决了
"写入中断"的问题。两个窗口各自读到旧数据、又各自写回时，后写的会**静默覆盖**
先写的那一份——数据就这么没了，而且谁都不会收到提示。

所以在这里加一把进程级的锁：同一份保险箱文件，同一时间只允许一个实例编辑。
用 Qt 的 QLockFile 实现：它在锁文件里记录 PID，持有者崩溃退出后能被识别为
陈旧锁并自动回收，不会把用户永久挡在门外。
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QLockFile

# tryLock 的等待时间（毫秒）：太长会让"另一个实例正开着"的提示来得太慢
LOCK_TIMEOUT_MS = 300


class VaultLock:
    """绑定到具体保险箱文件的独占锁。未持有时 acquire 返回 False。"""

    def __init__(self) -> None:
        self._lock: QLockFile | None = None

    @property
    def path(self) -> str | None:
        """当前持有的锁文件路径，未持有时为 None。"""
        return self._lock.fileName() if self._lock is not None else None

    def acquire(self, vault_path: str | Path) -> bool:
        """获取该保险箱的锁；切换到另一个保险箱时会先释放旧的。"""
        target = str(vault_path) + ".lock"
        if self._lock is not None and self._lock.fileName() == target:
            return True                     # 已经是自己持有的

        candidate = QLockFile(target)
        # 不按时间判定过期：交给 PID 检测，避免长时间挂着的窗口被误抢
        candidate.setStaleLockTime(0)
        if not candidate.tryLock(LOCK_TIMEOUT_MS):
            return False                    # 别的进程正开着

        self.release()                      # 换文件时释放旧锁
        self._lock = candidate
        return True

    def release(self) -> None:
        """释放锁（进程正常退出时也会自动释放）。"""
        if self._lock is not None:
            self._lock.unlock()
            self._lock = None
