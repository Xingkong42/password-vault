"""密码强度评估与弱密码审计的判定规则。

思路：先按字符集估算信息熵，再对键盘序列、重复字符、常见弱口令等
可被字典/模式攻击快速命中的情形扣分，最后映射到 0~4 五档。
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field

# 常见弱口令（小样本，用于快速识别典型弱密码）
COMMON_PASSWORDS = {
    "123456", "12345678", "123456789", "1234567890", "password", "qwerty",
    "abc123", "111111", "123123", "admin", "letmein", "welcome", "monkey",
    "iloveyou", "dragon", "sunshine", "princess", "football", "baseball",
    "master", "shadow", "superman", "qazwsx", "1q2w3e4r", "zxcvbnm",
    "asdfgh", "666666", "888888", "000000", "a123456", "p@ssw0rd",
    "woaini", "woaini1314", "5201314", "qwe123", "admin123", "root",
}

# 键盘上连续的按键序列
KEYBOARD_ROWS = ("qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890")

STRENGTH_LABELS = ("很弱", "较弱", "一般", "较强", "很强")


@dataclass
class StrengthReport:
    """评估结果。"""

    score: int = 0                      # 0~4
    entropy_bits: float = 0.0           # 估算熵（比特）
    label: str = "很弱"
    warnings: list[str] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)

    @property
    def percent(self) -> int:
        """映射到 0~100 的进度值，便于界面展示。"""
        return int(min(100, max(0, (self.score + 1) * 20 - (0 if self.score == 4 else 5))))


def _charset_size(password: str) -> int:
    """根据出现的字符种类推断搜索空间大小。"""
    size = 0
    if re.search(r"[a-z]", password):
        size += 26
    if re.search(r"[A-Z]", password):
        size += 26
    if re.search(r"\d", password):
        size += 10
    if re.search(r"[^A-Za-z0-9]", password):
        size += 33
    return size or 1


def _has_sequence(password: str, length: int = 4) -> bool:
    """是否包含长度为 length 的键盘连续序列或字母数字递增序列。"""
    lowered = password.lower()
    for row in KEYBOARD_ROWS:
        for i in range(len(row) - length + 1):
            chunk = row[i:i + length]
            if chunk in lowered or chunk[::-1] in lowered:
                return True
    # 形如 abcd / 4321 的递增递减序列
    for i in range(len(lowered) - length + 1):
        window = lowered[i:i + length]
        if window.isalnum() and all(ord(window[j + 1]) - ord(window[j]) == 1 for j in range(length - 1)):
            return True
        if window.isalnum() and all(ord(window[j]) - ord(window[j + 1]) == 1 for j in range(length - 1)):
            return True
    return False


def _has_repeat(password: str, length: int = 3) -> bool:
    """是否包含重复字符或重复片段。"""
    if re.search(r"(.)\1{%d,}" % (length - 1), password):
        return True
    for size in (2, 3):
        for i in range(len(password) - size * 2 + 1):
            if password[i:i + size] == password[i + size:i + size * 2]:
                return True
    return False


def estimate_entropy(password: str) -> float:
    """估算密码熵（比特）。"""
    if not password:
        return 0.0
    return len(password) * math.log2(_charset_size(password))


def evaluate(password: str) -> StrengthReport:
    """综合评估密码强度。"""
    report = StrengthReport()
    if not password:
        report.warnings.append("密码为空")
        return report

    report.entropy_bits = estimate_entropy(password)
    lowered = password.lower()
    penalty = 0.0

    if lowered in COMMON_PASSWORDS:
        penalty += 55
        report.warnings.append("这是广为人知的弱密码")
    if len(password) < 8:
        penalty += 20
        report.warnings.append("长度不足 8 位")
    elif len(password) < 12:
        penalty += 8
    if _has_sequence(password):
        penalty += 12
        report.warnings.append("包含键盘或数字连续序列")
    if _has_repeat(password):
        penalty += 10
        report.warnings.append("包含重复字符或重复片段")
    if re.fullmatch(r"\d+", password):
        penalty += 15
        report.warnings.append("全部由数字组成")
    if re.fullmatch(r"[A-Za-z]+", password):
        penalty += 6
    if re.fullmatch(r".{1,3}", password):
        penalty += 25

    effective = max(report.entropy_bits - penalty, 0.0)
    if effective < 28:
        report.score = 0
    elif effective < 45:
        report.score = 1
    elif effective < 65:
        report.score = 2
    elif effective < 90:
        report.score = 3
    else:
        report.score = 4
    report.label = STRENGTH_LABELS[report.score]

    if report.score < 3:
        if len(password) < 14:
            report.suggestions.append("加长到 14 位以上，长度比复杂度更有效")
        if not re.search(r"[A-Z]", password) or not re.search(r"[a-z]", password):
            report.suggestions.append("混合大小写字母")
        if not re.search(r"\d", password):
            report.suggestions.append("加入数字")
        if not re.search(r"[^A-Za-z0-9]", password):
            report.suggestions.append("加入符号（如 !@#$%）")
        report.suggestions.append("建议使用内置生成器随机生成")
    return report


def audit(entries: list, max_age_days: int = 180) -> dict[str, list]:
    """对条目列表做安全审计，返回弱密码、重复密码、过期密码三组结果。

    参数 entries 为 models.Entry 列表（仅传入未删除的条目）。
    """
    weak = [e for e in entries if evaluate(e.password).score <= 1]

    buckets: dict[str, list] = {}
    for entry in entries:
        if entry.password:
            buckets.setdefault(entry.password, []).append(entry)
    reused = [group for group in buckets.values() if len(group) > 1]

    aged = [e for e in entries if max_age_days > 0 and e.age_days() >= max_age_days]
    empty = [e for e in entries if not e.password]

    return {"weak": weak, "reused": reused, "aged": aged, "empty": empty}
