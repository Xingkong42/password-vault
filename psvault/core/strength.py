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
    """按问题类型分组，便于整体查看。

    与 `entry_issues` 共用同一套判定逻辑（包括"已忽略"的处理），
    保证界面各处口径一致。返回的每个列表里是同一条记录可能出现一次。
    """
    grouped: dict[str, list] = {"weak": [], "reused": [], "aged": [], "empty": []}
    for entry in entries:
        for issue in entry_issues(entry, entries, max_age_days):
            if issue.ignored or issue.kind not in grouped:
                continue
            grouped[issue.kind].append(entry)
    return grouped


# ---------------------------------------------------------------- 单条记录体检

# 严重程度排序：数字越小越需要优先处理
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}

SEVERITY_LABELS = {
    "high": "风险",
    "medium": "注意",
    "low": "建议",
    "info": "提示",
}

# 列表卡片上用的短标签
ISSUE_SHORT_LABELS = {
    "weak": "弱密码",
    "reused": "重复使用",
    "aged": "久未更新",
    "empty": "未设密码",
    "suggest": "可优化",
}

# 审计分组：key -> (标题, 图标, 一句话说明)
ISSUE_GROUPS = (
    ("weak", "弱密码", "alert", "这些密码很容易被字典或暴力破解猜到"),
    ("reused", "重复使用的密码", "copy", "一处泄漏会连带其他账号一起失守"),
    ("aged", "长期未更换", "clock", "建议定期更换重要账号的密码"),
    ("empty", "未设置密码", "info", "这些记录还没有保存密码"),
    ("suggest", "可以更好", "sparkles", "不影响使用，但做了会更安全"),
)


@dataclass
class Issue:
    """一条记录身上的具体问题——用来回答"风险到底在哪"。"""

    kind: str          # weak / reused / aged / empty / suggest
    severity: str      # high / medium / low / info
    title: str         # 一句话结论，如「密码强度较弱」
    detail: str = ""   # 具体原因，如「长度不足 8 位；包含键盘连续序列」
    ignored: bool = False   # 用户已在审计里主动忽略这类问题

    @property
    def severity_risk(self) -> bool:
        """按严重程度判断是否算风险（不考虑是否已忽略）。"""
        return self.severity != "info"

    @property
    def is_risk(self) -> bool:
        """当前是否仍需要处理：既是风险，又没有被人为忽略。"""
        return self.severity_risk and not self.ignored

    @property
    def severity_label(self) -> str:
        return SEVERITY_LABELS.get(self.severity, "提示")

    @property
    def short_label(self) -> str:
        return ISSUE_SHORT_LABELS.get(self.kind, "问题")


def entry_issues(entry, entries: list, max_age_days: int = 180) -> list[Issue]:
    """检查单条记录，返回它存在的全部问题（按严重程度排序）。

    这是审计视图、详情页风险提示共用的判定逻辑，保证两处口径一致。
    返回的每一项都带好 `ignored` 标记（用户是否忽略过这类问题）。
    """
    issues = _collect_issues(entry, entries, max_age_days)
    for issue in issues:
        issue.ignored = entry.is_issue_ignored(issue.kind)
    # 被忽略的排到后面，未处理的优先展示
    issues.sort(key=lambda item: (item.ignored, SEVERITY_ORDER.get(item.severity, 9)))
    return issues


def _collect_issues(entry, entries: list, max_age_days: int) -> list[Issue]:
    """收集一条记录身上的全部问题（不含忽略标记）。"""
    issues: list[Issue] = []

    if not entry.password:
        issues.append(Issue(
            kind="empty", severity="medium",
            title="未设置密码",
            detail="这条记录还没有保存密码，无法评估强度",
        ))
        return issues

    report = evaluate(entry.password)
    if report.score <= 1:
        reason = "；".join(report.warnings[:3]) or "密码过于简单"
        issues.append(Issue(
            kind="weak", severity="high",
            title=f"弱密码（强度{report.label}）",
            detail=reason,
        ))
    elif report.score == 2:
        reason = "；".join(report.suggestions[:2]) or "建议加长或增加字符种类"
        issues.append(Issue(
            kind="suggest", severity="info",
            title="密码强度一般",
            detail=reason,
        ))

    same = [e for e in entries
            if e.id != entry.id and e.password and e.password == entry.password]
    if same:
        names = "、".join(e.title for e in same[:3])
        more = f" 等 {len(same)} 条" if len(same) > 3 else ""
        issues.append(Issue(
            kind="reused", severity="high",
            title=f"与 {len(same)} 条记录使用了相同密码",
            detail=f"重复的账号：{names}{more}。一旦其中一处泄漏，其余账号会一并失守",
        ))

    if max_age_days > 0:
        days = entry.age_days()
        if days >= max_age_days:
            issues.append(Issue(
                kind="aged", severity="medium",
                title=f"已 {days} 天未修改密码",
                detail=f"超过设定的 {max_age_days} 天，建议定期更换",
            ))

    if not entry.totp_secret:
        issues.append(Issue(
            kind="suggest", severity="info",
            title="未启用两步验证",
            detail="支持两步验证的网站建议开启，密钥可保存在本记录中",
        ))

    return issues


def risk_entries(entries: list, max_age_days: int = 180) -> list:
    """筛出仍存在风险的记录（不含纯建议，也不含已全部忽略的）。"""
    return [e for e in entries if any(i.is_risk for i in entry_issues(e, entries, max_age_days))]


def ignored_issues(entries: list, max_age_days: int = 180) -> list[tuple[object, Issue]]:
    """列出被忽略、但问题当前依然存在的问题，供"恢复忽略"使用。"""
    result: list[tuple[object, Issue]] = []
    for entry in entries:
        for issue in entry_issues(entry, entries, max_age_days):
            if issue.ignored and issue.severity_risk:
                result.append((entry, issue))
    return result
