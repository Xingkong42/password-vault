"""密码生成器：随机强密码 + 易记短语密码。

随机数一律来自 `secrets`（操作系统级密码学随机源），不使用 random 模块。
"""

from __future__ import annotations

import secrets
import string
from dataclasses import dataclass

LOWERCASE = string.ascii_lowercase
UPPERCASE = string.ascii_uppercase
DIGITS = string.digits
SYMBOLS = "!@#$%^&*()-_=+[]{}<>?,.:;"

# 容易看错的字符（0/O、1/l/I 等），可一键排除
AMBIGUOUS = "0O1lI|`'\"{}[]()/\\"

# 易记短语用的短词表（3~7 个字母的常用英文词，便于记忆与输入）
WORDLIST = [
    "apple", "amber", "anchor", "arrow", "atlas", "autumn", "bacon", "badge",
    "bamboo", "banjo", "beacon", "berry", "bishop", "bison", "blossom", "breeze",
    "bridge", "bronze", "brook", "cabin", "cactus", "camel", "candle", "canoe",
    "canyon", "carbon", "castle", "cedar", "cello", "cherry", "cinder", "citrus",
    "clover", "cobalt", "comet", "compass", "copper", "coral", "cosmos", "cotton",
    "cricket", "crystal", "cypress", "daisy", "dapper", "dawn", "denim", "dolphin",
    "domino", "dragon", "dune", "eagle", "ember", "emerald", "falcon", "feather",
    "fennel", "ferry", "fiddle", "flint", "forest", "fossil", "fox", "galaxy",
    "garden", "ginger", "glacier", "granite", "grape", "harbor", "hazel", "heron",
    "hickory", "honey", "indigo", "ivory", "jade", "jasmine", "jungle", "juniper",
    "kettle", "koala", "lantern", "lark", "lavender", "lemon", "leopard", "lilac",
    "linen", "lotus", "lunar", "magnet", "mango", "maple", "marble", "meadow",
    "melon", "meteor", "mint", "mirror", "monsoon", "moss", "nectar", "needle",
    "nickel", "noble", "nutmeg", "oasis", "ocean", "olive", "onyx", "opal",
    "orbit", "orchid", "otter", "panda", "papaya", "pebble", "pepper", "petal",
    "pigeon", "pilot", "pine", "pixel", "planet", "plum", "pollen", "poppy",
    "prairie", "prism", "puddle", "puzzle", "quartz", "quill", "raven", "ribbon",
    "ripple", "river", "robin", "rocket", "saddle", "saffron", "sage", "salmon",
    "sapphire", "scarlet", "sequoia", "shadow", "silver", "siren", "solstice", "sparrow",
    "spruce", "stellar", "stone", "summit", "sunset", "sycamore", "tango", "teak",
    "thistle", "thunder", "timber", "topaz", "tulip", "tundra", "turtle", "velvet",
    "violet", "walnut", "willow", "winter", "zenith", "zephyr", "zinnia",
]


@dataclass
class GeneratorOptions:
    """生成参数。"""

    length: int = 18
    use_lowercase: bool = True
    use_uppercase: bool = True
    use_digits: bool = True
    use_symbols: bool = True
    exclude_ambiguous: bool = False
    require_each_type: bool = True    # 保证每类字符至少出现一次
    extra_excluded: str = ""          # 用户自定义要排除的字符


class GeneratorError(ValueError):
    """生成参数不合法。"""


def _pool(options: GeneratorOptions) -> str:
    """按参数拼出可用字符池。"""
    parts = []
    if options.use_lowercase:
        parts.append(LOWERCASE)
    if options.use_uppercase:
        parts.append(UPPERCASE)
    if options.use_digits:
        parts.append(DIGITS)
    if options.use_symbols:
        parts.append(SYMBOLS)
    pool = "".join(parts)

    excluded = set(options.extra_excluded or "")
    if options.exclude_ambiguous:
        excluded.update(AMBIGUOUS)
    if excluded:
        pool = "".join(ch for ch in pool if ch not in excluded)
    return pool


def generate_password(options: GeneratorOptions) -> str:
    """按参数生成随机密码。"""
    length = max(4, min(128, int(options.length)))
    pool = _pool(options)
    if not pool:
        raise GeneratorError("至少要选择一种字符类型")

    groups = []
    if options.use_lowercase:
        groups.append([c for c in LOWERCASE if c in pool])
    if options.use_uppercase:
        groups.append([c for c in UPPERCASE if c in pool])
    if options.use_digits:
        groups.append([c for c in DIGITS if c in pool])
    if options.use_symbols:
        groups.append([c for c in SYMBOLS if c in pool])
    groups = [g for g in groups if g]

    chars: list[str] = []
    if options.require_each_type and groups and len(groups) <= length:
        chars.extend(secrets.choice(group) for group in groups)
    while len(chars) < length:
        chars.append(secrets.choice(pool))

    # Fisher-Yates 洗牌，避免必选字符总在开头
    for i in range(len(chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        chars[i], chars[j] = chars[j], chars[i]
    return "".join(chars[:length])


def generate_passphrase(words: int = 4, separator: str = "-", capitalize: bool = False,
                        add_number: bool = True) -> str:
    """生成易记的短语密码，如 coral-ember-zenith-42。"""
    words = max(3, min(10, int(words)))
    picked = [secrets.choice(WORDLIST) for _ in range(words)]
    if capitalize:
        picked = [w.capitalize() for w in picked]
    phrase = separator.join(picked)
    if add_number:
        phrase += f"{separator}{secrets.randbelow(90) + 10}"
    return phrase


def generate_pin(length: int = 6) -> str:
    """生成纯数字 PIN 码。"""
    length = max(4, min(24, int(length)))
    return "".join(secrets.choice(DIGITS) for _ in range(length))


def generate_batch(options: GeneratorOptions, count: int = 5) -> list[str]:
    """一次生成多条候选密码（去重）。"""
    result: list[str] = []
    for _ in range(max(1, min(20, count))):
        candidate = generate_password(options)
        while candidate in result:
            candidate = generate_password(options)
        result.append(candidate)
    return result
