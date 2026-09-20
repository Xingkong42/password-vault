"""两步验证（TOTP，RFC 6238）实现，只依赖标准库。

支持从 base32 密钥或 otpauth:// 链接中解析参数，并生成当前动态口令。
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import struct
import time
from dataclasses import dataclass
from urllib.parse import parse_qs, unquote, urlparse

ALGORITHMS = {
    "SHA1": hashlib.sha1,
    "SHA256": hashlib.sha256,
    "SHA512": hashlib.sha512,
}


@dataclass
class TotpConfig:
    """一条 TOTP 配置。"""

    secret: str = ""
    digits: int = 6
    period: int = 30
    algorithm: str = "SHA1"
    issuer: str = ""
    account: str = ""


def normalize_secret(secret: str) -> str:
    """清理密钥中的空格、连字符与大小写，并补齐 base32 的填充 '='。"""
    cleaned = "".join(secret.split()).replace("-", "").upper()
    cleaned = cleaned.rstrip("=")
    remainder = len(cleaned) % 8
    if remainder:
        cleaned += "=" * (8 - remainder)
    return cleaned


def is_valid_secret(secret: str) -> bool:
    """判断是否可作为 base32 密钥解析。"""
    cleaned = normalize_secret(secret)
    if len(cleaned) < 8:
        return False
    try:
        base64.b32decode(cleaned, casefold=True)
    except (binascii.Error, ValueError):
        return False
    return True


def parse_otpauth(uri: str) -> TotpConfig | None:
    """解析 otpauth://totp/... 链接。"""
    uri = uri.strip()
    if not uri.lower().startswith("otpauth://"):
        return None
    parsed = urlparse(uri)
    params = parse_qs(parsed.query)
    secret = (params.get("secret") or [""])[0]
    # 必须校验：只判断"非空"的话，secret=??? 也会被当成有效配置，
    # 等到生成口令时才在 b32decode 上炸掉。
    if not secret or not is_valid_secret(secret):
        return None
    algorithm = (params.get("algorithm") or ["SHA1"])[0].upper()
    label = unquote(parsed.path.lstrip("/"))
    account = label.split(":")[-1] if ":" in label else label
    issuer = (params.get("issuer") or [""])[0]
    if not issuer and ":" in label:
        issuer = label.split(":")[0]
    digits = _int_param(params, "digits", 6, minimum=4)
    period = _int_param(params, "period", 30, minimum=5)
    if digits is None or period is None:
        return None                     # 参数畸形，视为整条链接不可用
    return TotpConfig(
        secret=normalize_secret(secret),
        digits=digits,
        period=period,
        algorithm=algorithm if algorithm in ALGORITHMS else "SHA1",
        issuer=issuer,
        account=account,
    )


def _int_param(params: dict, name: str, default: int, *, minimum: int) -> int | None:
    """读取整型查询参数。

    缺省时用默认值；写了但不是合法整数（如 digits=abc）时返回 None——
    这种情况下整条链接都不该被当成有效配置。
    """
    raw = (params.get(name) or [""])[0].strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return None
    return value if value >= minimum else None


def parse_secret_input(text: str) -> TotpConfig | None:
    """把用户输入（可能是 otpauth 链接或裸密钥）解析成 TotpConfig。

    任何格式问题都返回 None，绝不向调用方抛异常——这个函数会被输入框的
    textChanged 直接调用，抛异常会打断界面事件处理。
    """
    text = (text or "").strip()
    if not text:
        return None
    try:
        if text.lower().startswith("otpauth://"):
            return parse_otpauth(text)
        if is_valid_secret(text):
            return TotpConfig(secret=normalize_secret(text))
    except (ValueError, TypeError, binascii.Error):
        return None
    return None


def generate_code(secret: str, *, digits: int = 6, period: int = 30,
                  algorithm: str = "SHA1", at: float | None = None) -> str:
    """生成指定时刻的动态口令。"""
    key = base64.b32decode(normalize_secret(secret), casefold=True)
    counter = int((time.time() if at is None else at) // period)
    digest = hmac.new(key, struct.pack(">Q", counter), ALGORITHMS.get(algorithm, hashlib.sha1)).digest()
    offset = digest[-1] & 0x0F
    truncated = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(truncated % (10 ** digits)).zfill(digits)


def seconds_remaining(period: int = 30, at: float | None = None) -> int:
    """当前口令还剩多少秒失效。"""
    moment = time.time() if at is None else at
    return int(period - (moment % period))


def format_code(code: str) -> str:
    """把 6/8 位口令从中间断开，方便阅读。"""
    half = len(code) // 2
    return f"{code[:half]} {code[half:]}" if half else code
