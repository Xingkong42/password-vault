"""密码学核心：主密钥派生 + 保险箱整体加密。

设计要点
--------
* 主密码从不落盘，只用于派生密钥；校验主密码的方式就是"能否成功解密"。
* 密钥派生使用 scrypt（内存硬，抗 GPU 暴力破解），参数随文件保存，日后可升级。
* 数据加密使用 AES-256-GCM（认证加密），任何一位密文被篡改都会解密失败。
* 文件头部（KDF 参数、版本号等）作为附加认证数据（AAD）参与校验，
  因此攻击者无法偷偷降低 scrypt 强度或替换盐值。
"""

from __future__ import annotations

import base64
import json
import os
import secrets
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# ---------------------------------------------------------------- 常量定义

FORMAT_NAME = "psvault"          # 文件格式标识
FORMAT_VERSION = 1               # 容器格式版本，用于未来兼容升级

SALT_SIZE = 16                   # scrypt 盐长度（字节）
NONCE_SIZE = 12                  # GCM 推荐 nonce 长度（字节）
KEY_SIZE = 32                    # 256 位密钥

# scrypt 工作参数：N=32768, r=8, p=1 约需 32MB 内存，桌面端耗时约 0.1~0.3 秒
SCRYPT_N = 2 ** 15
SCRYPT_R = 8
SCRYPT_P = 1

# 明文备份文件的后缀
VAULT_EXTENSION = ".psvault"


class VaultError(Exception):
    """保险箱读写相关的通用错误。"""


class InvalidPassword(VaultError):
    """主密码错误（或文件被篡改导致认证失败）。"""


class CorruptedVault(VaultError):
    """文件结构损坏或不是本程序生成的保险箱。"""


# ---------------------------------------------------------------- 编解码辅助


def _b64e(raw: bytes) -> str:
    """字节 -> URL 安全的 base64 字符串。"""
    return base64.b64encode(raw).decode("ascii")


def _b64d(text: str) -> bytes:
    """base64 字符串 -> 字节。"""
    try:
        return base64.b64decode(text.encode("ascii"), validate=False)
    except Exception as exc:  # noqa: BLE001 - 统一转为自定义异常
        raise CorruptedVault("保险箱文件中的编码数据无法解析") from exc


def _canonical_header(kdf: dict[str, Any]) -> bytes:
    """把参与认证的头部字段序列化成稳定的字节串，作为 AES-GCM 的 AAD。"""
    material = {
        "format": FORMAT_NAME,
        "version": FORMAT_VERSION,
        "kdf": kdf,
    }
    return json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")


# ---------------------------------------------------------------- 密钥派生


def derive_key(
    password: str,
    salt: bytes,
    *,
    n: int = SCRYPT_N,
    r: int = SCRYPT_R,
    p: int = SCRYPT_P,
) -> bytes:
    """用 scrypt 从主密码派生出 32 字节密钥。"""
    if not password:
        raise InvalidPassword("主密码不能为空")
    kdf = Scrypt(salt=salt, length=KEY_SIZE, n=n, r=r, p=p)
    return kdf.derive(password.encode("utf-8"))


# ---------------------------------------------------------------- 加解密


def encrypt_payload(plaintext: bytes, key: bytes, kdf: dict[str, Any]) -> dict[str, Any]:
    """加密任意字节串，返回可直接 JSON 序列化的容器字典。"""
    nonce = os.urandom(NONCE_SIZE)
    cipher = AESGCM(key)
    sealed = cipher.encrypt(nonce, plaintext, _canonical_header(kdf))
    return {
        "format": FORMAT_NAME,
        "version": FORMAT_VERSION,
        "kdf": kdf,
        "cipher": {"algo": "AES-256-GCM", "nonce": _b64e(nonce)},
        "payload": _b64e(sealed),
    }


def decrypt_payload(container: dict[str, Any], key: bytes) -> bytes:
    """解密容器字典，返回原始字节串。主密码错误或数据被篡改时抛异常。"""
    try:
        kdf = container["kdf"]
        nonce = _b64d(container["cipher"]["nonce"])
        sealed = _b64d(container["payload"])
    except (KeyError, TypeError) as exc:
        raise CorruptedVault("保险箱文件结构不完整") from exc

    cipher = AESGCM(key)
    try:
        return cipher.decrypt(nonce, sealed, _canonical_header(kdf))
    except InvalidTag as exc:
        raise InvalidPassword("主密码错误，或保险箱文件已被损坏/篡改") from exc


def validate_container(container: Any) -> dict[str, Any]:
    """校验容器结构，返回规范化后的字典。"""
    if not isinstance(container, dict):
        raise CorruptedVault("保险箱文件内容不是有效的 JSON 对象")
    if container.get("format") != FORMAT_NAME:
        raise CorruptedVault("该文件不是密码保险箱文件")
    version = container.get("version")
    if not isinstance(version, int) or version > FORMAT_VERSION:
        raise CorruptedVault(f"保险箱格式版本（{version}）高于当前程序支持的版本")
    kdf = container.get("kdf")
    if not isinstance(kdf, dict) or "salt" not in kdf:
        raise CorruptedVault("保险箱文件缺少密钥派生参数")
    return container


def kdf_parameters(salt: bytes) -> dict[str, Any]:
    """构造 KDF 参数字典。"""
    return {
        "algo": "scrypt",
        "salt": _b64e(salt),
        "n": SCRYPT_N,
        "r": SCRYPT_R,
        "p": SCRYPT_P,
        "dklen": KEY_SIZE,
    }


def key_from_container(container: dict[str, Any], password: str) -> bytes:
    """按容器中记录的参数，用给定主密码派生密钥。"""
    kdf = container["kdf"]
    try:
        salt = _b64d(kdf["salt"])
        n = int(kdf.get("n", SCRYPT_N))
        r = int(kdf.get("r", SCRYPT_R))
        p = int(kdf.get("p", SCRYPT_P))
    except (KeyError, TypeError, ValueError) as exc:
        raise CorruptedVault("保险箱文件的密钥派生参数无效") from exc
    return derive_key(password, salt, n=n, r=r, p=p)


def new_salt() -> bytes:
    """生成新的随机盐。"""
    return secrets.token_bytes(SALT_SIZE)


def random_password_charset_sample() -> str:
    """返回一个用于占位展示的随机字符串（不用于真实密码生成）。"""
    return secrets.token_urlsafe(8)
