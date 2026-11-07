import base64
import hashlib
import hmac
import os
import string
import struct
import time

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

import i18n


PBKDF2_ITERATIONS_LEGACY = 600000

DEFAULT_ARGON2_PARAMS = {
    "time_cost": 3,
    "memory_cost_kib": 65536,
    "parallelism": 2,
}


def generate_salt() -> bytes:
    """生成用于密钥派生的随机盐值。"""
    return os.urandom(16)


def derive_key(password: str, salt: bytes) -> bytes:
    """基于密码和盐值通过 PBKDF2-SHA256(600k) 派生密钥。

    保留用于兼容旧版 passwords.json 解密与迁移流程，新库请使用
    ``derive_key_argon2id`` / ``derive_key_for_kdf``。
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS_LEGACY,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def derive_key_argon2id(password: str, salt: bytes, params: dict | None = None) -> bytes:
    """基于密码和盐值通过 Argon2id 派生对称加密密钥。

    params 可覆盖 time_cost / memory_cost_kib / parallelism，缺省取
    ``DEFAULT_ARGON2_PARAMS``。返回值与 ``derive_key`` 同为 urlsafe-b64
    的 32 字节密钥，可直接喂给 Fernet。
    """
    p = dict(DEFAULT_ARGON2_PARAMS)
    if params:
        p.update({k: v for k, v in params.items() if k in p})

    kdf = Argon2id(
        salt=salt,
        length=32,
        iterations=int(p["time_cost"]),
        lanes=int(p["parallelism"]),
        memory_cost=int(p["memory_cost_kib"]),
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def derive_key_for_kdf(password: str, salt: bytes, kdf_spec: dict) -> bytes:
    """根据 kdf_spec 中的 algorithm 字段分发到具体的 KDF 实现。

    支持的算法：
        - "argon2id": 使用 Argon2id，params 字段透传
        - "pbkdf2_sha256": 使用 PBKDF2-SHA256，params.iterations
          缺省为 ``PBKDF2_ITERATIONS_LEGACY``（兼容旧库）

    未知算法抛出 ValueError。
    """
    algorithm = (kdf_spec or {}).get("algorithm")
    if algorithm == "argon2id":
        return derive_key_argon2id(password, salt, (kdf_spec or {}).get("params"))
    if algorithm == "pbkdf2_sha256":
        params = (kdf_spec or {}).get("params", {}) or {}
        iterations = int(params.get("iterations", PBKDF2_ITERATIONS_LEGACY))
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))
    raise ValueError(f"unsupported kdf algorithm: {algorithm!r}")


COMMON_PASSWORDS = [
    "123456",
    "password",
    "12345678",
    "qwerty",
    "123456789",
    "12345",
    "1234",
    "111111",
    "1234567",
    "dragon",
    "123123",
    "baseball",
    "iloveyou",
    "trustno1",
    "sunshine",
    "master",
    "welcome",
    "shadow",
    "ashley",
    "football",
    "jesus",
    "michael",
    "ninja",
    "mustang",
    "password1",
    "123456a",
    "password123",
    "admin",
    "letmein",
    "login",
    "passw0rd",
    "hello",
    "monkey",
    "whatever",
    "abc123",
    "starwars",
    "1234567890",
    "computer",
    "internet",
    "princess",
    "qwerty123",
    "solo",
    "hottie",
    "loveme",
    "flower",
    "zaq1zaq1",
    "password2",
    "fuckyou",
    "fuckoff",
    "test",
    "testing",
    "temp",
    "master123",
    "root",
    "toor",
    "pass",
    "changeme",
    "default",
    "q1w2e3r4",
    "q1w2e3r4t5",
    "1q2w3e4r",
    "1q2w3e4r5t",
    "qwe123",
    "qwe123456",
    "admin123",
    "root123",
    "pass123",
    "user123",
    "test123",
    "demo123",
    "server",
    "mysql",
    "oracle",
    "postgres",
    "ubuntu",
    "debian",
    "centos",
    "redhat",
    "fedora",
    "windows",
    "office",
    "excel",
    "word",
    "powerpoint",
    "access",
    "outlook",
    "skype",
    "teams",
    "zoom",
    "gmail",
    "yahoo",
    "hotmail",
    "mail",
    "facebook",
    "twitter",
    "instagram",
    "linkedin",
    "tiktok",
    "youtube",
    "google",
    "baidu",
    "amazon",
    "ebay",
]


def evaluate_password_strength(password: str) -> dict:
    """
    评估密码强度并返回评分结果。

    返回值:
        dict，包含以下键:
            - strength: 'weak' / 'medium' / 'strong'
            - score: 0-100 的整数分数
            - suggestions: 强化建议列表
    """
    if not password:
        return {
            "strength": "weak",
            "score": 0,
            "suggestions": [i18n._t("strength_suggest_enter_password")],
        }

    if len(password) < 6:
        return {
            "strength": "weak",
            "score": max(5, len(password) * 3),
            "suggestions": [i18n._t("strength_suggest_min_length")],
        }

    score = 0
    suggestions = []

    length = len(password)
    if length >= 16:
        score += 25
    elif length >= 12:
        score += 20
    elif length >= 8:
        score += 15
    elif length >= 6:
        score += 10
    else:
        suggestions.append(i18n._t("strength_suggest_min_length"))

    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in string.punctuation for c in password)
    type_count = sum([has_lower, has_upper, has_digit, has_special])

    if has_lower:
        score += 10
    if has_upper:
        score += 10
    if has_digit:
        score += 10
    if has_special:
        score += 10

    if type_count < 3:
        suggestions.append(i18n._t("strength_suggest_mix_chars"))

    max_consecutive = 1
    current_consecutive = 1
    prev_char = ""
    for char in password:
        if char == prev_char:
            current_consecutive += 1
            max_consecutive = max(max_consecutive, current_consecutive)
        else:
            current_consecutive = 1
        prev_char = char

    if max_consecutive >= 4:
        score -= 5
        suggestions.append(i18n._t("strength_suggest_no_repeat"))
        if max_consecutive == length:
            score -= 40
    else:
        score += 15

    has_sequential = False
    sequences = [
        "123",
        "234",
        "345",
        "456",
        "567",
        "678",
        "789",
        "890",
        "abc",
        "bcd",
        "cde",
        "def",
        "efg",
        "fgh",
        "ghi",
        "hij",
        "ijk",
        "jkl",
        "klm",
        "lmn",
        "mno",
        "nop",
        "opq",
        "pqr",
        "qrs",
        "rst",
        "stu",
        "tuv",
        "uvw",
        "vwx",
        "wxy",
        "xyz",
    ]
    password_lower = password.lower()
    for seq in sequences:
        if seq in password_lower or seq[::-1] in password_lower:
            has_sequential = True
            break

    if has_sequential:
        score -= 5
        suggestions.append(i18n._t("strength_suggest_no_sequential"))
    else:
        score += 10

    if password.lower() in COMMON_PASSWORDS:
        score = max(score - 30, 5)
        suggestions.append(i18n._t("strength_suggest_not_common"))
    else:
        score += 10

    score = max(0, min(100, score))

    if score < 40:
        strength = "weak"
    elif score < 70:
        strength = "medium"
    else:
        strength = "strong"

    return {
        "strength": strength,
        "score": score,
        "suggestions": suggestions,
    }


def get_strength_color(strength: str) -> str:
    colors = {
        "weak": "#e74c3c",
        "medium": "#f39c12",
        "strong": "#27ae60",
    }
    return colors.get(strength, "#95a5a6")


def generate_totp(
    secret_str: str,
    for_time: float | None = None,
    digits: int = 6,
    interval: int = 30,
) -> tuple[str, int, str]:
    """生成符合 RFC 6238 / RFC 4226 标准的 TOTP 动态验证码。

    返回 (code, remaining_seconds, status)。
    status 可取值:
      - 'ok': 成功生成 6 位动态验证码
      - 'empty': 密钥为空
      - 'invalid': 密钥不是有效的 Base32 编码
    """
    cleaned = secret_str.strip().replace(" ", "").replace("-", "").upper()
    if not cleaned:
        return "", 0, "empty"

    padding = (8 - len(cleaned) % 8) % 8
    try:
        key = base64.b32decode(cleaned + ("=" * padding), casefold=True)
    except Exception:
        return "", 0, "invalid"

    if for_time is None:
        for_time = time.time()

    counter = int(for_time // interval)
    counter_bytes = struct.pack(">Q", counter)
    mac = hmac.new(key, counter_bytes, hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    code_int = struct.unpack(">I", mac[offset : offset + 4])[0] & 0x7FFFFFFF
    code = str(code_int % (10**digits)).zfill(digits)
    remaining = interval - int(for_time) % interval
    return code, remaining, "ok"
