import base64
import os
import string

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

import i18n


def generate_salt() -> bytes:
    """生成用于密钥派生的随机盐值。"""
    return os.urandom(16)


def derive_key(password: str, salt: bytes) -> bytes:
    """基于密码和盐值通过 PBKDF2 派生对称加密密钥。"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


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
