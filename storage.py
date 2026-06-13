import datetime
import json
import os
import shutil
import sys

from cryptography.fernet import Fernet, InvalidToken

import crypto_utils


DEFAULT_CONFIG = {
    "language": "zh",
    "auto_lock_minutes": 0,
    "auto_backup": False,
    "column_widths": [],
}


class StorageError(Exception):
    pass


class ConfigLoadError(StorageError):
    pass


class ConfigSaveError(StorageError):
    pass


class PasswordLoadError(StorageError):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class PasswordSaveError(StorageError):
    pass


class BackupError(StorageError):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def get_app_dir() -> str:
    """获取应用程序所在目录，支持便携模式（U盘等）。"""
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def get_data_dir() -> str:
    return os.path.join(get_app_dir(), "data")


DATA_DIR = get_data_dir()
CONFIG_FILE = os.path.join(DATA_DIR, "config.json")
PASSWORDS_FILE = os.path.join(DATA_DIR, "passwords.json")
BACKUP_DIR = os.path.join(DATA_DIR, "backups")
LEGACY_CONFIG_FILE = os.path.join(get_app_dir(), "config.json")
LEGACY_PASSWORDS_FILE = os.path.join(get_app_dir(), "passwords.json")
LEGACY_BACKUP_DIR = os.path.join(get_app_dir(), "backups")


def ensure_data_dir():
    os.makedirs(DATA_DIR, exist_ok=True)


def migrate_legacy_files():
    ensure_data_dir()

    if os.path.exists(LEGACY_CONFIG_FILE) and not os.path.exists(CONFIG_FILE):
        shutil.move(LEGACY_CONFIG_FILE, CONFIG_FILE)

    if os.path.exists(LEGACY_PASSWORDS_FILE) and not os.path.exists(PASSWORDS_FILE):
        shutil.move(LEGACY_PASSWORDS_FILE, PASSWORDS_FILE)

    if os.path.isdir(LEGACY_BACKUP_DIR) and not os.path.exists(BACKUP_DIR):
        shutil.move(LEGACY_BACKUP_DIR, BACKUP_DIR)


def _with_config_defaults(config: dict) -> dict:
    merged = DEFAULT_CONFIG.copy()
    merged.update(config)
    return merged


def _normalize_passwords(passwords):
    if not isinstance(passwords, list):
        raise PasswordLoadError("invalid_format")

    for entry in passwords:
        if not isinstance(entry, dict):
            raise PasswordLoadError("invalid_format")
        if "category" not in entry:
            entry["category"] = "other"
        if "password_history" not in entry:
            entry["password_history"] = []
    return passwords


def _read_password_payload(file_path: str):
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        raise PasswordLoadError("missing_file")
    except json.JSONDecodeError:
        raise PasswordLoadError("invalid_json")
    except OSError:
        raise PasswordLoadError("read_failed")

    if not isinstance(data, dict):
        raise PasswordLoadError("invalid_format")

    salt_hex = data.get("salt")
    encrypted_hex = data.get("data")
    if not isinstance(salt_hex, str) or not isinstance(encrypted_hex, str):
        raise PasswordLoadError("invalid_format")

    try:
        salt = bytes.fromhex(salt_hex)
        encrypted = bytes.fromhex(encrypted_hex)
    except ValueError:
        raise PasswordLoadError("invalid_format")

    return salt, encrypted


def load_config() -> dict:
    """从 config.json 加载配置。"""
    migrate_legacy_files()
    if not os.path.exists(CONFIG_FILE):
        save_config(DEFAULT_CONFIG.copy())
        return DEFAULT_CONFIG.copy()

    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as exc:
        raise ConfigLoadError("invalid_json") from exc
    except OSError as exc:
        raise ConfigLoadError("read_failed") from exc

    if not isinstance(data, dict):
        raise ConfigLoadError("invalid_format")
    return _with_config_defaults(data)


def save_config(config: dict):
    ensure_data_dir()
    tmp = CONFIG_FILE + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(_with_config_defaults(config), f, indent=2, ensure_ascii=False)
        os.replace(tmp, CONFIG_FILE)
    except OSError as exc:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass
        raise ConfigSaveError("write_failed") from exc


def is_first_run() -> bool:
    """检查是否首次运行（即尚未生成 passwords.json）。"""
    migrate_legacy_files()
    return not os.path.exists(PASSWORDS_FILE)


def load_passwords(master_password: str):
    """从文件读取并解密密码数据。返回 (passwords, key, salt)。"""
    migrate_legacy_files()
    if not os.path.exists(PASSWORDS_FILE):
        return [], None, None

    salt, encrypted = _read_password_payload(PASSWORDS_FILE)

    key = crypto_utils.derive_key(master_password, salt)
    try:
        decrypted_json = Fernet(key).decrypt(encrypted).decode()
    except InvalidToken as exc:
        raise PasswordLoadError("wrong_password") from exc
    except Exception as exc:
        raise PasswordLoadError("decrypt_failed") from exc

    try:
        passwords = json.loads(decrypted_json)
    except json.JSONDecodeError as exc:
        raise PasswordLoadError("invalid_data") from exc

    return _normalize_passwords(passwords), key, salt


def load_passwords_by_key(key: bytes, salt: bytes):
    """用已有 key 和 salt 直接解密文件，返回 (passwords, key, salt)。"""
    migrate_legacy_files()
    if not os.path.exists(PASSWORDS_FILE):
        return [], key, salt

    _, encrypted = _read_password_payload(PASSWORDS_FILE)
    try:
        decrypted_json = Fernet(key).decrypt(encrypted).decode()
    except InvalidToken as exc:
        raise PasswordLoadError("wrong_password") from exc
    except Exception as exc:
        raise PasswordLoadError("decrypt_failed") from exc

    try:
        passwords = json.loads(decrypted_json)
    except json.JSONDecodeError as exc:
        raise PasswordLoadError("invalid_data") from exc

    return _normalize_passwords(passwords), key, salt


def save_passwords(passwords: list, key: bytes, salt: bytes):
    """加密后保存密码数据到文件。key 和 salt 由调用方提供。"""
    ensure_data_dir()
    normalized = _normalize_passwords(passwords)

    encrypted = Fernet(key).encrypt(json.dumps(normalized, indent=2, ensure_ascii=False).encode())
    data = {"salt": salt.hex(), "data": encrypted.hex()}

    tmp = PASSWORDS_FILE + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, PASSWORDS_FILE)
    except OSError as exc:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass
        raise PasswordSaveError("write_failed") from exc


def create_backup(backup_path: str = None) -> bool:
    """创建密码文件备份（直接复制文件）。"""
    migrate_legacy_files()
    if not os.path.exists(PASSWORDS_FILE):
        raise BackupError("missing_source")

    if backup_path is None:
        os.makedirs(BACKUP_DIR, exist_ok=True)
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = os.path.join(BACKUP_DIR, f"passwords_backup_{timestamp}.json")

    try:
        shutil.copy2(PASSWORDS_FILE, backup_path)
    except OSError as exc:
        raise BackupError("copy_failed") from exc
    return True


def restore_backup(backup_path: str, key: bytes, salt: bytes) -> bool:
    """从备份文件恢复密码数据。用 key 验证备份文件可解密后覆盖当前文件。"""
    if not os.path.exists(backup_path):
        raise BackupError("missing_backup")

    backup_salt, encrypted = _read_password_payload(backup_path)
    try:
        decrypted_json = Fernet(key).decrypt(encrypted).decode()
    except InvalidToken as exc:
        raise BackupError("wrong_password") from exc
    except Exception as exc:
        raise BackupError("decrypt_failed") from exc

    try:
        passwords = json.loads(decrypted_json)
    except json.JSONDecodeError as exc:
        raise BackupError("invalid_data") from exc

    _ = backup_salt
    try:
        save_passwords(_normalize_passwords(passwords), key, salt)
    except PasswordSaveError as exc:
        raise BackupError("write_failed") from exc
    return True
