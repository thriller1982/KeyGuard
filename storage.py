import datetime
import glob
import json
import os
import shutil
import sys
import tempfile
import uuid

from cryptography.fernet import Fernet, InvalidToken

import crypto_utils


VAULT_MAGIC = "KGVLT"
VAULT_VERSION = 3
VAULT_EXT = ".kgvault"
SNAPSHOT_LIMIT = 10
VAULT_BASENAME = f"KeyGuard{VAULT_EXT}"
VAULT_TIMESTAMP_PREFIX = "KeyGuard_"

CHANGE_FIELDS = ["name", "url", "username", "password", "category", "notes"]

DEFAULT_PREFERENCES = {
    "language": "zh",
    "auto_lock_minutes": 0,
    "column_widths": [],
}

DEFAULT_CONFIG = DEFAULT_PREFERENCES


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
    def __init__(self, reason: str, *, detail: str = "", recovery_path: str | None = None):
        super().__init__(reason)
        self.reason = reason
        self.detail = detail
        self.recovery_path = recovery_path


class BackupError(StorageError):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class VaultError(StorageError):
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
DEFAULT_VAULT_PATH = os.path.join(get_app_dir(), VAULT_BASENAME)
LEGACY_DATA_DIR = DATA_DIR
LEGACY_DATA_CONFIG_FILE = os.path.join(DATA_DIR, "config.json")
LEGACY_DATA_PASSWORDS_FILE = os.path.join(DATA_DIR, "passwords.json")
LEGACY_ROOT_CONFIG_FILE = os.path.join(get_app_dir(), "config.json")
LEGACY_ROOT_PASSWORDS_FILE = os.path.join(get_app_dir(), "passwords.json")
LEGACY_ROOT_BACKUP_DIR = os.path.join(get_app_dir(), "backups")
LEGACY_DATA_BACKUP_DIR = os.path.join(DATA_DIR, "backups")

CONFIG_FILE = LEGACY_DATA_CONFIG_FILE
PASSWORDS_FILE = LEGACY_DATA_PASSWORDS_FILE


def ensure_data_dir():
    os.makedirs(DATA_DIR, exist_ok=True)


def _with_preferences_defaults(prefs: dict) -> dict:
    merged = DEFAULT_PREFERENCES.copy()
    if isinstance(prefs, dict):
        merged.update(prefs)
    return merged


_with_config_defaults = _with_preferences_defaults


def _normalize_entries(passwords):
    if not isinstance(passwords, list):
        raise VaultError("invalid_format")
    for entry in passwords:
        if not isinstance(entry, dict):
            raise VaultError("invalid_format")
        if "category" not in entry:
            entry["category"] = "other"
        if "password_history" not in entry:
            entry["password_history"] = []
    return passwords


_normalize_passwords = _normalize_entries


def ensure_entry_ids(entries):
    """为缺少 id 的条目生成 uuid4 hex。返回 (entries, changed)。

    不会覆盖已有 id。changed=True 表示至少生成过一个新 id。
    """
    changed = False
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        existing = entry.get("id")
        if not isinstance(existing, str) or not existing:
            entry["id"] = uuid.uuid4().hex
            changed = True
    return entries, changed


def compute_changes(prev_entries, curr_entries):
    """计算 curr 相对 prev 的字段级变化。

    返回 {entry_id: [field_key, ...]}，只包含有变化的条目。
    新增条目（prev 中无对应 id）不在结果中（UI 留空）。
    已删除条目（curr 中无对应 id）忽略。
    比较字段为 CHANGE_FIELDS，不含 password_history 和 id。
    """
    prev_map = {}
    for e in prev_entries or []:
        if isinstance(e, dict) and isinstance(e.get("id"), str) and e["id"]:
            prev_map[e["id"]] = e

    change = {}
    for curr in curr_entries or []:
        if not isinstance(curr, dict):
            continue
        eid = curr.get("id")
        if not isinstance(eid, str) or not eid or eid not in prev_map:
            continue
        prev = prev_map[eid]
        changed_fields = []
        for f in CHANGE_FIELDS:
            if str(prev.get(f, "")) != str(curr.get(f, "")):
                changed_fields.append(f)
        if changed_fields:
            change[eid] = changed_fields
    return change


def _argon2_kdf_spec(salt: bytes, params: dict | None = None) -> dict:
    p = dict(crypto_utils.DEFAULT_ARGON2_PARAMS)
    if params:
        p.update({k: v for k, v in params.items() if k in p})
    return {"algorithm": "argon2id", "salt": salt.hex(), "params": p}


def _kdf_spec_to_key(password: str, kdf_spec: dict) -> tuple[bytes, bytes]:
    salt_hex = kdf_spec.get("salt")
    if not isinstance(salt_hex, str):
        raise VaultError("invalid_format")
    try:
        salt = bytes.fromhex(salt_hex)
    except ValueError:
        raise VaultError("invalid_format")
    key = crypto_utils.derive_key_for_kdf(password, salt, kdf_spec)
    return key, salt


def _encrypt_payload(payload: dict, key: bytes) -> str:
    raw = json.dumps(payload, indent=2, ensure_ascii=False).encode()
    return Fernet(key).encrypt(raw).hex()


def _decrypt_payload(encrypted_hex: str, key: bytes) -> dict:
    try:
        encrypted = bytes.fromhex(encrypted_hex)
    except ValueError:
        raise VaultError("invalid_format")
    try:
        decrypted = Fernet(key).decrypt(encrypted).decode()
    except InvalidToken as exc:
        raise VaultError("wrong_password") from exc
    except Exception as exc:
        raise VaultError("decrypt_failed") from exc
    try:
        payload = json.loads(decrypted)
    except json.JSONDecodeError as exc:
        raise VaultError("invalid_data") from exc
    if not isinstance(payload, dict):
        raise VaultError("invalid_data")
    return payload


def _read_vault_container(file_path: str) -> dict:
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        raise VaultError("missing_file")
    except json.JSONDecodeError:
        raise VaultError("invalid_json")
    except OSError:
        raise VaultError("read_failed")
    if not isinstance(data, dict):
        raise VaultError("invalid_format")
    return data


def _normalized_snapshots(snapshots) -> list:
    normalized = []
    if not isinstance(snapshots, list):
        return normalized
    for snap in snapshots[:SNAPSHOT_LIMIT]:
        if not (
            isinstance(snap, dict)
            and isinstance(snap.get("timestamp"), str)
            and isinstance(snap.get("data"), str)
        ):
            continue
        change = snap.get("change", {})
        if not isinstance(change, dict):
            change = {}
        normalized.append(
            {"timestamp": snap["timestamp"], "data": snap["data"], "change": change}
        )
    return normalized


def is_vault_file(path: str) -> bool:
    """快速判断 path 是否为 KeyGuard vault 文件（检查 magic 字段）。"""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return False
    return isinstance(data, dict) and data.get("magic") == VAULT_MAGIC


def _parse_vault_container(data: dict, password: str):
    """解析 v3 vault 容器，返回 (entries, prefs, key, salt, kdf_spec, snapshots)。"""
    if data.get("magic") != VAULT_MAGIC:
        raise VaultError("unsupported_format")
    version = data.get("version")
    if version != VAULT_VERSION:
        raise VaultError("unsupported_version")

    kdf_spec = data.get("kdf")
    if not isinstance(kdf_spec, dict):
        raise VaultError("invalid_format")

    encrypted_hex = data.get("data")
    if not isinstance(encrypted_hex, str):
        raise VaultError("invalid_format")

    key, salt = _kdf_spec_to_key(password, kdf_spec)
    payload = _decrypt_payload(encrypted_hex, key)
    entries = _normalize_entries(payload.get("entries", []))
    prefs = _with_preferences_defaults(payload.get("preferences", {}))

    snapshots_raw = data.get("snapshots", [])
    snapshots = []
    if isinstance(snapshots_raw, list):
        for snap in snapshots_raw:
            if isinstance(snap, dict) and isinstance(snap.get("timestamp"), str) and isinstance(snap.get("data"), str):
                ch = snap.get("change", {})
                if not isinstance(ch, dict):
                    ch = {}
                snapshots.append({"timestamp": snap["timestamp"], "data": snap["data"], "change": ch})

    return entries, prefs, key, salt, kdf_spec, snapshots


def _parse_vault_container_by_key(data: dict, key: bytes):
    """用已派生的 key 解析 v3 容器，返回 (entries, prefs, key, salt, kdf_spec, snapshots)。"""
    if data.get("magic") != VAULT_MAGIC:
        raise VaultError("unsupported_format")
    if data.get("version") != VAULT_VERSION:
        raise VaultError("unsupported_version")

    kdf_spec = data.get("kdf")
    if not isinstance(kdf_spec, dict):
        raise VaultError("invalid_format")
    try:
        salt = bytes.fromhex(kdf_spec.get("salt", ""))
    except ValueError:
        raise VaultError("invalid_format")

    encrypted_hex = data.get("data")
    if not isinstance(encrypted_hex, str):
        raise VaultError("invalid_format")

    payload = _decrypt_payload(encrypted_hex, key)
    entries = _normalize_entries(payload.get("entries", []))
    prefs = _with_preferences_defaults(payload.get("preferences", {}))

    snapshots_raw = data.get("snapshots", [])
    snapshots = []
    if isinstance(snapshots_raw, list):
        for snap in snapshots_raw:
            if isinstance(snap, dict) and isinstance(snap.get("timestamp"), str) and isinstance(snap.get("data"), str):
                ch = snap.get("change", {})
                if not isinstance(ch, dict):
                    ch = {}
                snapshots.append({"timestamp": snap["timestamp"], "data": snap["data"], "change": ch})

    return entries, prefs, key, salt, kdf_spec, snapshots


def load_vault(path: str, password: str):
    """读取并解密 v3 vault。返回 (entries, preferences, key, salt, kdf_spec, snapshots)。"""
    if not os.path.exists(path):
        raise VaultError("missing_file")
    data = _read_vault_container(path)
    return _parse_vault_container(data, password)


def load_vault_by_key(path: str, key: bytes):
    """用已派生的 key 直接解密 v3 vault。返回 (entries, preferences, key, salt, kdf_spec, snapshots)。"""
    if not os.path.exists(path):
        raise VaultError("missing_file")
    data = _read_vault_container(path)
    return _parse_vault_container_by_key(data, key)


def save_vault(path: str, entries: list, preferences: dict, key: bytes, salt: bytes, kdf_spec: dict, snapshots: list | None = None):
    """加密后保存 vault（v3 格式）。snapshots 可选，缺省保留已有快照。"""
    normalized_entries = _normalize_entries(entries)
    prefs = _with_preferences_defaults(preferences)

    payload = {"entries": normalized_entries, "preferences": prefs}
    encrypted_hex = _encrypt_payload(payload, key)

    spec = dict(kdf_spec)
    spec["salt"] = salt.hex()

    if snapshots is None and os.path.exists(path):
        try:
            snapshots = _read_vault_container(path).get("snapshots", [])
        except VaultError as exc:
            raise PasswordSaveError(
                "preserve_snapshots_failed", detail=str(exc)
            ) from exc
    snaps_out = _normalized_snapshots(snapshots or [])

    container = {
        "magic": VAULT_MAGIC,
        "version": VAULT_VERSION,
        "kdf": spec,
        "data": encrypted_hex,
        "snapshots": snaps_out,
    }

    tmp = path + ".tmp"
    recovery_path = path + ".recovery"
    try:
        os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(container, f, indent=2, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())

        # 在替换正式文件前重新读取并验证当前数据可解密。
        verified = _read_vault_container(tmp)
        _parse_vault_container_by_key(verified, key)
        os.replace(tmp, path)
    except Exception as exc:
        saved_recovery_path = None
        if os.path.exists(tmp):
            try:
                os.replace(tmp, recovery_path)
                saved_recovery_path = recovery_path
            except OSError:
                saved_recovery_path = tmp
        reason = "write_failed" if isinstance(exc, OSError) else "verify_failed"
        raise PasswordSaveError(
            reason,
            detail=str(exc),
            recovery_path=saved_recovery_path,
        ) from exc


def create_new_vault(path: str, password: str, preferences: dict | None = None) -> tuple[bytes, bytes, dict]:
    """新建空 vault。返回 (key, salt, kdf_spec)。"""
    salt = crypto_utils.generate_salt()
    kdf_spec = _argon2_kdf_spec(salt)
    key = crypto_utils.derive_key_for_kdf(password, salt, kdf_spec)
    prefs = _with_preferences_defaults(preferences or {})
    save_vault(path, [], prefs, key, salt, kdf_spec, snapshots=[])
    return key, salt, kdf_spec


def append_snapshot(
    snapshots: list,
    entries: list,
    preferences: dict,
    key: bytes,
    timestamp: str,
    change: dict | None = None,
) -> list:
    """把当前 entries+preferences 作为新快照加密后追加到 snapshots 列表前部。

    change 是 {entry_id: [field_keys]} 字典，存入快照结构供 UI 展示。
    超过 SNAPSHOT_LIMIT 时丢弃最老的。返回新列表。
    """
    payload = {
        "entries": _normalize_entries(entries),
        "preferences": _with_preferences_defaults(preferences),
    }
    encrypted_hex = _encrypt_payload(payload, key)
    new_snap = {
        "timestamp": timestamp,
        "data": encrypted_hex,
        "change": change if isinstance(change, dict) else {},
    }
    new_list = [new_snap] + list(snapshots or [])
    return new_list[:SNAPSHOT_LIMIT]


def snapshot_matches(snapshot: dict, entries: list, preferences: dict, key: bytes) -> bool:
    """判断一份快照是否与当前完整 payload 相同。"""
    if not isinstance(snapshot, dict) or not isinstance(snapshot.get("data"), str):
        return False
    payload = _decrypt_payload(snapshot["data"], key)
    return (
        _normalize_entries(payload.get("entries", [])) == _normalize_entries(entries)
        and _with_preferences_defaults(payload.get("preferences", {}))
        == _with_preferences_defaults(preferences)
    )


def payloads_match(entries_a: list, preferences_a: dict, entries_b: list, preferences_b: dict) -> bool:
    """比较两份未加密 payload 的规范化内容。"""
    return (
        _normalize_entries(entries_a) == _normalize_entries(entries_b)
        and _with_preferences_defaults(preferences_a)
        == _with_preferences_defaults(preferences_b)
    )


def reencrypt_snapshots(snapshots: list, old_key: bytes, new_key: bytes) -> list:
    """用新密钥重新加密全部快照；任一快照失败时不返回部分结果。"""
    reencrypted = []
    for snap in _normalized_snapshots(snapshots):
        payload = _decrypt_payload(snap["data"], old_key)
        reencrypted.append(
            {
                "timestamp": snap["timestamp"],
                "data": _encrypt_payload(payload, new_key),
                "change": snap["change"],
            }
        )
    return reencrypted


def load_snapshot(path: str, snapshot_index: int, key: bytes):
    """解密指定历史快照。返回 (entries, preferences, change)。"""
    data = _read_vault_container(path)
    if data.get("magic") != VAULT_MAGIC or data.get("version") != VAULT_VERSION:
        raise VaultError("unsupported_version")
    snapshots = data.get("snapshots", [])
    if not isinstance(snapshots, list) or snapshot_index < 0 or snapshot_index >= len(snapshots):
        raise VaultError("snapshot_not_found")
    snap = snapshots[snapshot_index]
    if not isinstance(snap, dict) or not isinstance(snap.get("data"), str):
        raise VaultError("snapshot_not_found")
    payload = _decrypt_payload(snap["data"], key)
    entries = _normalize_entries(payload.get("entries", []))
    prefs = _with_preferences_defaults(payload.get("preferences", {}))
    change = snap.get("change", {})
    if not isinstance(change, dict):
        change = {}
    return entries, prefs, change


def scan_vaults_in_dir(directory: str) -> list:
    """返回 directory 下所有 .kgvault 文件路径（按修改时间升序）。"""
    if not os.path.isdir(directory):
        return []
    pattern = os.path.join(directory, f"*{VAULT_EXT}")
    files = glob.glob(pattern)
    files = [f for f in files if is_vault_file(f)]
    files.sort(key=lambda p: os.path.getmtime(p))
    return files


def compute_closed_vault_path(vault_path: str, file_stamp: str | None = None) -> str:
    """根据关闭时刻计算带时间戳的新 vault 文件名。

    file_stamp 缺省取当前时间，格式 YYYYMMDD_HHMMSS。
    返回与 vault_path 同目录的 KeyGuard_<stamp>.kgvault。
    """
    if file_stamp is None:
        file_stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    directory = os.path.dirname(os.path.abspath(vault_path)) or "."
    return os.path.join(directory, f"{VAULT_TIMESTAMP_PREFIX}{file_stamp}{VAULT_EXT}")


def remove_previous_managed_vault(previous_path: str, keep_path: str) -> bool:
    """仅删除本次关闭前明确打开的 KeyGuard 受管文件。"""
    previous_abs = os.path.abspath(previous_path)
    keep_abs = os.path.abspath(keep_path)
    if previous_abs == keep_abs or not os.path.exists(previous_abs):
        return False
    if os.path.dirname(previous_abs) != os.path.dirname(keep_abs):
        return False

    name = os.path.basename(previous_abs)
    is_managed = name == VAULT_BASENAME or (
        name.startswith(VAULT_TIMESTAMP_PREFIX) and name.endswith(VAULT_EXT)
    )
    if not is_managed:
        return False

    os.remove(previous_abs)
    return True


def write_error_log(operation: str, exc: Exception, **context) -> str | None:
    """写入不含保险库明文的本地 JSONL 错误日志。"""
    base_dir = os.environ.get("LOCALAPPDATA") or tempfile.gettempdir()
    log_dir = os.path.join(base_dir, "KeyGuard", "logs")
    log_path = os.path.join(log_dir, "keyguard.log")
    record = {
        "timestamp": datetime.datetime.now().isoformat(timespec="seconds"),
        "operation": str(operation),
        "error_type": type(exc).__name__,
        "error": str(exc),
        "context": {str(k): str(v) for k, v in context.items() if v is not None},
    }
    try:
        os.makedirs(log_dir, exist_ok=True)
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
        return log_path
    except OSError:
        return None


def detect_legacy_passwords_json() -> dict | None:
    """检测是否存在旧版 passwords.json（项目根或 data/）。返回 {passwords, config} 或 None。"""
    for p in (LEGACY_DATA_PASSWORDS_FILE, LEGACY_ROOT_PASSWORDS_FILE):
        if os.path.exists(p):
            cfg = LEGACY_DATA_CONFIG_FILE if os.path.exists(LEGACY_DATA_CONFIG_FILE) else (
                LEGACY_ROOT_CONFIG_FILE if os.path.exists(LEGACY_ROOT_CONFIG_FILE) else None
            )
            return {"passwords": p, "config": cfg}
    return None


def _read_legacy_passwords_payload(file_path: str):
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        raise VaultError("missing_file")
    except json.JSONDecodeError:
        raise VaultError("invalid_json")
    except OSError:
        raise VaultError("read_failed")
    if not isinstance(data, dict):
        raise VaultError("invalid_format")
    salt_hex = data.get("salt")
    encrypted_hex = data.get("data")
    if not isinstance(salt_hex, str) or not isinstance(encrypted_hex, str):
        raise VaultError("invalid_format")
    try:
        salt = bytes.fromhex(salt_hex)
        encrypted = bytes.fromhex(encrypted_hex)
    except ValueError:
        raise VaultError("invalid_format")
    return salt, encrypted


def migrate_legacy_passwords_json(
    legacy_passwords_path: str,
    legacy_config_path: str | None,
    target_path: str,
    password: str,
) -> tuple[bytes, bytes, dict]:
    """将旧版 passwords.json + 可选 config.json 迁移为 v3 .kgvault。

    流程：PBKDF2 解密旧文件 → 合并 config.json 偏好 → Argon2id 重加密为 v3 → 旧文件改名 .bak。
    """
    salt, encrypted = _read_legacy_passwords_payload(legacy_passwords_path)
    legacy_key = crypto_utils.derive_key(password, salt)
    try:
        decrypted_json = Fernet(legacy_key).decrypt(encrypted).decode()
    except InvalidToken as exc:
        raise VaultError("wrong_password") from exc
    except Exception as exc:
        raise VaultError("decrypt_failed") from exc
    try:
        entries = json.loads(decrypted_json)
    except json.JSONDecodeError as exc:
        raise VaultError("invalid_data") from exc

    entries, _ = ensure_entry_ids(_normalize_entries(entries))

    prefs = DEFAULT_PREFERENCES.copy()
    if legacy_config_path and os.path.exists(legacy_config_path):
        try:
            with open(legacy_config_path, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            if isinstance(cfg, dict):
                prefs = _with_preferences_defaults(cfg)
        except (OSError, json.JSONDecodeError):
            pass

    new_salt = crypto_utils.generate_salt()
    new_kdf_spec = _argon2_kdf_spec(new_salt)
    new_key = crypto_utils.derive_key_for_kdf(password, new_salt, new_kdf_spec)
    save_vault(target_path, entries, prefs, new_key, new_salt, new_kdf_spec, snapshots=[])

    for old in (legacy_passwords_path, legacy_config_path):
        if old and os.path.exists(old):
            bak = old + ".bak"
            try:
                if os.path.exists(bak):
                    os.remove(bak)
                os.rename(old, bak)
            except OSError:
                pass

    return new_key, new_salt, new_kdf_spec


def cleanup_legacy_data_dir():
    """迁移成功后清理 data/ 目录中的旧文件并尝试删除空目录。"""
    for p in (LEGACY_DATA_CONFIG_FILE, LEGACY_DATA_PASSWORDS_FILE):
        if os.path.exists(p):
            try:
                os.remove(p)
            except OSError:
                pass
    for bak in (LEGACY_DATA_CONFIG_FILE + ".bak", LEGACY_DATA_PASSWORDS_FILE + ".bak"):
        if os.path.exists(bak):
            try:
                os.remove(bak)
            except OSError:
                pass
    for d in (LEGACY_DATA_BACKUP_DIR, LEGACY_DATA_DIR):
        if os.path.isdir(d):
            try:
                shutil.rmtree(d)
            except OSError:
                pass


def cleanup_legacy_root_files():
    """清理项目根下的旧 config.json/passwords.json/backups/（迁移后）。"""
    for p in (LEGACY_ROOT_CONFIG_FILE, LEGACY_ROOT_PASSWORDS_FILE):
        if os.path.exists(p):
            try:
                os.remove(p)
            except OSError:
                pass
    for bak in (LEGACY_ROOT_CONFIG_FILE + ".bak", LEGACY_ROOT_PASSWORDS_FILE + ".bak"):
        if os.path.exists(bak):
            try:
                os.remove(bak)
            except OSError:
                pass
    if os.path.isdir(LEGACY_ROOT_BACKUP_DIR):
        try:
            shutil.rmtree(LEGACY_ROOT_BACKUP_DIR)
        except OSError:
            pass


def load_config() -> dict:
    """兼容旧调用：从 data/config.json 加载明文偏好。新代码应使用 vault 内 preferences。"""
    if not os.path.exists(LEGACY_DATA_CONFIG_FILE):
        return DEFAULT_PREFERENCES.copy()
    try:
        with open(LEGACY_DATA_CONFIG_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as exc:
        raise ConfigLoadError("invalid_json") from exc
    except OSError as exc:
        raise ConfigLoadError("read_failed") from exc
    if not isinstance(data, dict):
        raise ConfigLoadError("invalid_format")
    return _with_preferences_defaults(data)


def save_config(config: dict):
    """兼容旧调用。新代码不应使用。"""
    ensure_data_dir()
    tmp = LEGACY_DATA_CONFIG_FILE + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(_with_preferences_defaults(config), f, indent=2, ensure_ascii=False)
        os.replace(tmp, LEGACY_DATA_CONFIG_FILE)
    except OSError as exc:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass
        raise ConfigSaveError("write_failed") from exc


_KGVLT_PROG_ID = "KeyGuard.Vault"
_KGVLT_DESC = "KeyGuard Vault File"


def _winreg():
    try:
        import winreg

        return winreg
    except ImportError:
        return None


def is_kgvault_associated() -> bool:
    winreg = _winreg()
    if winreg is None:
        return False
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, f"Software\\Classes\\{VAULT_EXT}") as k:
            prog_id, _ = winreg.QueryValueEx(k, "")
            if prog_id != _KGVLT_PROG_ID:
                return False
        exe = _current_exe_path()
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            f"Software\\Classes\\{_KGVLT_PROG_ID}\\shell\\open\\command",
        ) as k:
            cmd, _ = winreg.QueryValueEx(k, "")
            return f'"{exe}"' in cmd
    except OSError:
        return False


def register_kgvault_association() -> bool:
    winreg = _winreg()
    if winreg is None:
        return False
    exe = _current_exe_path()
    if not exe:
        return False
    try:
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, f"Software\\Classes\\{VAULT_EXT}") as k:
            winreg.SetValueEx(k, "", 0, winreg.REG_SZ, _KGVLT_PROG_ID)
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, f"Software\\Classes\\{_KGVLT_PROG_ID}") as k:
            winreg.SetValueEx(k, "", 0, winreg.REG_SZ, _KGVLT_DESC)
            winreg.SetValueEx(k, "FriendlyTypeName", 0, winreg.REG_SZ, _KGVLT_DESC)
        with winreg.CreateKey(
            winreg.HKEY_CURRENT_USER,
            f"Software\\Classes\\{_KGVLT_PROG_ID}\\DefaultIcon",
        ) as k:
            winreg.SetValueEx(k, "", 0, winreg.REG_SZ, f'"{exe}",0')
        with winreg.CreateKey(
            winreg.HKEY_CURRENT_USER,
            f"Software\\Classes\\{_KGVLT_PROG_ID}\\shell\\open\\command",
        ) as k:
            winreg.SetValueEx(k, "", 0, winreg.REG_SZ, f'"{exe}" "%1"')

        try:
            from ctypes import windll

            windll.shell32.SHChangeNotify(0x08000000, 0x0000, None, None)
        except Exception:
            pass
        return True
    except OSError:
        return False


def unregister_kgvault_association() -> bool:
    winreg = _winreg()
    if winreg is None:
        return False

    def _del_tree(root_path: str):
        try:
            subkeys = []
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, root_path) as k:
                while True:
                    try:
                        subkeys.append(winreg.EnumKey(k, 0))
                    except OSError:
                        break
            for sub in subkeys:
                _del_tree(f"{root_path}\\{sub}")
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, root_path)
        except OSError:
            pass

    _del_tree(f"Software\\Classes\\{_KGVLT_PROG_ID}")
    _del_tree(f"Software\\Classes\\{VAULT_EXT}")

    try:
        from ctypes import windll

        windll.shell32.SHChangeNotify(0x08000000, 0x0000, None, None)
    except Exception:
        pass
    return True


def _current_exe_path() -> str | None:
    if getattr(sys, "frozen", False):
        return sys.executable
    return None
