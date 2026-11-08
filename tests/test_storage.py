import json
from pathlib import Path

import pytest

import crypto_utils
import storage


@pytest.fixture
def storage_module(monkeypatch, tmp_path):
    module = __import__("storage")
    monkeypatch.setattr(module, "get_app_dir", lambda: str(tmp_path))
    monkeypatch.setattr(module, "DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setattr(
        module, "DEFAULT_VAULT_PATH", str(tmp_path / "KeyGuard.kgvault")
    )
    monkeypatch.setattr(
        module, "LEGACY_DATA_DIR", str(tmp_path / "data")
    )
    monkeypatch.setattr(
        module, "LEGACY_DATA_CONFIG_FILE", str(tmp_path / "data" / "config.json")
    )
    monkeypatch.setattr(
        module, "LEGACY_DATA_PASSWORDS_FILE", str(tmp_path / "data" / "passwords.json")
    )
    monkeypatch.setattr(
        module, "LEGACY_ROOT_CONFIG_FILE", str(tmp_path / "config.json")
    )
    monkeypatch.setattr(
        module, "LEGACY_ROOT_PASSWORDS_FILE", str(tmp_path / "passwords.json")
    )
    monkeypatch.setattr(
        module, "LEGACY_ROOT_BACKUP_DIR", str(tmp_path / "backups")
    )
    monkeypatch.setattr(
        module, "LEGACY_DATA_BACKUP_DIR", str(tmp_path / "data" / "backups")
    )
    monkeypatch.setattr(module, "CONFIG_FILE", str(tmp_path / "data" / "config.json"))
    monkeypatch.setattr(
        module, "PASSWORDS_FILE", str(tmp_path / "data" / "passwords.json")
    )
    return module


def _make_vault(storage_module, path, password, entries, prefs=None):
    salt = crypto_utils.generate_salt()
    kdf_spec = storage_module._argon2_kdf_spec(salt)
    key = crypto_utils.derive_key_for_kdf(password, salt, kdf_spec)
    storage_module.save_vault(
        path, entries, prefs or storage_module.DEFAULT_PREFERENCES.copy(),
        key, salt, kdf_spec
    )
    return key, salt, kdf_spec


def test_save_and_load_vault_v3_roundtrip(storage_module):
    path = str(Path(storage_module.get_app_dir()) / "v.kgvault")
    key, salt, kdf_spec = _make_vault(
        storage_module, path, "secret", [{"name": "demo", "password": "v"}],
        prefs={"language": "en", "column_widths": [80, 90]},
    )
    entries, prefs, k2, s2, kdf2, trash = storage_module.load_vault(path, "secret")
    assert entries[0]["name"] == "demo"
    assert entries[0]["category"] == "other"
    assert k2 == key and s2 == salt
    assert kdf2["algorithm"] == "argon2id"
    assert prefs["language"] == "en"
    assert prefs["column_widths"] == [80, 90]
    assert trash == []


def test_vault_version_is_3(storage_module):
    path = str(Path(storage_module.get_app_dir()) / "v.kgvault")
    _make_vault(storage_module, path, "secret", [])
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    assert raw["magic"] == storage_module.VAULT_MAGIC
    assert raw["version"] == 3
    assert raw["kdf"]["algorithm"] == "argon2id"


def test_load_vault_wrong_password_raises(storage_module):
    path = str(Path(storage_module.get_app_dir()) / "v.kgvault")
    _make_vault(storage_module, path, "secret", [])
    with pytest.raises(storage_module.VaultError) as exc:
        storage_module.load_vault(path, "wrong")
    assert exc.value.reason == "wrong_password"


def test_load_vault_by_key_roundtrip(storage_module):
    path = str(Path(storage_module.get_app_dir()) / "v.kgvault")
    key, salt, kdf_spec = _make_vault(
        storage_module, path, "secret", [{"name": "x", "password": "1"}]
    )
    entries, prefs, k2, s2, kdf2, trash = storage_module.load_vault_by_key(path, key)
    assert entries[0]["name"] == "x"
    assert k2 == key and s2 == salt and kdf2 == kdf_spec
    assert trash == []


def test_load_vault_v2_raises_unsupported(storage_module):
    path = str(Path(storage_module.get_app_dir()) / "v2.kgvault")
    # 手工构造 v2 容器
    salt = crypto_utils.generate_salt()
    kdf_spec = storage_module._argon2_kdf_spec(salt)
    key = crypto_utils.derive_key_for_kdf("pw", salt, kdf_spec)
    from cryptography.fernet import Fernet
    enc = Fernet(key).encrypt(b'{"entries":[],"preferences":{}}').hex()
    raw = {"magic": "KGVLT", "version": 2, "kdf": kdf_spec, "data": enc}
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(storage_module.VaultError) as exc:
        storage_module.load_vault(path, "pw")
    assert exc.value.reason == "unsupported_version"


def test_load_vault_missing_magic_raises(storage_module):
    path = str(Path(storage_module.get_app_dir()) / "bad.kgvault")
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({"salt": "00", "data": "00"}), encoding="utf-8")
    with pytest.raises(storage_module.VaultError) as exc:
        storage_module.load_vault(path, "secret")
    assert exc.value.reason == "unsupported_format"


def test_is_vault_file_true_for_v3(storage_module):
    path = str(Path(storage_module.get_app_dir()) / "v.kgvault")
    _make_vault(storage_module, path, "secret", [])
    assert storage_module.is_vault_file(path) is True


def test_is_vault_file_false_for_legacy_json(storage_module):
    p = Path(storage_module.get_app_dir()) / "passwords.json"
    p.write_text(json.dumps({"salt": "00", "data": "00"}), encoding="utf-8")
    assert storage_module.is_vault_file(str(p)) is False


def test_create_new_vault_writes_valid_v3(storage_module):
    path = str(Path(storage_module.get_app_dir()) / "new.kgvault")
    key, salt, kdf_spec = storage_module.create_new_vault(path, "master")
    assert storage_module.is_vault_file(path) is True
    entries, prefs, k2, s2, kdf2, trash = storage_module.load_vault(path, "master")
    assert entries == []
    assert prefs == storage_module.DEFAULT_PREFERENCES
    assert k2 == key
    assert trash == []


def test_migrate_legacy_passwords_json_to_v3(storage_module):
    legacy_pw = Path(storage_module.LEGACY_DATA_PASSWORDS_FILE)
    legacy_pw.parent.mkdir(parents=True, exist_ok=True)
    salt = crypto_utils.generate_salt()
    key = crypto_utils.derive_key("secret", salt)
    from cryptography.fernet import Fernet
    enc = Fernet(key).encrypt(json.dumps([{"name": "old", "password": "p"}]).encode()).hex()
    legacy_pw.write_text(json.dumps({"salt": salt.hex(), "data": enc}), encoding="utf-8")

    legacy_cfg = Path(storage_module.LEGACY_DATA_CONFIG_FILE)
    legacy_cfg.write_text(
        json.dumps({"language": "en", "auto_lock_minutes": 5, "column_widths": [50]}),
        encoding="utf-8",
    )

    target = str(Path(storage_module.get_app_dir()) / "migrated.kgvault")
    new_key, new_salt, new_kdf = storage_module.migrate_legacy_passwords_json(
        str(legacy_pw), str(legacy_cfg), target, "secret"
    )

    entries, prefs, k2, s2, kdf2, trash = storage_module.load_vault(target, "secret")
    assert entries[0]["name"] == "old"
    assert prefs["language"] == "en"
    assert prefs["auto_lock_minutes"] == 5
    assert kdf2["algorithm"] == "argon2id"
    assert k2 == new_key
    assert trash == []
    # 旧文件改名 .bak
    assert not legacy_pw.exists()
    assert Path(str(legacy_pw) + ".bak").exists()


def test_migrate_legacy_wrong_password_raises(storage_module):
    legacy_pw = Path(storage_module.LEGACY_DATA_PASSWORDS_FILE)
    legacy_pw.parent.mkdir(parents=True, exist_ok=True)
    salt = crypto_utils.generate_salt()
    key = crypto_utils.derive_key("secret", salt)
    from cryptography.fernet import Fernet
    enc = Fernet(key).encrypt(json.dumps([]).encode()).hex()
    legacy_pw.write_text(json.dumps({"salt": salt.hex(), "data": enc}), encoding="utf-8")

    target = str(Path(storage_module.get_app_dir()) / "migrated.kgvault")
    with pytest.raises(storage_module.VaultError) as exc:
        storage_module.migrate_legacy_passwords_json(str(legacy_pw), None, target, "wrong")
    assert exc.value.reason == "wrong_password"
    assert legacy_pw.exists()
    assert not Path(target).exists()


def test_scan_vaults_in_dir_empty(storage_module):
    d = Path(storage_module.get_app_dir())
    assert storage_module.scan_vaults_in_dir(str(d)) == []


def test_scan_vaults_in_dir_finds_vaults(storage_module):
    d = Path(storage_module.get_app_dir())
    p1 = str(d / "a.kgvault")
    p2 = str(d / "b.kgvault")
    _make_vault(storage_module, p1, "s", [])
    _make_vault(storage_module, p2, "s", [])
    found = storage_module.scan_vaults_in_dir(str(d))
    assert len(found) == 2
    assert p1 in found and p2 in found


def test_scan_vaults_in_dir_ignores_non_kgvault(storage_module):
    d = Path(storage_module.get_app_dir())
    p1 = str(d / "real.kgvault")
    _make_vault(storage_module, p1, "s", [])
    (d / "fake.kgvault").write_text(json.dumps({"not": "a vault"}), encoding="utf-8")
    found = storage_module.scan_vaults_in_dir(str(d))
    assert len(found) == 1
    assert found[0] == p1


def test_detect_legacy_passwords_json_returns_none_when_clean(storage_module):
    assert storage_module.detect_legacy_passwords_json() is None


def test_detect_legacy_passwords_json_finds_data(storage_module):
    legacy_pw = Path(storage_module.LEGACY_DATA_PASSWORDS_FILE)
    legacy_pw.parent.mkdir(parents=True, exist_ok=True)
    legacy_pw.write_text(json.dumps({"salt": "00", "data": "00"}), encoding="utf-8")
    result = storage_module.detect_legacy_passwords_json()
    assert result is not None
    assert result["passwords"] == str(legacy_pw)


def test_cleanup_legacy_data_dir_removes_data_dir(storage_module):
    data_dir = Path(storage_module.LEGACY_DATA_DIR)
    data_dir.mkdir(parents=True, exist_ok=True)
    Path(storage_module.LEGACY_DATA_CONFIG_FILE).write_text("{}", encoding="utf-8")
    Path(storage_module.LEGACY_DATA_PASSWORDS_FILE).write_text("{}", encoding="utf-8")
    storage_module.cleanup_legacy_data_dir()
    assert not data_dir.exists()


def test_cleanup_legacy_root_files_removes_root_files(storage_module):
    Path(storage_module.LEGACY_ROOT_CONFIG_FILE).write_text("{}", encoding="utf-8")
    Path(storage_module.LEGACY_ROOT_PASSWORDS_FILE).write_text("{}", encoding="utf-8")
    Path(storage_module.LEGACY_ROOT_BACKUP_DIR).mkdir(parents=True, exist_ok=True)
    (Path(storage_module.LEGACY_ROOT_BACKUP_DIR) / "x.json").write_text("{}", encoding="utf-8")
    storage_module.cleanup_legacy_root_files()
    assert not Path(storage_module.LEGACY_ROOT_CONFIG_FILE).exists()
    assert not Path(storage_module.LEGACY_ROOT_PASSWORDS_FILE).exists()
    assert not Path(storage_module.LEGACY_ROOT_BACKUP_DIR).exists()


def test_ensure_entry_ids_generates_for_missing(storage_module):
    entries = [{"name": "a"}, {"name": "b", "id": "preset"}]
    out, changed = storage_module.ensure_entry_ids(entries)
    assert changed is True
    assert out[0]["id"]  # 自动生成
    assert out[1]["id"] == "preset"  # 已有保留


def test_ensure_entry_ids_preserves_existing(storage_module):
    entries = [{"name": "a", "id": "keep1"}, {"name": "b", "id": "keep2"}]
    out, changed = storage_module.ensure_entry_ids(entries)
    assert changed is False
    assert out[0]["id"] == "keep1"
    assert out[1]["id"] == "keep2"


def test_write_error_log_contains_diagnostics_without_vault_data(storage_module, monkeypatch, tmp_path):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    log_path = storage_module.write_error_log(
        "close_save", OSError("disk full"), vault_path="D:/vault.kgvault"
    )

    content = Path(log_path).read_text(encoding="utf-8")
    assert "close_save" in content
    assert "disk full" in content
    assert "D:/vault.kgvault" in content
    assert "password" not in content.lower()


def test_load_vault_ignores_existing_snapshots_field(storage_module):
    """旧 vault 中含有 snapshots 数组时，load_vault 正常忽略它并解密 entries。"""
    path = str(Path(storage_module.get_app_dir()) / "old_vault.kgvault")
    key, salt, kdf_spec = _make_vault(storage_module, path, "secret", [{"name": "v1"}])
    with open(path, "r", encoding="utf-8") as f:
        container = json.load(f)
    container["snapshots"] = [{"timestamp": "2026-01-01 00:00:00", "data": "dummy"}]
    with open(path, "w", encoding="utf-8") as f:
        json.dump(container, f)
    entries, prefs, k2, s2, kdf2, trash = storage_module.load_vault(path, "secret")
    assert entries[0]["name"] == "v1"
    assert k2 == key


def test_save_vault_atomic_in_place(storage_module):
    """保存 vault 直接原子替换原文件路径。"""
    path = str(Path(storage_module.get_app_dir()) / "test.kgvault")
    key, salt, kdf_spec = _make_vault(storage_module, path, "secret", [{"name": "item1"}])
    assert Path(path).exists()
    # 再次保存
    storage_module.save_vault(path, [{"name": "item2"}], {}, key, salt, kdf_spec)
    entries, _, _, _, _, _ = storage_module.load_vault(path, "secret")
    assert len(entries) == 1
    assert entries[0]["name"] == "item2"


def test_migrate_legacy_generates_entry_ids(storage_module):
    legacy_pw = Path(storage_module.LEGACY_DATA_PASSWORDS_FILE)
    legacy_pw.parent.mkdir(parents=True, exist_ok=True)
    salt = crypto_utils.generate_salt()
    key = crypto_utils.derive_key("secret", salt)
    from cryptography.fernet import Fernet
    enc = Fernet(key).encrypt(json.dumps([{"name": "old", "password": "p"}]).encode()).hex()
    legacy_pw.write_text(json.dumps({"salt": salt.hex(), "data": enc}), encoding="utf-8")

    target = str(Path(storage_module.get_app_dir()) / "migrated.kgvault")
    storage_module.migrate_legacy_passwords_json(str(legacy_pw), None, target, "secret")
    entries, prefs, k, s, kdf, trash = storage_module.load_vault(target, "secret")
    assert entries[0]["id"]  # 迁移后应有 id
    assert trash == []


def test_save_and_load_vault_trash_roundtrip(storage_module):
    """回收站条目加密保存与解密恢复往返测试。"""
    path = str(Path(storage_module.get_app_dir()) / "trash_test.kgvault")
    salt = crypto_utils.generate_salt()
    kdf_spec = storage_module._argon2_kdf_spec(salt)
    key = crypto_utils.derive_key_for_kdf("pass123", salt, kdf_spec)

    active_entries = [{"name": "active1", "username": "user1"}]
    trash_entries = [
        {"name": "deleted1", "username": "duser1", "deleted_at": "2026-11-07 10:00:00"}
    ]

    storage_module.save_vault(
        path,
        active_entries,
        {"language": "zh"},
        key,
        salt,
        kdf_spec,
        trash=trash_entries,
    )

    loaded_entries, prefs, k2, s2, kdf2, loaded_trash = storage_module.load_vault(path, "pass123")
    assert len(loaded_entries) == 1
    assert loaded_entries[0]["name"] == "active1"
    assert len(loaded_trash) == 1
    assert loaded_trash[0]["name"] == "deleted1"
    assert loaded_trash[0]["username"] == "duser1"
    assert loaded_trash[0]["deleted_at"] == "2026-11-07 10:00:00"
    assert loaded_trash[0]["category"] == "other"


def test_normalize_entries_populates_updated_at(storage_module):
    """验证老条目缺少 updated_at 时，自动从 password_history 恢复或补空。"""
    entries = [
        {"name": "e1", "password_history": [{"date": "2026-01-01 12:00:00", "password": "old"}]},
        {"name": "e2"},
    ]
    normalized = storage_module._normalize_entries(entries)
    assert normalized[0]["updated_at"] == "2026-01-01 12:00:00"
    assert normalized[1]["updated_at"] == ""
