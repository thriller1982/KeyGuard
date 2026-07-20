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
        key, salt, kdf_spec, snapshots=[]
    )
    return key, salt, kdf_spec


def test_save_and_load_vault_v3_roundtrip(storage_module):
    path = str(Path(storage_module.get_app_dir()) / "v.kgvault")
    key, salt, kdf_spec = _make_vault(
        storage_module, path, "secret", [{"name": "demo", "password": "v"}],
        prefs={"language": "en", "column_widths": [80, 90]},
    )
    entries, prefs, k2, s2, kdf2, snaps = storage_module.load_vault(path, "secret")
    assert entries[0]["name"] == "demo"
    assert entries[0]["category"] == "other"
    assert k2 == key and s2 == salt
    assert kdf2["algorithm"] == "argon2id"
    assert prefs["language"] == "en"
    assert prefs["column_widths"] == [80, 90]
    assert snaps == []


def test_vault_version_is_3(storage_module):
    path = str(Path(storage_module.get_app_dir()) / "v.kgvault")
    _make_vault(storage_module, path, "secret", [])
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    assert raw["magic"] == storage_module.VAULT_MAGIC
    assert raw["version"] == 3
    assert "snapshots" in raw
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
    entries, prefs, k2, s2, kdf2, snaps = storage_module.load_vault_by_key(path, key)
    assert entries[0]["name"] == "x"
    assert k2 == key and s2 == salt and kdf2 == kdf_spec


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
    entries, prefs, k2, s2, kdf2, snaps = storage_module.load_vault(path, "master")
    assert entries == []
    assert prefs == storage_module.DEFAULT_PREFERENCES
    assert snaps == []
    assert k2 == key


def test_append_snapshot_and_load_snapshot_roundtrip(storage_module):
    path = str(Path(storage_module.get_app_dir()) / "v.kgvault")
    key, salt, kdf_spec = _make_vault(
        storage_module, path, "secret", [{"name": "v1", "password": "1"}]
    )
    ts = "2026-07-20 10:00:00"
    snapshots = storage_module.append_snapshot([], [{"name": "v1", "password": "1"}], {}, key, ts)
    storage_module.save_vault(
        path, [{"name": "v2", "password": "2"}], {}, key, salt, kdf_spec, snapshots=snapshots
    )

    _, _, _, _, _, snaps_loaded = storage_module.load_vault(path, "secret")
    assert len(snaps_loaded) == 1
    assert snaps_loaded[0]["timestamp"] == ts

    entries, prefs, change = storage_module.load_snapshot(path, 0, key)
    assert entries[0]["name"] == "v1"


def test_append_snapshot_rotates_to_limit(storage_module):
    salt = crypto_utils.generate_salt()
    key = crypto_utils.derive_key_argon2id("pw", salt)
    snapshots = []
    for i in range(storage_module.SNAPSHOT_LIMIT + 5):
        snapshots = storage_module.append_snapshot(
            snapshots, [{"name": f"v{i}"}], {}, key, f"2026-07-20 10:0{i}:00",
        )
    assert len(snapshots) == storage_module.SNAPSHOT_LIMIT


def test_append_snapshot_most_recent_first(storage_module):
    salt = crypto_utils.generate_salt()
    key = crypto_utils.derive_key_argon2id("pw", salt)
    snapshots = []
    snapshots = storage_module.append_snapshot(snapshots, [{"name": "old"}], {}, key, "2026-01-01 00:00:00")
    snapshots = storage_module.append_snapshot(snapshots, [{"name": "new"}], {}, key, "2026-01-02 00:00:00")
    assert len(snapshots) == 2
    assert snapshots[0]["timestamp"] == "2026-01-02 00:00:00"
    assert snapshots[1]["timestamp"] == "2026-01-01 00:00:00"


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

    entries, prefs, k2, s2, kdf2, snaps = storage_module.load_vault(target, "secret")
    assert entries[0]["name"] == "old"
    assert prefs["language"] == "en"
    assert prefs["auto_lock_minutes"] == 5
    assert kdf2["algorithm"] == "argon2id"
    assert k2 == new_key
    assert snaps == []
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


def test_compute_closed_vault_path_format(storage_module):
    base = str(Path(storage_module.get_app_dir()) / "KeyGuard.kgvault")
    closed = storage_module.compute_closed_vault_path(base, "20260720_164500")
    assert closed.endswith("KeyGuard_20260720_164500.kgvault")
    assert Path(closed).parent == Path(base).parent


def test_remove_previous_managed_vault_only_removes_explicit_previous(storage_module):
    d = Path(storage_module.get_app_dir())
    keep = str(d / "KeyGuard_20260720_164500.kgvault")
    old1 = str(d / "KeyGuard_20260720_100000.kgvault")
    old2 = str(d / "KeyGuard.kgvault")
    _make_vault(storage_module, keep, "s", [])
    _make_vault(storage_module, old1, "s", [])
    _make_vault(storage_module, old2, "s", [])

    assert storage_module.remove_previous_managed_vault(old1, keep) is True
    assert Path(keep).exists()
    assert not Path(old1).exists()
    assert Path(old2).exists()


def test_remove_previous_managed_vault_preserves_user_named_file(storage_module):
    d = Path(storage_module.get_app_dir())
    keep = str(d / "KeyGuard_20260720_164500.kgvault")
    user_file = str(d / "personal.kgvault")
    _make_vault(storage_module, keep, "s", [])
    _make_vault(storage_module, user_file, "s", [])

    assert storage_module.remove_previous_managed_vault(user_file, keep) is False
    assert Path(user_file).exists()


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


def test_compute_changes_field_modified(storage_module):
    prev = [{"id": "x", "name": "old", "url": "a.com", "username": "u", "password": "p", "category": "website", "notes": "n"}]
    curr = [{"id": "x", "name": "new", "url": "a.com", "username": "u", "password": "p", "category": "website", "notes": "n"}]
    change = storage_module.compute_changes(prev, curr)
    assert change == {"x": ["name"]}


def test_compute_changes_multiple_fields(storage_module):
    prev = [{"id": "x", "name": "old", "url": "a.com", "username": "u", "password": "p", "category": "website", "notes": "n"}]
    curr = [{"id": "x", "name": "new", "url": "b.com", "username": "u", "password": "p", "category": "website", "notes": "n"}]
    change = storage_module.compute_changes(prev, curr)
    assert change == {"x": ["name", "url"]}


def test_compute_changes_added_entry_not_in_change(storage_module):
    prev = [{"id": "x", "name": "a", "url": "", "username": "", "password": "", "category": "other", "notes": ""}]
    curr = [
        {"id": "x", "name": "a", "url": "", "username": "", "password": "", "category": "other", "notes": ""},
        {"id": "y", "name": "new", "url": "", "username": "", "password": "", "category": "other", "notes": ""},
    ]
    change = storage_module.compute_changes(prev, curr)
    assert "y" not in change  # 新增条目不在 change 中
    assert change == {}


def test_compute_changes_deleted_entry_ignored(storage_module):
    prev = [
        {"id": "x", "name": "a", "url": "", "username": "", "password": "", "category": "other", "notes": ""},
        {"id": "y", "name": "b", "url": "", "username": "", "password": "", "category": "other", "notes": ""},
    ]
    curr = [{"id": "x", "name": "a", "url": "", "username": "", "password": "", "category": "other", "notes": ""}]
    change = storage_module.compute_changes(prev, curr)
    assert change == {}  # 删除的条目 y 不计入


def test_compute_changes_password_history_ignored(storage_module):
    prev = [{"id": "x", "name": "a", "url": "", "username": "", "password": "p1", "category": "other", "notes": "", "password_history": []}]
    curr = [{"id": "x", "name": "a", "url": "", "username": "", "password": "p1", "category": "other", "notes": "", "password_history": [{"password": "p0", "date": "2026"}]}]
    change = storage_module.compute_changes(prev, curr)
    assert change == {}  # password_history 变化不计入


def test_compute_changes_no_change_returns_empty(storage_module):
    prev = [{"id": "x", "name": "a", "url": "b", "username": "u", "password": "p", "category": "website", "notes": "n"}]
    curr = [{"id": "x", "name": "a", "url": "b", "username": "u", "password": "p", "category": "website", "notes": "n"}]
    change = storage_module.compute_changes(prev, curr)
    assert change == {}


def test_append_snapshot_with_change(storage_module):
    salt = crypto_utils.generate_salt()
    key = crypto_utils.derive_key_argon2id("pw", salt)
    change = {"x": ["name", "url"]}
    snapshots = storage_module.append_snapshot([], [{"name": "a"}], {}, key, "2026-01-01 00:00:00", change=change)
    assert snapshots[0]["change"] == change
    assert "change" in snapshots[0]


def test_append_snapshot_without_change_defaults_empty(storage_module):
    salt = crypto_utils.generate_salt()
    key = crypto_utils.derive_key_argon2id("pw", salt)
    snapshots = storage_module.append_snapshot([], [{"name": "a"}], {}, key, "2026-01-01 00:00:00")
    assert snapshots[0]["change"] == {}


def test_load_snapshot_returns_change(storage_module):
    path = str(Path(storage_module.get_app_dir()) / "v.kgvault")
    key, salt, kdf_spec = _make_vault(storage_module, path, "secret", [{"name": "v1", "password": "1"}])
    change = {"abc": ["name"]}
    snapshots = storage_module.append_snapshot([], [{"name": "v1"}], {}, key, "2026-01-01 00:00:00", change=change)
    storage_module.save_vault(path, [{"name": "v2"}], {}, key, salt, kdf_spec, snapshots=snapshots)
    entries, prefs, loaded_change = storage_module.load_snapshot(path, 0, key)
    assert entries[0]["name"] == "v1"
    assert loaded_change == change


def test_save_vault_without_snapshots_argument_preserves_history(storage_module):
    path = str(Path(storage_module.get_app_dir()) / "v.kgvault")
    key, salt, kdf_spec = _make_vault(storage_module, path, "secret", [{"id": "x", "name": "v1"}])
    snapshots = storage_module.append_snapshot(
        [], [{"id": "x", "name": "v1"}], {}, key, "2026-01-01 00:00:00"
    )
    storage_module.save_vault(
        path, [{"id": "x", "name": "v2"}], {}, key, salt, kdf_spec, snapshots=snapshots
    )

    storage_module.save_vault(
        path, [{"id": "x", "name": "v3"}], {}, key, salt, kdf_spec
    )
    _, _, _, _, _, loaded_snapshots = storage_module.load_vault(path, "secret")
    assert len(loaded_snapshots) == 1
    entries, _, _ = storage_module.load_snapshot(path, 0, key)
    assert entries[0]["name"] == "v1"


def test_reencrypt_snapshots_switches_key_and_preserves_change(storage_module):
    old_salt = crypto_utils.generate_salt()
    old_key = crypto_utils.derive_key_argon2id("old", old_salt)
    new_salt = crypto_utils.generate_salt()
    new_key = crypto_utils.derive_key_argon2id("new", new_salt)
    change = {"x": ["name"]}
    snapshots = storage_module.append_snapshot(
        [], [{"id": "x", "name": "v1"}], {}, old_key,
        "2026-01-01 00:00:00", change=change,
    )

    converted = storage_module.reencrypt_snapshots(snapshots, old_key, new_key)
    assert converted[0]["change"] == change
    payload = storage_module._decrypt_payload(converted[0]["data"], new_key)
    assert payload["entries"][0]["name"] == "v1"
    with pytest.raises(storage_module.VaultError):
        storage_module._decrypt_payload(converted[0]["data"], old_key)


def test_snapshot_matches_detects_content_and_preference_changes(storage_module):
    salt = crypto_utils.generate_salt()
    key = crypto_utils.derive_key_argon2id("pw", salt)
    entries = [{"id": "x", "name": "v1"}]
    preferences = {"language": "zh", "auto_lock_minutes": 0, "column_widths": []}
    snapshot = storage_module.append_snapshot(
        [], entries, preferences, key, "2026-01-01 00:00:00"
    )[0]

    assert storage_module.snapshot_matches(snapshot, entries, preferences, key) is True
    assert storage_module.snapshot_matches(
        snapshot, [{"id": "x", "name": "v2"}], preferences, key
    ) is False
    assert storage_module.snapshot_matches(
        snapshot, entries, {**preferences, "language": "en"}, key
    ) is False


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


def test_load_snapshot_legacy_without_change_returns_empty(storage_module):
    """旧快照无 change 字段时返回空 dict，兼容。"""
    path = str(Path(storage_module.get_app_dir()) / "v.kgvault")
    key, salt, kdf_spec = _make_vault(storage_module, path, "secret", [])
    # 手工构造无 change 字段的快照
    from cryptography.fernet import Fernet
    import json as _json
    enc = Fernet(key).encrypt(_json.dumps({"entries": [], "preferences": {}}).encode()).hex()
    raw_snap = {"timestamp": "2026-01-01 00:00:00", "data": enc}  # 无 change
    with open(path, "r", encoding="utf-8") as f:
        container = _json.load(f)
    container["snapshots"] = [raw_snap]
    with open(path, "w", encoding="utf-8") as f:
        _json.dump(container, f)
    entries, prefs, loaded_change = storage_module.load_snapshot(path, 0, key)
    assert loaded_change == {}


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
    entries, prefs, k, s, kdf, snaps = storage_module.load_vault(target, "secret")
    assert entries[0]["id"]  # 迁移后应有 id
