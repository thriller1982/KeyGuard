import importlib
import json
from pathlib import Path

import pytest


@pytest.fixture
def storage_module(monkeypatch, tmp_path):
    module = importlib.import_module("storage")
    monkeypatch.setattr(module, "get_app_dir", lambda: str(tmp_path))
    monkeypatch.setattr(module, "DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setattr(module, "CONFIG_FILE", str(tmp_path / "data" / "config.json"))
    monkeypatch.setattr(module, "PASSWORDS_FILE", str(tmp_path / "data" / "passwords.json"))
    monkeypatch.setattr(module, "BACKUP_DIR", str(tmp_path / "data" / "backups"))
    monkeypatch.setattr(module, "LEGACY_CONFIG_FILE", str(tmp_path / "config.json"))
    monkeypatch.setattr(module, "LEGACY_PASSWORDS_FILE", str(tmp_path / "passwords.json"))
    monkeypatch.setattr(module, "LEGACY_BACKUP_DIR", str(tmp_path / "backups"))
    return module


def test_save_and_load_passwords_roundtrip(storage_module):
    salt = storage_module.crypto_utils.generate_salt()
    key = storage_module.crypto_utils.derive_key("secret", salt)
    passwords = [{"name": "demo", "password": "value"}]

    storage_module.save_passwords(passwords, key, salt)
    loaded, loaded_key, loaded_salt = storage_module.load_passwords("secret")

    assert loaded[0]["name"] == "demo"
    assert loaded[0]["category"] == "other"
    assert loaded_key == key
    assert loaded_salt == salt


def test_load_passwords_with_wrong_password_raises(storage_module):
    salt = storage_module.crypto_utils.generate_salt()
    key = storage_module.crypto_utils.derive_key("secret", salt)
    storage_module.save_passwords([], key, salt)

    with pytest.raises(storage_module.PasswordLoadError) as exc_info:
        storage_module.load_passwords("wrong")

    assert exc_info.value.reason == "wrong_password"


def test_restore_backup_roundtrip(storage_module):
    salt = storage_module.crypto_utils.generate_salt()
    key = storage_module.crypto_utils.derive_key("secret", salt)
    storage_module.save_passwords([{"name": "one", "password": "1"}], key, salt)

    backup_path = Path(storage_module.DATA_DIR) / "backup.json"
    storage_module.create_backup(str(backup_path))
    storage_module.save_passwords([{"name": "two", "password": "2"}], key, salt)

    storage_module.restore_backup(str(backup_path), key, salt)
    loaded, _, _ = storage_module.load_passwords("secret")
    assert loaded[0]["name"] == "one"


def test_migrate_legacy_files(storage_module):
    legacy_config = Path(storage_module.LEGACY_CONFIG_FILE)
    legacy_passwords = Path(storage_module.LEGACY_PASSWORDS_FILE)
    legacy_config.write_text(json.dumps({"language": "en"}), encoding="utf-8")
    legacy_passwords.write_text(json.dumps({"salt": "00", "data": "00"}), encoding="utf-8")

    storage_module.migrate_legacy_files()

    assert Path(storage_module.CONFIG_FILE).exists()
    assert Path(storage_module.PASSWORDS_FILE).exists()
    assert not legacy_config.exists()
    assert not legacy_passwords.exists()
