from types import MethodType, SimpleNamespace

import main


def _entry(**overrides):
    entry = {
        "id": "entry-1",
        "name": "old name",
        "url": "https://old.example",
        "username": "old-user",
        "password": "old-password",
        "category": "website",
        "notes": "old notes",
        "password_history": [],
    }
    entry.update(overrides)
    return entry


def _window_stub(passwords, snapshots=None):
    window = SimpleNamespace(
        vault_path="vault.kgvault",
        passwords=passwords,
        preferences={},
        master_key=b"key",
        master_salt=b"salt",
        kdf_spec={},
        snapshots=snapshots if snapshots is not None else [{}],
        _dirty=True,
        _viewing_snapshot=False,
        _latest_cache=None,
        _latest_changes={"stale": ["name"]},
        _current_changes={"stale": ["name"]},
        _snapshot_session_baseline=([], {}),
    )
    window._recompute_latest_changes = MethodType(
        main.MainWindow._recompute_latest_changes, window
    )
    window._entries_for_latest = MethodType(
        main.MainWindow._entries_for_latest, window
    )
    return window


def test_recompute_latest_changes_is_cumulative_and_clears_reverted_fields(monkeypatch):
    baseline = _entry()
    current = _entry(name="new name", notes="new notes")
    window = _window_stub([current])
    monkeypatch.setattr(
        main.storage, "load_snapshot", lambda path, index, key: ([baseline], {}, {})
    )

    window._recompute_latest_changes()
    assert window._latest_changes == {"entry-1": ["name", "notes"]}
    assert window._current_changes == window._latest_changes

    current["name"] = baseline["name"]
    window._recompute_latest_changes()
    assert window._latest_changes == {"entry-1": ["notes"]}


def test_recompute_latest_changes_ignores_password_history(monkeypatch):
    baseline = _entry()
    current = _entry(
        password="new-password",
        password_history=[{"password": "old-password", "date": "2026-07-20"}],
    )
    window = _window_stub([current])
    monkeypatch.setattr(
        main.storage, "load_snapshot", lambda path, index, key: ([baseline], {}, {})
    )

    window._recompute_latest_changes()
    assert window._latest_changes == {"entry-1": ["password"]}


def test_recompute_latest_changes_without_snapshot_clears_stale_state():
    window = _window_stub([_entry(name="new name")], snapshots=[])

    window._recompute_latest_changes()
    assert window._latest_changes == {}
    assert window._current_changes == {}


def test_recompute_latest_changes_does_not_replace_historical_view(monkeypatch):
    baseline = _entry()
    window = _window_stub([_entry(name="new name")])
    historical_changes = {"entry-1": ["url"]}
    window._viewing_snapshot = True
    window._latest_cache = [_entry(name="new name")]
    window._current_changes = historical_changes
    monkeypatch.setattr(
        main.storage, "load_snapshot", lambda path, index, key: ([baseline], {}, {})
    )

    window._recompute_latest_changes()
    assert window._latest_changes == {"entry-1": ["name"]}
    assert window._current_changes is historical_changes


def test_save_and_refresh_recomputes_before_refresh(monkeypatch):
    baseline = _entry()
    window = _window_stub([_entry(name="new name")])
    events = []
    monkeypatch.setattr(
        main.storage, "save_vault", lambda *args, **kwargs: events.append("save")
    )
    monkeypatch.setattr(
        main.storage,
        "load_snapshot",
        lambda path, index, key: (events.append("recompute") or [baseline], {}, {}),
    )
    window.refresh_table = lambda: events.append("refresh")

    assert main.MainWindow.save_and_refresh(window) is True
    assert window._latest_changes == {"entry-1": ["name"]}
    assert events == ["save", "recompute", "refresh"]


def test_save_failure_does_not_publish_new_change_state(monkeypatch):
    window = _window_stub([_entry(name="new name")])

    def fail_save(*args, **kwargs):
        raise OSError("save failed")

    monkeypatch.setattr(
        main.storage,
        "save_vault",
        fail_save,
    )
    monkeypatch.setattr(main.MsgBox, "critical", lambda *args, **kwargs: None)
    window.refresh_table = lambda: None

    assert main.MainWindow.save_and_refresh(window) is False
    assert window._latest_changes == {"stale": ["name"]}
    assert window._current_changes == {"stale": ["name"]}


def test_settings_save_uses_latest_entries_while_viewing_history(monkeypatch):
    latest_entries = [_entry(name="latest")]
    historical_entries = [_entry(name="historical")]
    window = _window_stub(historical_entries)
    window._viewing_snapshot = True
    window._latest_cache = latest_entries
    saved_entries = []
    monkeypatch.setattr(
        main.storage,
        "save_vault",
        lambda path, entries, *args, **kwargs: saved_entries.extend(entries),
    )

    assert main.MainWindow._write_vault(window) is True
    assert saved_entries[0]["name"] == "latest"


def test_close_without_actual_changes_does_not_append_snapshot(monkeypatch):
    window = _window_stub([_entry()])
    window.table = SimpleNamespace(columnWidth=lambda index: 100)
    event = SimpleNamespace(accepted=False, ignored=False)
    event.accept = lambda: setattr(event, "accepted", True)
    event.ignore = lambda: setattr(event, "ignored", True)
    monkeypatch.setattr(main.storage, "snapshot_matches", lambda *args: True)
    monkeypatch.setattr(
        main.storage,
        "append_snapshot",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("snapshot should not be appended")
        ),
    )

    main.MainWindow.closeEvent(window, event)
    assert event.accepted is True
    assert event.ignored is False


def test_close_save_failure_keeps_window_open_and_reports_recovery(monkeypatch):
    window = _window_stub([_entry(name="new name")], snapshots=[])
    window._snapshot_session_baseline = ([_entry()], {})
    window.table = SimpleNamespace(columnWidth=lambda index: 100)
    event = SimpleNamespace(accepted=False, ignored=False)
    event.accept = lambda: setattr(event, "accepted", True)
    event.ignore = lambda: setattr(event, "ignored", True)
    messages = []
    failure = main.storage.PasswordSaveError(
        "write_failed", detail="disk full", recovery_path="vault.recovery"
    )
    monkeypatch.setattr(
        main.storage, "append_snapshot", lambda *args, **kwargs: [{}]
    )
    monkeypatch.setattr(
        main.storage,
        "save_vault",
        lambda *args, **kwargs: (_ for _ in ()).throw(failure),
    )
    monkeypatch.setattr(
        main.storage, "write_error_log", lambda *args, **kwargs: "keyguard.log"
    )
    monkeypatch.setattr(
        main.MsgBox, "critical", lambda *args: messages.append(args[-1])
    )

    main.MainWindow.closeEvent(window, event)
    assert event.accepted is False
    assert event.ignored is True
    assert "vault.recovery" in messages[0]
    assert "disk full" in messages[0]


def test_change_master_password_commits_key_only_after_success(monkeypatch):
    old_key = b"old-key"
    old_salt = b"old-salt"
    old_kdf = {"algorithm": "argon2id", "salt": old_salt.hex(), "params": {}}
    new_key = b"new-key"
    new_salt = b"new-salt"
    new_kdf = {"algorithm": "argon2id", "salt": new_salt.hex(), "params": {}}
    new_snapshots = [{"timestamp": "t", "data": "encrypted", "change": {}}]
    window = _window_stub([_entry()])
    window.master_key = old_key
    window.master_salt = old_salt
    window.kdf_spec = old_kdf
    window.reset_idle_timer = lambda: None
    window._recompute_latest_changes = lambda *args: None
    window.refresh_table = lambda: None

    class DialogStub:
        def __init__(self, key, salt, kdf_spec, parent):
            assert (key, salt, kdf_spec, parent) == (old_key, old_salt, old_kdf, window)

        def exec(self):
            return True

        def get_new_password(self):
            return "new password"

    monkeypatch.setattr(main, "ChangePasswordDialog", DialogStub)
    monkeypatch.setattr(main.crypto_utils, "generate_salt", lambda: new_salt)
    monkeypatch.setattr(main.storage, "_argon2_kdf_spec", lambda salt: new_kdf)
    monkeypatch.setattr(main.crypto_utils, "derive_key_for_kdf", lambda *args: new_key)
    monkeypatch.setattr(main.storage, "reencrypt_snapshots", lambda *args: new_snapshots)
    monkeypatch.setattr(main.storage, "save_vault", lambda *args, **kwargs: None)
    monkeypatch.setattr(main.MsgBox, "information", lambda *args: None)

    main.MainWindow.change_master_password(window)
    assert window.master_key == new_key
    assert window.master_salt == new_salt
    assert window.kdf_spec == new_kdf
    assert window.snapshots == new_snapshots


def test_save_and_refresh_refuses_while_viewing_snapshot(monkeypatch):
    historical_entries = [_entry(name="historical")]
    window = _window_stub(historical_entries)
    window._viewing_snapshot = True
    window._latest_cache = [_entry(name="latest")]

    saved = []
    monkeypatch.setattr(
        main.storage, "save_vault", lambda *args, **kwargs: saved.append(args)
    )

    assert main.MainWindow.save_and_refresh(window) is False
    assert len(saved) == 0


def test_modifying_actions_blocked_while_viewing_snapshot(monkeypatch):
    window = _window_stub([_entry(name="historical")])
    window._viewing_snapshot = True
    window.reset_idle_timer = lambda: None

    monkeypatch.setattr(
        main,
        "EntryDialog",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("EntryDialog opened")),
    )
    monkeypatch.setattr(
        main,
        "QDialog",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("QDialog opened")),
    )
    monkeypatch.setattr(
        main,
        "QMenu",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("QMenu opened")),
    )
    monkeypatch.setattr(
        main.MsgBox,
        "question",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("MsgBox opened")),
    )

    main.MainWindow.add_entry(window)
    main.MainWindow.edit_entry(window)
    main.MainWindow.delete_entry(window)
    main.MainWindow.import_data(window)
    main.MainWindow.show_context_menu(window, SimpleNamespace(y=lambda: 0))


def test_set_readonly_toggles_shortcuts_and_buttons():
    class DummyWidget:
        def __init__(self):
            self.enabled = None

        def setEnabled(self, val):
            self.enabled = val

    class DummyTable:
        def setEditTriggers(self, val):
            self.triggers = val

    window = SimpleNamespace(
        table=DummyTable(),
        add_btn=DummyWidget(),
        delete_btn=DummyWidget(),
        import_btn=DummyWidget(),
        add_shortcut=DummyWidget(),
        delete_shortcut=DummyWidget(),
    )

    main.MainWindow._set_readonly(window, True)
    assert window.add_btn.enabled is False
    assert window.delete_btn.enabled is False
    assert window.import_btn.enabled is False
    assert window.add_shortcut.enabled is False
    assert window.delete_shortcut.enabled is False

    main.MainWindow._set_readonly(window, False)
    assert window.add_btn.enabled is True
    assert window.delete_btn.enabled is True
    assert window.import_btn.enabled is True
    assert window.add_shortcut.enabled is True
    assert window.delete_shortcut.enabled is True
