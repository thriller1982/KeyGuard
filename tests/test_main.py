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


def _window_stub(passwords):
    window = SimpleNamespace(
        vault_path="vault.kgvault",
        passwords=passwords,
        trash=[],
        preferences={},
        master_key=b"key",
        master_salt=b"salt",
        kdf_spec={},
        _dirty=True,
        _last_totp_secret="",
        reset_idle_timer=lambda: None,
    )
    window._write_vault = MethodType(main.MainWindow._write_vault, window)
    window.update_trash_btn = MethodType(main.MainWindow.update_trash_btn, window)
    window.mark_dirty = MethodType(main.MainWindow.mark_dirty, window)
    return window


def test_save_and_refresh_saves_and_refreshes(monkeypatch):
    window = _window_stub([_entry(name="new name")])
    events = []
    monkeypatch.setattr(
        main.storage, "save_vault", lambda *args, **kwargs: events.append("save")
    )
    window.refresh_table = lambda: events.append("refresh")
    window.update_trash_btn = lambda: events.append("trash_btn")

    assert main.MainWindow.save_and_refresh(window) is True
    assert window._dirty is False
    assert events == ["save", "refresh", "trash_btn"]


def test_save_failure_reports_error(monkeypatch):
    window = _window_stub([_entry(name="new name")])

    def fail_save(*args, **kwargs):
        raise OSError("save failed")

    monkeypatch.setattr(main.storage, "save_vault", fail_save)
    monkeypatch.setattr(main.MsgBox, "critical", lambda *args, **kwargs: None)
    window.refresh_table = lambda: None

    assert main.MainWindow.save_and_refresh(window) is False
    assert window._dirty is True


def test_settings_save_writes_vault(monkeypatch):
    window = _window_stub([_entry(name="test")])
    saved = []
    monkeypatch.setattr(
        main.storage,
        "save_vault",
        lambda path, entries, prefs, *args, **kwargs: saved.append((entries, prefs)),
    )

    assert main.MainWindow.save_preferences(window, {"language": "en"}) is True
    assert saved[0][0][0]["name"] == "test"
    assert saved[0][1]["language"] == "en"


def test_close_without_changes_does_not_save(monkeypatch):
    window = _window_stub([_entry()])
    window._dirty = False
    window.preferences = {"column_widths": [100] * 7}
    window.table = SimpleNamespace(columnWidth=lambda index: 100)
    event = SimpleNamespace(accepted=False, ignored=False)
    event.accept = lambda: setattr(event, "accepted", True)
    event.ignore = lambda: setattr(event, "ignored", True)
    saved = []
    monkeypatch.setattr(main.storage, "save_vault", lambda *args, **kwargs: saved.append(True))

    main.MainWindow.closeEvent(window, event)
    assert event.accepted is True
    assert len(saved) == 0


def test_close_with_changes_saves_directly_to_vault_path(monkeypatch):
    window = _window_stub([_entry(name="updated")])
    window._dirty = True
    window.table = SimpleNamespace(columnWidth=lambda index: 100)
    event = SimpleNamespace(accepted=False, ignored=False)
    event.accept = lambda: setattr(event, "accepted", True)
    event.ignore = lambda: setattr(event, "ignored", True)
    saved = []
    monkeypatch.setattr(
        main.storage,
        "save_vault",
        lambda path, entries, *args, **kwargs: saved.append((path, entries)),
    )

    main.MainWindow.closeEvent(window, event)
    assert event.accepted is True
    assert saved[0][0] == "vault.kgvault"
    assert saved[0][1][0]["name"] == "updated"
    assert window._dirty is False


def test_close_save_failure_keeps_window_open_and_reports_recovery(monkeypatch):
    window = _window_stub([_entry(name="new name")])
    window._dirty = True
    window.table = SimpleNamespace(columnWidth=lambda index: 100)
    event = SimpleNamespace(accepted=False, ignored=False)
    event.accept = lambda: setattr(event, "accepted", True)
    event.ignore = lambda: setattr(event, "ignored", True)
    messages = []
    failure = main.storage.PasswordSaveError(
        "write_failed", detail="disk full", recovery_path="vault.recovery"
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
    window = _window_stub([_entry()])
    window.master_key = old_key
    window.master_salt = old_salt
    window.kdf_spec = old_kdf
    window.reset_idle_timer = lambda: None
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
    monkeypatch.setattr(main.storage, "save_vault", lambda *args, **kwargs: None)
    monkeypatch.setattr(main.MsgBox, "information", lambda *args: None)

    main.MainWindow.change_master_password(window)
    assert window.master_key == new_key
    assert window.master_salt == new_salt
    assert window.kdf_spec == new_kdf
    assert window._dirty is False


def test_drag_select_table_initial_adjust_distributes_weights():
    import sys
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication(sys.argv)
    table = main.DragSelectTableWidget(0, 7)
    table.resize(800, 400)
    table.adjust_column_widths(700)
    widths = [table.columnWidth(i) for i in range(7)]
    assert sum(widths) == 700
    assert widths[1] > widths[0]
    assert widths[1] > widths[3]


def test_drag_select_table_proportional_resizing():
    import sys
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication(sys.argv)
    table = main.DragSelectTableWidget(0, 7)
    table.adjust_column_widths(700)
    initial_widths = [table.columnWidth(i) for i in range(7)]

    table.adjust_column_widths(1400)
    larger_widths = [table.columnWidth(i) for i in range(7)]
    assert sum(larger_widths) == 1400
    for init_w, large_w in zip(initial_widths, larger_widths):
        assert abs(large_w - init_w * 2) <= 2


def test_drag_select_table_respects_minimum_widths():
    import sys
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication(sys.argv)
    table = main.DragSelectTableWidget(0, 7)
    table.adjust_column_widths(300)
    widths = [table.columnWidth(i) for i in range(7)]
    assert widths == main.DragSelectTableWidget.MIN_COLUMN_WIDTHS


def test_totp_button_alignment_under_generator(monkeypatch):
    import sys
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication(sys.argv)
    monkeypatch.setattr(main.storage, "save_vault", lambda *args, **kwargs: None)
    monkeypatch.setattr(main.MainWindow, "closeEvent", lambda self, event: event.accept())

    win = main.MainWindow("vault.kgvault", [], {}, b"k" * 32, b"s" * 16, {})
    win.show()
    app.processEvents()

    gen = win.gen_tool_btn
    totp = win.totp_btn
    assert gen.x() == totp.x()
    assert gen.width() == totp.width()
    assert totp.y() > gen.y()
    win.hide()


def test_open_totp_remembers_last_secret(monkeypatch):
    window = _window_stub([_entry()])
    window._last_totp_secret = "INITSECRET"
    window.reset_idle_timer = lambda: None

    class StubDialog:
        def __init__(self, parent, initial_secret=""):
            assert initial_secret == "INITSECRET"

        def exec(self):
            return True

        def get_secret(self):
            return "NEWSECRET"

    monkeypatch.setattr(main, "TwoFactorDialog", StubDialog)
    main.MainWindow.open_totp(window)
    assert window._last_totp_secret == "NEWSECRET"


def test_delete_entry_moves_to_trash(monkeypatch):
    import sys
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QApplication, QMessageBox, QTableWidget, QTableWidgetItem

    app = QApplication.instance() or QApplication(sys.argv)
    window = _window_stub([
        _entry(id="e1", name="Entry 1"),
        _entry(id="e2", name="Entry 2"),
    ])
    window.statusBar = lambda: SimpleNamespace(showMessage=lambda *args: None)
    window.refresh_table = lambda: None
    saved = []
    window.save_and_refresh = lambda: (saved.append(list(window.trash)), True)[1]
    monkeypatch.setattr(
        main.storage,
        "save_vault",
        lambda *args, **kwargs: saved.append(kwargs.get("trash")),
    )

    table = QTableWidget(2, 6)
    it0 = QTableWidgetItem("Entry 1")
    it0.setData(Qt.UserRole, 0)
    table.setItem(0, 0, it0)
    it1 = QTableWidgetItem("Entry 2")
    it1.setData(Qt.UserRole, 1)
    table.setItem(1, 0, it1)
    table.setCurrentCell(0, 0)
    window.table = table

    # First: cancel deletion
    monkeypatch.setattr(main.MsgBox, "question", lambda *args, **kwargs: QMessageBox.No)
    main.MainWindow.delete_entry(window)
    assert len(window.passwords) == 2
    assert len(window.trash) == 0

    # Second: confirm deletion
    monkeypatch.setattr(main.MsgBox, "question", lambda *args, **kwargs: QMessageBox.Yes)
    main.MainWindow.delete_entry(window)
    assert len(window.passwords) == 1
    assert window.passwords[0]["id"] == "e2"
    assert len(window.trash) == 1
    assert window.trash[0]["id"] == "e1"
    assert "deleted_at" in window.trash[0]
    assert len(saved) == 1


def test_update_trash_btn():
    import sys
    from PySide6.QtWidgets import QApplication, QPushButton

    app = QApplication.instance() or QApplication(sys.argv)
    window = _window_stub([])
    btn = QPushButton()
    window.trash_btn = btn

    # When trash is empty
    window.trash = []
    main.MainWindow.update_trash_btn(window)
    assert "(" not in btn.text()
    assert len(btn.text()) > 0

    # When trash has 3 items
    window.trash = [{"name": "1"}, {"name": "2"}, {"name": "3"}]
    main.MainWindow.update_trash_btn(window)
    assert "(3)" in btn.text()


def test_trash_dialog_operations(monkeypatch):
    import sys
    from PySide6.QtWidgets import QApplication, QMessageBox

    app = QApplication.instance() or QApplication(sys.argv)
    window = _window_stub([_entry(id="active1", name="Active 1")])
    window.trash = [
        _entry(id="t1", name="Trash 1", deleted_at="2026-11-07 10:00:00"),
        _entry(id="t2", name="Trash 2", deleted_at="2026-11-07 10:05:00"),
    ]
    window.statusBar = lambda: SimpleNamespace(showMessage=lambda *args: None)
    window.refresh_table = lambda: None
    saved = []
    window.save_and_refresh = lambda: (saved.append(True), True)[1]
    monkeypatch.setattr(main.storage, "save_vault", lambda *args, **kwargs: saved.append(True))

    dlg = main.TrashDialog(window)
    assert dlg.table.rowCount() == 2

    # Select row 0 (Trash 1) and restore
    dlg.table.selectRow(0)
    dlg.restore_selected()
    assert len(window.passwords) == 2
    assert window.passwords[-1]["name"] == "Trash 1"
    assert "deleted_at" not in window.passwords[-1]
    assert len(window.trash) == 1
    assert window.trash[0]["name"] == "Trash 2"
    assert dlg.table.rowCount() == 1

    # Select row 0 (Trash 2) and delete permanently (accept dialog)
    monkeypatch.setattr(main.MsgBox, "question", lambda *args, **kwargs: QMessageBox.Yes)
    dlg.table.selectRow(0)
    dlg.delete_permanently()
    assert len(window.trash) == 0
    assert dlg.table.rowCount() == 0

    # Add item to trash and test empty_trash
    window.trash = [_entry(id="t3", name="Trash 3")]
    dlg.refresh_table()
    assert dlg.table.rowCount() == 1
    dlg.empty_trash()
    assert len(window.trash) == 0


def test_trash_button_layout_in_bottom_right(monkeypatch):
    import sys
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication(sys.argv)
    monkeypatch.setattr(main.storage, "save_vault", lambda *args, **kwargs: None)
    monkeypatch.setattr(main.MainWindow, "closeEvent", lambda self, event: event.accept())

    win = main.MainWindow("test.kgvault", [], {}, b"k" * 32, b"s" * 16, {})
    # btn_layout should contain: add_btn (0), delete_btn (1), stretch (2), trash_btn (3)
    assert win.btn_layout.count() == 4
    assert win.btn_layout.itemAt(0).widget() == win.add_btn
    assert win.btn_layout.itemAt(1).widget() == win.delete_btn
    assert win.btn_layout.itemAt(3).widget() == win.trash_btn


def test_entry_dialog_creates_and_updates_timestamp():
    import sys
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication(sys.argv)
    # Test new entry
    dlg_new = main.EntryDialog()
    dlg_new.name_edit.setText("Service A")
    dlg_new.password_edit.setText("secret")
    data_new = dlg_new.get_data()
    assert data_new["updated_at"]
    assert len(data_new["updated_at"]) == 19  # YYYY-MM-DD HH:MM:SS

    # Test existing entry
    old_entry = {
        "id": "e-1",
        "name": "Service B",
        "password": "old",
        "updated_at": "2026-01-01 10:00:00",
    }
    dlg_edit = main.EntryDialog(entry=old_entry)
    dlg_edit.password_edit.setText("new-secret")
    data_edit = dlg_edit.get_data()
    assert data_edit["updated_at"] > "2026-01-01 10:00:00"


def test_main_window_table_column_structure(monkeypatch):
    import sys
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication(sys.argv)
    monkeypatch.setattr(main.storage, "save_vault", lambda *args, **kwargs: None)
    monkeypatch.setattr(main.MainWindow, "closeEvent", lambda self, event: event.accept())

    test_entries = [
        {
            "id": "1",
            "name": "Site 1",
            "url": "https://example.com",
            "username": "user1",
            "password": "pwd",
            "category": "website",
            "notes": "my notes",
            "updated_at": "2026-11-08 12:00:00",
        }
    ]
    win = main.MainWindow("test.kgvault", test_entries, {}, b"k" * 32, b"s" * 16, {})

    # Columns: 0:Name, 1:URL, 2:Username, 3:Password, 4:Category, 5:Notes, 6:Modified
    assert win.table.columnCount() == 7
    assert win.table.item(0, 5).text() == "my notes"
    assert win.table.item(0, 6).text() == "2026-11-08 12:00:00"
