import csv
import copy
import datetime
import json
import locale
import os
import secrets
import sys
import uuid

from PySide6.QtCore import Qt, QTimer, QTranslator, QLibraryInfo, QEvent
from PySide6.QtGui import QFont, QGuiApplication, QIcon, QKeySequence, QMouseEvent, QShortcut
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QDialog,
    QFileDialog,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMenuBar,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTableWidgetSelectionRange,
    QVBoxLayout,
    QWidget,
)

import crypto_utils
import i18n
import storage
from crypto_utils import evaluate_password_strength
from dialogs import (
    AuthDialog,
    ChangePasswordDialog,
    EntryDialog,
    LockScreen,
    MsgBox,
    PasswordGenerator,
    SettingsDialog,
    TwoFactorDialog,
    VaultPickerDialog,
)


WINDOW_WIDTH = 900
WINDOW_HEIGHT = 650
CLIPBOARD_CLEAR_MS = 300000
PASSWORD_HISTORY_LIMIT = 10


def get_resource_path(relative_path):
    """获取资源绝对路径，兼容开发环境与 PyInstaller 打包环境。"""
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)


class DragSelectTableWidget(QTableWidget):
    """支持从空白区域开始拖选行并自适应列宽的表格。"""

    MIN_COLUMN_WIDTHS = [80, 100, 80, 80, 60, 80]
    DEFAULT_COLUMN_WEIGHTS = [18, 26, 18, 14, 10, 14]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._drag_start_row = -1
        self._is_dragging = False
        self._is_adjusting_columns = False

    def adjust_column_widths(self, target_width=None):
        if self.columnCount() == 0 or self._is_adjusting_columns:
            return
        if target_width is None:
            target_width = self.viewport().width()
        if target_width <= 0:
            return

        n = min(self.columnCount(), len(self.DEFAULT_COLUMN_WEIGHTS))
        min_widths = self.MIN_COLUMN_WIDTHS[:n]
        total_min = sum(min_widths)

        if target_width < total_min:
            new_widths = list(min_widths)
        else:
            current_widths = [self.columnWidth(i) for i in range(n)]
            total_current = sum(current_widths)

            if total_current <= 0 or all(w == 100 for w in current_widths):
                weights = self.DEFAULT_COLUMN_WEIGHTS[:n]
                total_w = sum(weights)
                new_widths = []
                for i in range(n - 1):
                    w = max(min_widths[i], int(target_width * weights[i] / total_w))
                    new_widths.append(w)
                new_widths.append(max(min_widths[n - 1], target_width - sum(new_widths)))
            else:
                ratio = target_width / total_current
                new_widths = []
                for i in range(n - 1):
                    w = max(min_widths[i], int(round(current_widths[i] * ratio)))
                    new_widths.append(w)
                new_widths.append(max(min_widths[n - 1], target_width - sum(new_widths)))

        self._is_adjusting_columns = True
        try:
            for i, w in enumerate(new_widths):
                self.setColumnWidth(i, w)
        finally:
            self._is_adjusting_columns = False

    def viewportEvent(self, event):
        res = super().viewportEvent(event)
        if event.type() == QEvent.Resize:
            self.adjust_column_widths()
        return res

    def _row_at_or_clamp(self, y):
        """返回 y 坐标对应的行号，超出范围时夹紧到首/末行。"""
        row = self.rowAt(y)
        if row == -1:
            if y < 0:
                row = 0
            else:
                row = self.rowCount() - 1
        return row

    def mousePressEvent(self, event: QMouseEvent):
        if event.button() == Qt.LeftButton:
            row = self._row_at_or_clamp(event.position().toPoint().y())
            if row >= 0:
                self._drag_start_row = row
                self._is_dragging = True
                modifiers = event.modifiers()
                if not (modifiers & Qt.ControlModifier) and not (modifiers & Qt.ShiftModifier):
                    self.clearSelection()
                self.setCurrentCell(row, 0)
                self.selectRow(row)
        else:
            self._is_dragging = False
        super().mousePressEvent(event)

    def mouseDoubleClickEvent(self, event: QMouseEvent):
        self._is_dragging = False
        self._drag_start_row = -1
        super().mouseDoubleClickEvent(event)

    def mouseMoveEvent(self, event: QMouseEvent):
        if self._is_dragging and self._drag_start_row >= 0:
            current_row = self._row_at_or_clamp(event.position().toPoint().y())
            if current_row < 0:
                return
            self.clearSelection()
            top = min(self._drag_start_row, current_row)
            bottom = max(self._drag_start_row, current_row)
            self.setRangeSelected(
                QTableWidgetSelectionRange(top, 0, bottom, self.columnCount() - 1),
                True,
            )
            return
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event: QMouseEvent):
        if event.button() == Qt.LeftButton:
            self._is_dragging = False
            self._drag_start_row = -1
        super().mouseReleaseEvent(event)


class MainWindow(QMainWindow):
    def __init__(self, vault_path, entries, preferences, master_key, master_salt, kdf_spec):
        super().__init__()
        self.resize(WINDOW_WIDTH, WINDOW_HEIGHT)
        self.setWindowIcon(QIcon(get_resource_path("icon.ico")))

        self.vault_path = vault_path
        self.passwords = entries
        self.preferences = preferences or storage.DEFAULT_PREFERENCES.copy()
        self.master_key = master_key
        self.master_salt = master_salt
        self.kdf_spec = kdf_spec
        self._dirty = False
        self._last_totp_secret = ""

        # 为缺少 id 的条目补生成 id；若有改动立即落盘作为基线
        self.passwords, ids_changed = storage.ensure_entry_ids(self.passwords)
        if ids_changed:
            try:
                storage.save_vault(
                    self.vault_path, self.passwords, self.preferences,
                    self.master_key, self.master_salt, self.kdf_spec,
                )
            except Exception:
                pass

        self.idle_timer = QTimer()
        self.idle_timer.timeout.connect(self.check_idle)
        self.last_activity = datetime.datetime.now()
        self.is_locked = False

        self.clipboard_timer = QTimer()
        self.clipboard_timer.setSingleShot(True)
        self.clipboard_timer.timeout.connect(self.clear_clipboard)

        self.setup_ui()
        self.apply_auto_lock_settings()
        self.refresh_table()

    def mark_dirty(self):
        self._dirty = True

    def save_preferences(self, prefs):
        self.preferences = dict(prefs)
        return self._write_vault()

    def _write_vault(self):
        try:
            storage.save_vault(
                self.vault_path,
                self.passwords,
                self.preferences,
                self.master_key,
                self.master_salt,
                self.kdf_spec,
            )
            self._dirty = False
            return True
        except Exception:
            return False

    def apply_auto_lock_settings(self):
        self.idle_timer.stop()
        auto_lock_minutes = self.preferences.get("auto_lock_minutes", 0)
        if auto_lock_minutes > 0:
            self.idle_timer.start(auto_lock_minutes * 60 * 1000)

    def check_idle(self):
        if self.is_locked:
            return
        auto_lock_minutes = self.preferences.get("auto_lock_minutes", 0)
        if auto_lock_minutes > 0:
            idle_time = (datetime.datetime.now() - self.last_activity).total_seconds()
            if idle_time >= auto_lock_minutes * 60:
                self.show_lock_screen()

    def reset_idle_timer(self):
        self.last_activity = datetime.datetime.now()

    def load_config_safe(self):
        return self.preferences

    def show_lock_screen(self):
        if self.is_locked:
            return

        self.is_locked = True
        self.clipboard_timer.stop()
        QApplication.clipboard().clear()

        while self.is_locked:
            self.lock_screen = LockScreen(self)
            self.lock_screen.setWindowTitle(i18n._t("lock_screen_title"))
            if not self.lock_screen.exec():
                continue

            pwd = self.lock_screen.password_edit.text()
            derived = crypto_utils.derive_key_for_kdf(pwd, self.master_salt, self.kdf_spec)
            if secrets.compare_digest(derived, self.master_key):
                self.is_locked = False
                self.reset_idle_timer()
                self.statusBar().showMessage(i18n._t("unlock_btn"), 2000)
                continue

            MsgBox.warning(self, i18n._t("error_title"), i18n._t("decrypt_error"))

    def setup_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        self.main_layout = QVBoxLayout(central_widget)

        top_grid = QGridLayout()
        top_grid.setColumnStretch(0, 1)

        self.search_bar = QLineEdit()
        self.search_bar.textChanged.connect(self.filter_entries)
        self.search_bar.textChanged.connect(lambda: self.reset_idle_timer())
        top_grid.addWidget(self.search_bar, 0, 0)

        self.category_filter = QComboBox()
        self.category_filter.addItem(i18n._t("category_all"), "all")
        self.category_filter.addItem(i18n._t("category_website"), "website")
        self.category_filter.addItem(i18n._t("category_email"), "email")
        self.category_filter.addItem(i18n._t("category_social"), "social")
        self.category_filter.addItem(i18n._t("category_bank"), "bank")
        self.category_filter.addItem(i18n._t("category_other"), "other")
        self.category_filter.currentIndexChanged.connect(self.filter_entries)
        top_grid.addWidget(self.category_filter, 0, 1)

        self.gen_tool_btn = QPushButton()
        self.gen_tool_btn.clicked.connect(self.open_generator)
        top_grid.addWidget(self.gen_tool_btn, 0, 2)

        self.import_btn = QPushButton()
        self.import_btn.clicked.connect(self.import_data)
        top_grid.addWidget(self.import_btn, 0, 3)

        self.export_btn = QPushButton()
        self.export_btn.clicked.connect(self.export_data)
        top_grid.addWidget(self.export_btn, 0, 4)

        self.settings_btn = QPushButton()
        self.settings_btn.clicked.connect(self.open_settings)
        top_grid.addWidget(self.settings_btn, 0, 5)

        batch_widget = QWidget()
        batch_layout = QHBoxLayout(batch_widget)
        batch_layout.setContentsMargins(0, 0, 0, 0)

        self.new_btn = QPushButton()
        self.new_btn.clicked.connect(self.new_vault)
        batch_layout.addWidget(self.new_btn)

        self.open_btn = QPushButton()
        self.open_btn.clicked.connect(self.open_vault)
        batch_layout.addWidget(self.open_btn)
        batch_layout.addStretch()

        top_grid.addWidget(batch_widget, 1, 0)

        self.totp_btn = QPushButton()
        self.totp_btn.clicked.connect(self.open_totp)
        top_grid.addWidget(self.totp_btn, 1, 2)

        self.main_layout.addLayout(top_grid)

        self.table = DragSelectTableWidget(0, 6)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QTableWidget.ExtendedSelection)
        self.table.doubleClicked.connect(self.on_table_double_click)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_context_menu)
        self.main_layout.addWidget(self.table)

        config = self.preferences
        col_widths = config.get("column_widths", [])
        for i, w in enumerate(col_widths):
            if i < 6:
                self.table.setColumnWidth(i, w)

        self.table.viewport().installEventFilter(self)

        self.btn_layout = QHBoxLayout()
        self.add_btn = QPushButton()
        self.add_btn.clicked.connect(self.add_entry)
        self.delete_btn = QPushButton()
        self.delete_btn.clicked.connect(self.delete_entry)
        self.btn_layout.addWidget(self.add_btn)
        self.btn_layout.addWidget(self.delete_btn)
        self.btn_layout.addStretch(1)
        self.main_layout.addLayout(self.btn_layout)

        self.status_label = QLabel()
        self.status_label.setAlignment(Qt.AlignCenter)
        self.statusBar().addWidget(self.status_label, 1)

        self.add_shortcut = QShortcut(QKeySequence("Ctrl+N"), self)
        self.add_shortcut.activated.connect(self.add_entry)
        self.delete_shortcut = QShortcut(QKeySequence("Delete"), self)
        self.delete_shortcut.activated.connect(self.delete_entry)
        QShortcut(QKeySequence("Ctrl+F"), self).activated.connect(self.focus_search)

        self.retranslate_ui()

    def closeEvent(self, event):
        current_widths = [self.table.columnWidth(i) for i in range(6)]
        widths_changed = self.preferences.get("column_widths") != current_widths
        self.preferences["column_widths"] = current_widths
        if not self._dirty and not widths_changed:
            event.accept()
            return

        try:
            storage.save_vault(
                self.vault_path,
                self.passwords,
                self.preferences,
                self.master_key,
                self.master_salt,
                self.kdf_spec,
            )
            self._dirty = False
        except Exception as exc:
            recovery_path = getattr(exc, "recovery_path", None)
            detail = getattr(exc, "detail", "") or str(exc)
            log_path = storage.write_error_log(
                "close_save",
                exc,
                vault_path=self.vault_path,
                recovery_path=recovery_path,
            )
            MsgBox.critical(
                self,
                i18n._t("error_title"),
                i18n._t("vault_close_save_failed").format(
                    original_path=self.vault_path,
                    recovery_path=recovery_path or "-",
                    error=detail,
                    log_path=log_path or "-",
                ),
            )
            event.ignore()
            return
        event.accept()

    def eventFilter(self, obj, event):
        if obj is self.table.viewport() and event.type() == event.Type.MouseButtonPress:
            self.reset_idle_timer()
        return super().eventFilter(obj, event)

    def keyPressEvent(self, event):
        self.reset_idle_timer()
        super().keyPressEvent(event)

    def retranslate_ui(self):
        self.setWindowTitle(i18n._t("window_title"))
        self.search_bar.setPlaceholderText(i18n._t("search_placeholder"))

        self.new_btn.setText(i18n._t("vault_new_btn"))
        self.open_btn.setText(i18n._t("vault_open_btn"))

        self.category_filter.setItemText(0, i18n._t("category_all"))
        self.category_filter.setItemText(1, i18n._t("category_website"))
        self.category_filter.setItemText(2, i18n._t("category_email"))
        self.category_filter.setItemText(3, i18n._t("category_social"))
        self.category_filter.setItemText(4, i18n._t("category_bank"))
        self.category_filter.setItemText(5, i18n._t("category_other"))

        self.gen_tool_btn.setText(i18n._t("generator_btn"))
        self.totp_btn.setText(i18n._t("totp_btn"))
        self.import_btn.setText(i18n._t("import_btn"))
        self.export_btn.setText(i18n._t("export_btn"))
        self.settings_btn.setText(i18n._t("settings_btn"))
        self.add_btn.setText(i18n._t("add_btn"))
        self.delete_btn.setText(i18n._t("delete_btn"))

        headers = [
            i18n._t("table_name"),
            i18n._t("table_url"),
            i18n._t("table_username"),
            i18n._t("table_password"),
            i18n._t("table_category"),
            i18n._t("table_notes"),
        ]
        self.table.setHorizontalHeaderLabels(headers)

    def get_category_text(self, category):
        category_map = {
            "website": i18n._t("category_website"),
            "email": i18n._t("category_email"),
            "social": i18n._t("category_social"),
            "bank": i18n._t("category_bank"),
            "other": i18n._t("category_other"),
        }
        return category_map.get(category, category)

    def refresh_table(self):
        self.table.setRowCount(0)
        search_text = self.search_bar.text().lower()
        category_filter = self.category_filter.currentData()

        for i, entry in enumerate(self.passwords):
            if search_text and not any(search_text in str(v).lower() for v in entry.values() if v):
                continue

            if category_filter != "all" and entry.get("category", "other") != category_filter:
                continue

            row = self.table.rowCount()
            self.table.insertRow(row)
            self.table.setItem(row, 0, QTableWidgetItem(entry.get("name", "")))
            self.table.setItem(row, 1, QTableWidgetItem(entry.get("url", "")))
            self.table.setItem(row, 2, QTableWidgetItem(entry.get("username", "")))

            pass_item = QTableWidgetItem("********")
            pass_item.setData(Qt.UserRole, entry.get("password", ""))
            self.table.setItem(row, 3, pass_item)

            self.table.setItem(
                row,
                4,
                QTableWidgetItem(self.get_category_text(entry.get("category", "other"))),
            )
            self.table.setItem(row, 5, QTableWidgetItem(entry.get("notes", "")))
            self.table.item(row, 0).setData(Qt.UserRole, i)

        total = len(self.passwords)
        shown = self.table.rowCount()
        self.status_label.setText(i18n._t("status_count").format(shown=shown, total=total))

    def filter_entries(self):
        self.refresh_table()

    def focus_search(self):
        self.search_bar.setFocus()
        self.search_bar.selectAll()

    def add_entry(self):
        self.reset_idle_timer()
        dialog = EntryDialog(self)
        if dialog.exec():
            data = dialog.get_data()
            self.passwords.append(data)
            self.mark_dirty()
            self.save_and_refresh()

    def edit_entry(self):
        self.reset_idle_timer()
        row = self.table.currentRow()
        if row < 0:
            selected = self.table.selectedRanges()
            if selected:
                row = selected[0].topRow()
            else:
                return

        orig_index = self.table.item(row, 0).data(Qt.UserRole)
        entry = self.passwords[orig_index]

        old_password = entry.get("password", "")
        new_password = ""

        dialog = EntryDialog(self, entry)
        if dialog.exec():
            new_data = dialog.get_data()
            new_password = new_data.get("password", "")

            if old_password and new_password != old_password:
                history = entry.get("password_history", [])
                history.insert(
                    0,
                    {
                        "password": old_password,
                        "date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    },
                )
                if len(history) > PASSWORD_HISTORY_LIMIT:
                    history = history[:PASSWORD_HISTORY_LIMIT]
                new_data["password_history"] = history
            elif old_password:
                new_data["password_history"] = entry.get("password_history", [])

            self.passwords[orig_index] = new_data
            self.mark_dirty()
            self.save_and_refresh()

    def delete_entry(self):
        self.reset_idle_timer()
        selected_rows = set()
        for r in self.table.selectedRanges():
            for i in range(r.topRow(), r.bottomRow() + 1):
                selected_rows.add(i)

        if not selected_rows:
            row = self.table.currentRow()
            if row >= 0:
                selected_rows.add(row)
            else:
                return

        if len(selected_rows) == 1:
            row = list(selected_rows)[0]
            orig_index = self.table.item(row, 0).data(Qt.UserRole)
            msg = i18n._t("confirm_delete_msg").format(self.passwords[orig_index]["name"])
        else:
            msg = i18n._t("confirm_delete_msg_plural").format(len(selected_rows))

        reply = MsgBox.question(
            self,
            i18n._t("confirm_delete_title"),
            msg,
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if reply == QMessageBox.Yes:
            orig_indices = []
            for row in selected_rows:
                orig_indices.append(self.table.item(row, 0).data(Qt.UserRole))
            orig_indices.sort(reverse=True)
            for idx in orig_indices:
                self.passwords.pop(idx)
            self.mark_dirty()
            self.save_and_refresh()

    def clear_clipboard(self):
        QApplication.clipboard().clear()
        self.statusBar().showMessage(i18n._t("clipboard_cleared"), 3000)

    def show_context_menu(self, pos):
        self.reset_idle_timer()
        row = self.table.rowAt(pos.y())
        if row < 0:
            return

        menu = QMenu(self)
        edit_action = menu.addAction(i18n._t("edit_btn"))
        delete_action = menu.addAction(i18n._t("delete_btn"))
        action = menu.exec(self.table.viewport().mapToGlobal(pos))

        if action == edit_action:
            self.table.setCurrentCell(row, 0)
            self.edit_entry()
            return

        if action == delete_action:
            self.table.setCurrentCell(row, 0)
            self.delete_entry()

    def on_table_double_click(self, index):
        self.reset_idle_timer()
        col = index.column()
        row = index.row()

        if col == 3:
            password = self.table.item(row, 3).data(Qt.UserRole)
            QApplication.clipboard().setText(password)
            self.statusBar().showMessage(i18n._t("copy_password_success"), 2000)
            self.clipboard_timer.start(CLIPBOARD_CLEAR_MS)
            return

        if col in (0, 1, 2, 4, 5):
            item = self.table.item(row, col)
            if item:
                QApplication.clipboard().setText(item.text())
                col_name = self.table.horizontalHeaderItem(col).text()
                self.statusBar().showMessage(f"{col_name} {i18n._t('copy_success')}", 2000)

    def import_data(self):
        self.reset_idle_timer()

        format_dialog = QDialog(self)
        format_dialog.setWindowTitle(i18n._t("import_format"))
        layout = QVBoxLayout(format_dialog)
        layout.addWidget(QLabel(i18n._t("import_format") + ":"))

        format_combo = QComboBox()
        format_combo.addItem(i18n._t("format_markdown"), "md")
        format_combo.addItem(i18n._t("format_csv"), "csv")
        format_combo.addItem(i18n._t("format_json"), "json")
        layout.addWidget(format_combo)

        btn = QPushButton(i18n._t("import_btn"))
        btn.clicked.connect(format_dialog.accept)
        layout.addWidget(btn)

        if not format_dialog.exec():
            return

        file_format = format_combo.currentData()
        filters = {
            "md": "Markdown Files (*.md);;All Files (*)",
            "csv": "CSV Files (*.csv);;All Files (*)",
            "json": "JSON Files (*.json);;All Files (*)",
        }
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            i18n._t("import_btn"),
            "",
            filters[file_format],
        )
        if not file_path:
            return

        try:
            entries = []
            if file_format == "md":
                entries = self.import_markdown(file_path)
            elif file_format == "csv":
                entries = self.import_csv(file_path)
            elif file_format == "json":
                entries = self.import_json(file_path)

            sanitized_entries = self.sanitize_import_entries(entries)
            if sanitized_entries:
                old_passwords = list(self.passwords)
                self.passwords.extend(sanitized_entries)
                try:
                    self.save_and_refresh()
                except Exception:
                    self.passwords = old_passwords
                    self.refresh_table()
                    raise

                MsgBox.information(
                    self,
                    i18n._t("import_btn"),
                    i18n._t("import_success").format(len(sanitized_entries)),
                )
                return

            MsgBox.warning(self, i18n._t("error_title"), i18n._t("import_fail"))
        except Exception as e:
            MsgBox.critical(self, i18n._t("error_title"), i18n._t("error_import").format(str(e)))

    def sanitize_import_entries(self, entries):
        if not isinstance(entries, list):
            return []

        valid_categories = {"website", "email", "social", "bank", "other"}
        sanitized = []

        for raw_entry in entries:
            if not isinstance(raw_entry, dict):
                continue

            category = str(raw_entry.get("category", "other")).strip().lower()
            if category not in valid_categories:
                category = "other"

            sanitized_entry = {
                "id": str(raw_entry.get("id") or uuid.uuid4().hex),
                "name": str(raw_entry.get("name", "")).strip(),
                "url": str(raw_entry.get("url", "")).strip(),
                "username": str(raw_entry.get("username", "")).strip(),
                "password": str(raw_entry.get("password", "")),
                "notes": str(raw_entry.get("notes", "")),
                "category": category,
                "password_history": [],
            }

            history = raw_entry.get("password_history", [])
            if isinstance(history, list):
                for item in history[:10]:
                    if not isinstance(item, dict):
                        continue
                    old_password = str(item.get("password", ""))
                    old_date = str(item.get("date", ""))
                    if not old_password:
                        continue
                    sanitized_entry["password_history"].append(
                        {"password": old_password, "date": old_date}
                    )

            if not sanitized_entry["name"]:
                continue
            sanitized.append(sanitized_entry)

        return sanitized

    def import_markdown(self, file_path):
        entries = []
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        sections = content.split("---")
        for section in sections:
            section = section.strip()
            if not section:
                continue

            lines = section.split("\n")
            entry = {
                "name": "",
                "url": "",
                "username": "",
                "password": "",
                "notes": "",
                "category": "other",
            }

            if lines[0].startswith("### "):
                entry["name"] = lines[0][4:].strip()

            notes_lines = []
            is_notes = False
            for line in lines[1:]:
                line = line.strip()
                if line.startswith("- **URL**: "):
                    entry["url"] = line[len("- **URL**: ") :].strip()
                    continue
                if line.startswith("- **Username**: "):
                    entry["username"] = line[len("- **Username**: ") :].strip()
                    continue
                if line.startswith("- **Password**: "):
                    entry["password"] = line[len("- **Password**: ") :].strip()
                    continue
                if line.startswith("- **Category**: "):
                    entry["category"] = line[len("- **Category**: ") :].strip()
                    continue
                if line.startswith("- **Notes**: "):
                    entry["notes"] = line[len("- **Notes**: ") :].strip()
                    is_notes = True
                    continue
                if not is_notes:
                    continue
                notes_lines.append(line)

            if notes_lines:
                entry["notes"] += "\n" + "\n".join(notes_lines)

            if not entry["name"]:
                continue
            entries.append(entry)

        return entries

    def import_csv(self, file_path):
        entries = []
        with open(file_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                entry = {
                    "name": row.get("name", ""),
                    "url": row.get("url", ""),
                    "username": row.get("username", ""),
                    "password": row.get("password", ""),
                    "notes": row.get("notes", ""),
                    "category": row.get("category", "other"),
                }
                if not entry["name"]:
                    continue
                entries.append(entry)
        return entries

    def import_json(self, file_path):
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            return data
        return []

    def export_data(self):
        self.reset_idle_timer()

        format_dialog = QDialog(self)
        format_dialog.setWindowTitle(i18n._t("export_format"))
        layout = QVBoxLayout(format_dialog)
        layout.addWidget(QLabel(i18n._t("export_format") + ":"))

        format_combo = QComboBox()
        format_combo.addItem(i18n._t("format_markdown"), "md")
        format_combo.addItem(i18n._t("format_csv"), "csv")
        format_combo.addItem(i18n._t("format_json"), "json")
        layout.addWidget(format_combo)

        btn = QPushButton(i18n._t("export_btn"))
        btn.clicked.connect(format_dialog.accept)
        layout.addWidget(btn)

        if not format_dialog.exec():
            return

        file_format = format_combo.currentData()
        reply = MsgBox.question(
            self,
            i18n._t("export_format"),
            i18n._t("export_plaintext_warning"),
            QMessageBox.Ok | QMessageBox.Cancel,
            QMessageBox.Cancel,
        )
        if reply != QMessageBox.Ok:
            return

        default_names = {
            "md": "passwords_export.md",
            "csv": "passwords_export.csv",
            "json": "passwords_export.json",
        }
        filters = {
            "md": "Markdown Files (*.md);;All Files (*)",
            "csv": "CSV Files (*.csv);;All Files (*)",
            "json": "JSON Files (*.json);;All Files (*)",
        }
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            i18n._t("export_btn"),
            default_names[file_format],
            filters[file_format],
        )
        if not file_path:
            return

        try:
            if file_format == "md":
                self.export_markdown(file_path)
            elif file_format == "csv":
                self.export_csv(file_path)
            elif file_format == "json":
                self.export_json(file_path)

            MsgBox.information(self, i18n._t("export_btn"), i18n._t("export_success"))
        except Exception as e:
            MsgBox.critical(self, i18n._t("error_title"), i18n._t("error_export").format(str(e)))

    def export_markdown(self, file_path):
        markdown_items = []
        for entry in self.passwords:
            item = []
            item.append(f"### {entry['name']}")
            item.append(f"- **URL**: {entry['url']}")
            item.append(f"- **Username**: {entry['username']}")
            item.append(f"- **Password**: {entry['password']}")
            item.append(f"- **Category**: {entry.get('category', 'other')}")

            notes = entry["notes"]
            if "\n" in notes:
                notes_indented = notes.replace("\n", "\n  ")
                item.append(f"- **Notes**: {notes_indented}")
            else:
                item.append(f"- **Notes**: {notes}")

            markdown_items.append("\n".join(item))

        content = "\n\n---\n\n".join(markdown_items)
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content)

    def export_csv(self, file_path):
        import csv as csv_module

        fieldnames = ["name", "url", "username", "password", "notes", "category"]
        with open(file_path, "w", encoding="utf-8", newline="") as f:
            writer = csv_module.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for entry in self.passwords:
                row = {k: entry.get(k, "") for k in fieldnames}
                writer.writerow(row)

    def export_json(self, file_path):
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(self.passwords, f, indent=2, ensure_ascii=False)

    def save_and_refresh(self):
        try:
            storage.save_vault(
                self.vault_path,
                self.passwords,
                self.preferences,
                self.master_key,
                self.master_salt,
                self.kdf_spec,
            )
            self._dirty = False
        except Exception:
            MsgBox.critical(self, i18n._t("error_title"), i18n._t("storage_save_failed"))
            return False
        self.refresh_table()
        return True

    def open_generator(self):
        self.reset_idle_timer()
        gen = PasswordGenerator(self)
        gen.exec()

    def open_totp(self):
        self.reset_idle_timer()
        dialog = TwoFactorDialog(self, initial_secret=self._last_totp_secret)
        dialog.exec()
        self._last_totp_secret = dialog.get_secret()

    def open_settings(self):
        self.reset_idle_timer()
        dialog = SettingsDialog(self)
        if dialog.exec():
            self.apply_auto_lock_settings()

    def change_master_password(self):
        self.reset_idle_timer()
        dialog = ChangePasswordDialog(
            self.master_key, self.master_salt, self.kdf_spec, self
        )
        if dialog.exec():
            new_password = dialog.get_new_password()
            new_salt = crypto_utils.generate_salt()
            new_kdf_spec = storage._argon2_kdf_spec(new_salt)
            new_key = crypto_utils.derive_key_for_kdf(new_password, new_salt, new_kdf_spec)
            try:
                storage.save_vault(
                    self.vault_path,
                    self.passwords,
                    self.preferences,
                    new_key,
                    new_salt,
                    new_kdf_spec,
                )
            except Exception as exc:
                recovery_path = getattr(exc, "recovery_path", None)
                detail = getattr(exc, "detail", "") or str(exc)
                log_path = storage.write_error_log(
                    "change_master_password",
                    exc,
                    vault_path=self.vault_path,
                    recovery_path=recovery_path,
                )
                MsgBox.critical(
                    self,
                    i18n._t("error_title"),
                    i18n._t("vault_password_change_failed").format(
                        recovery_path=recovery_path or "-",
                        error=detail,
                        log_path=log_path or "-",
                    ),
                )
                return

            self.master_key = new_key
            self.master_salt = new_salt
            self.kdf_spec = new_kdf_spec
            self._dirty = False
            self.refresh_table()
            MsgBox.information(
                self, i18n._t("change_pass_title"), i18n._t("change_pass_success")
            )

    def _confirm_discard_changes(self, msg_key):
        if self._dirty:
            reply = MsgBox.question(
                self,
                i18n._t("vault_picker_title"),
                i18n._t(msg_key),
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if reply != QMessageBox.Yes:
                return False
        return True

    def new_vault(self):
        self.reset_idle_timer()
        if not self._confirm_discard_changes("confirm_switch_vault"):
            return
        path, _ = QFileDialog.getSaveFileName(
            self,
            i18n._t("vault_new_btn"),
            storage.DEFAULT_VAULT_PATH,
            i18n._t("vault_filter"),
        )
        if not path:
            return
        dialog = AuthDialog("setup", self)
        if not dialog.exec():
            return
        pwd = dialog.get_password()
        try:
            key, salt, kdf_spec = storage.create_new_vault(path, pwd, self.preferences)
        except Exception:
            MsgBox.critical(self, i18n._t("vault_create_error_title"), i18n._t("vault_save_failed"))
            return
        self.vault_path = path
        self.passwords = []
        self.master_key = key
        self.master_salt = salt
        self.kdf_spec = kdf_spec
        self._dirty = False
        self.refresh_table()
        self.statusBar().showMessage(i18n._t("vault_created"), 3000)

    def open_vault(self):
        self.reset_idle_timer()
        if not self._confirm_discard_changes("confirm_switch_vault"):
            return
        path, _ = QFileDialog.getOpenFileName(
            self,
            i18n._t("vault_open_btn"),
            "",
            i18n._t("vault_filter"),
        )
        if not path:
            return
        self._open_vault_path(path)

    def _open_vault_path(self, path):
        if not storage.is_vault_file(path):
            MsgBox.warning(self, i18n._t("vault_open_error_title"), i18n._t("vault_format_unsupported"))
            return
        while True:
            dialog = AuthDialog("login", self)
            if not dialog.exec():
                return
            pwd = dialog.get_password()
            try:
                entries, prefs, key, salt, kdf_spec = storage.load_vault(path, pwd)
            except storage.VaultError as exc:
                if exc.reason == "wrong_password":
                    MsgBox.warning(self, i18n._t("error_title"), i18n._t("decrypt_error"))
                    continue
                if exc.reason == "unsupported_version":
                    MsgBox.warning(self, i18n._t("vault_open_error_title"), i18n._t("vault_unsupported_v2"))
                else:
                    MsgBox.critical(self, i18n._t("vault_open_error_title"), i18n._t("vault_load_failed"))
                return
            self.vault_path = path
            self.passwords, _ = storage.ensure_entry_ids(entries)
            self.preferences = prefs
            self.master_key = key
            self.master_salt = salt
            self.kdf_spec = kdf_spec
            self._dirty = False
            self.refresh_table()
            self.statusBar().showMessage(i18n._t("vault_opened"), 3000)
            return


def detect_system_language():
    """根据系统 locale 推断 UI 语言，仅返回 'zh' 或 'en'。"""
    try:
        loc = locale.getdefaultlocale()[0] or ""
    except Exception:
        loc = ""
    if loc.lower().startswith("zh"):
        return "zh"
    return "en"


def _resolve_initial_vault_path(argv):
    """从命令行参数解析要打开的 vault 路径，无则返回 None。"""
    for arg in argv[1:]:
        if arg and not arg.startswith("-") and os.path.exists(arg):
            return arg
    return None


def _try_open_vault_for_startup(path, parent=None):
    """启动时尝试打开 vault 文件。返回 (entries, prefs, key, salt, kdf_spec) 或 None。"""
    if not storage.is_vault_file(path):
        MsgBox.warning(parent, i18n._t("vault_open_error_title"), i18n._t("vault_format_unsupported"))
        return None
    while True:
        dialog = AuthDialog("login", parent)
        if not dialog.exec():
            return None
        pwd = dialog.get_password()
        try:
            return storage.load_vault(path, pwd)
        except storage.VaultError as exc:
            if exc.reason == "wrong_password":
                MsgBox.warning(parent, i18n._t("error_title"), i18n._t("decrypt_error"))
                continue
            if exc.reason == "unsupported_version":
                MsgBox.warning(parent, i18n._t("vault_open_error_title"), i18n._t("vault_unsupported_v2"))
            else:
                MsgBox.critical(parent, i18n._t("vault_open_error_title"), i18n._t("vault_load_failed"))
            return None


def _create_vault_for_startup(path, parent=None):
    """启动时新建 vault。返回 (entries, prefs, key, salt, kdf_spec) 或 None。"""
    while True:
        dialog = AuthDialog("setup", parent)
        if not dialog.exec():
            return None
        pwd = dialog.get_password()
        try:
            key, salt, kdf_spec = storage.create_new_vault(path, pwd)
            return [], storage.DEFAULT_PREFERENCES.copy(), key, salt, kdf_spec
        except Exception:
            MsgBox.critical(parent, i18n._t("vault_create_error_title"), i18n._t("vault_save_failed"))
            return None


def _migrate_legacy_for_startup(legacy_info, parent=None):
    """启动时迁移旧版 passwords.json → v3 .kgvault。

    返回 (vault_path, entries, prefs, key, salt, kdf_spec) 或 None。
    迁移成功后清理旧 data/ 目录和根目录旧文件。
    """
    while True:
        dialog = AuthDialog(
            "login",
            parent,
            title=i18n._t("migrate_legacy_title"),
            message=i18n._t("migrate_legacy_msg"),
        )
        if not dialog.exec():
            return None
        pwd = dialog.get_password()
        target_path = storage.DEFAULT_VAULT_PATH
        try:
            key, salt, kdf_spec = storage.migrate_legacy_passwords_json(
                legacy_info["passwords"], legacy_info.get("config"), target_path, pwd
            )
        except storage.VaultError as exc:
            if exc.reason == "wrong_password":
                MsgBox.warning(parent, i18n._t("error_title"), i18n._t("decrypt_error"))
                continue
            MsgBox.critical(parent, i18n._t("vault_open_error_title"), i18n._t("vault_load_failed"))
            return None
        except Exception:
            MsgBox.critical(parent, i18n._t("vault_open_error_title"), i18n._t("vault_load_failed"))
            return None
        try:
            entries, prefs, k2, s2, kdf2 = storage.load_vault(target_path, pwd)
        except storage.VaultError:
            MsgBox.critical(parent, i18n._t("vault_open_error_title"), i18n._t("vault_load_failed"))
            return None
        storage.cleanup_legacy_data_dir()
        storage.cleanup_legacy_root_files()
        MsgBox.information(
            parent,
            i18n._t("vault_migrated_title"),
            i18n._t("vault_migrated_msg").format(path=target_path),
        )
        return target_path, entries, prefs, k2, s2, kdf2


def main():
    os.environ["QT_AUTO_SCREEN_SCALE_FACTOR"] = "1"
    if hasattr(Qt, "HighDpiScaleFactorRoundingPolicy"):
        QGuiApplication.setHighDpiScaleFactorRoundingPolicy(
            Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
        )

    app = QApplication(sys.argv)

    if sys.platform == "win32":
        default_font = QFont("Microsoft YaHei UI", 9)
    else:
        default_font = QFont("Sans Serif", 9)
    app.setFont(default_font)

    app.setWindowIcon(QIcon(get_resource_path("icon.ico")))

    lang = detect_system_language()
    i18n.set_language(lang)

    app._qt_translator = QTranslator(app)
    translations_path = QLibraryInfo.path(QLibraryInfo.LibraryPath.TranslationsPath)
    locale_name = "zh_CN" if lang == "zh" else "en"
    app._qt_translator.load(f"qt_{locale_name}", translations_path)
    app.installTranslator(app._qt_translator)

    init_vault_path = _resolve_initial_vault_path(sys.argv)

    vault_path = None
    entries = None
    prefs = None
    master_key = None
    master_salt = None
    kdf_spec = None

    if init_vault_path:
        result = _try_open_vault_for_startup(init_vault_path)
        if result is None:
            sys.exit(0)
        entries, prefs, master_key, master_salt, kdf_spec = result
        vault_path = init_vault_path
    else:
        # 优先检测旧 passwords.json，自动迁移
        legacy_info = storage.detect_legacy_passwords_json()
        if legacy_info:
            migrated = _migrate_legacy_for_startup(legacy_info)
            if migrated is None:
                sys.exit(0)
            vault_path, entries, prefs, master_key, master_salt, kdf_spec = migrated
        else:
            # 扫描 EXE 同目录下的 .kgvault 文件
            exe_dir = storage.get_app_dir()
            found_vaults = storage.scan_vaults_in_dir(exe_dir)
            if len(found_vaults) == 1:
                result = _try_open_vault_for_startup(found_vaults[0])
                if result is None:
                    sys.exit(0)
                entries, prefs, master_key, master_salt, kdf_spec = result
                vault_path = found_vaults[0]
            else:
                # 0 个或多于 1 个 → 引导界面
                picker = VaultPickerDialog()
                if not picker.exec():
                    sys.exit(0)
                chosen_path = picker.chosen_path
                if picker.chosen_action == "new":
                    result = _create_vault_for_startup(chosen_path)
                    if result is None:
                        sys.exit(0)
                    entries, prefs, master_key, master_salt, kdf_spec = result
                    vault_path = chosen_path
                elif picker.chosen_action == "open":
                    result = _try_open_vault_for_startup(chosen_path)
                    if result is None:
                        sys.exit(0)
                    entries, prefs, master_key, master_salt, kdf_spec = result
                    vault_path = chosen_path

    if lang != prefs.get("language", lang):
        new_lang = prefs.get("language", lang)
        i18n.set_language(new_lang)
        app.removeTranslator(app._qt_translator)
        app._qt_translator = QTranslator(app)
        locale_name = "zh_CN" if new_lang == "zh" else "en"
        app._qt_translator.load(f"qt_{locale_name}", translations_path)
        app.installTranslator(app._qt_translator)

    window = MainWindow(vault_path, entries, prefs, master_key, master_salt, kdf_spec)
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
