import csv
import datetime
import json
import os
import secrets
import sys

from PySide6.QtCore import Qt, QTimer, QTranslator, QLibraryInfo
from PySide6.QtGui import QFont, QGuiApplication, QIcon, QKeySequence, QMouseEvent, QShortcut
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
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
    """支持从空白区域开始拖选行的表格。"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._drag_start_row = -1
        self._is_dragging = False

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
    def __init__(self, master_password):
        super().__init__()
        self.resize(WINDOW_WIDTH, WINDOW_HEIGHT)
        self.setWindowIcon(QIcon(get_resource_path("icon.ico")))

        try:
            self.passwords, self.master_key, self.master_salt = storage.load_passwords(master_password)
        except storage.PasswordLoadError as exc:
            if exc.reason == "wrong_password":
                MsgBox.critical(None, i18n._t("error_title"), i18n._t("decrypt_error"))
            else:
                MsgBox.critical(None, i18n._t("error_title"), i18n._t("storage_load_failed"))
            sys.exit(1)

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

    def apply_auto_lock_settings(self):
        self.idle_timer.stop()
        config = self.load_config_safe()
        auto_lock_minutes = config.get("auto_lock_minutes", 0)
        if auto_lock_minutes > 0:
            self.idle_timer.start(auto_lock_minutes * 60 * 1000)

    def check_idle(self):
        if self.is_locked:
            return
        config = self.load_config_safe()
        auto_lock_minutes = config.get("auto_lock_minutes", 0)
        if auto_lock_minutes > 0:
            idle_time = (datetime.datetime.now() - self.last_activity).total_seconds()
            if idle_time >= auto_lock_minutes * 60:
                self.show_lock_screen()

    def reset_idle_timer(self):
        self.last_activity = datetime.datetime.now()

    def load_config_safe(self):
        try:
            return storage.load_config()
        except storage.ConfigLoadError:
            MsgBox.warning(self, i18n._t("error_title"), i18n._t("config_load_failed"))
            return storage.DEFAULT_CONFIG.copy()

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
            derived = crypto_utils.derive_key(pwd, self.master_salt)
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

        top_layout = QHBoxLayout()

        self.search_bar = QLineEdit()
        self.search_bar.textChanged.connect(self.filter_entries)
        self.search_bar.textChanged.connect(lambda: self.reset_idle_timer())
        top_layout.addWidget(self.search_bar)

        self.category_filter = QComboBox()
        self.category_filter.addItem(i18n._t("category_all"), "all")
        self.category_filter.addItem(i18n._t("category_website"), "website")
        self.category_filter.addItem(i18n._t("category_email"), "email")
        self.category_filter.addItem(i18n._t("category_social"), "social")
        self.category_filter.addItem(i18n._t("category_bank"), "bank")
        self.category_filter.addItem(i18n._t("category_other"), "other")
        self.category_filter.currentIndexChanged.connect(self.filter_entries)
        top_layout.addWidget(self.category_filter)

        self.gen_tool_btn = QPushButton()
        self.gen_tool_btn.clicked.connect(self.open_generator)
        top_layout.addWidget(self.gen_tool_btn)

        self.import_btn = QPushButton()
        self.import_btn.clicked.connect(self.import_data)
        top_layout.addWidget(self.import_btn)

        self.export_btn = QPushButton()
        self.export_btn.clicked.connect(self.export_data)
        top_layout.addWidget(self.export_btn)

        self.settings_btn = QPushButton()
        self.settings_btn.clicked.connect(self.open_settings)
        top_layout.addWidget(self.settings_btn)

        self.main_layout.addLayout(top_layout)

        batch_layout = QHBoxLayout()

        self.backup_btn = QPushButton()
        self.backup_btn.clicked.connect(self.create_backup)
        batch_layout.addWidget(self.backup_btn)

        self.restore_btn = QPushButton()
        self.restore_btn.clicked.connect(self.restore_backup)
        batch_layout.addWidget(self.restore_btn)

        batch_layout.addStretch()
        self.main_layout.addLayout(batch_layout)

        self.table = DragSelectTableWidget(0, 6)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QTableWidget.ExtendedSelection)
        self.table.doubleClicked.connect(self.on_table_double_click)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_context_menu)
        self.main_layout.addWidget(self.table)

        config = self.load_config_safe()
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

        QShortcut(QKeySequence("Ctrl+N"), self).activated.connect(self.add_entry)
        QShortcut(QKeySequence("Delete"), self).activated.connect(self.delete_entry)
        QShortcut(QKeySequence("Ctrl+F"), self).activated.connect(self.focus_search)

        self.retranslate_ui()

    def closeEvent(self, event):
        config = self.load_config_safe()
        config["column_widths"] = [self.table.columnWidth(i) for i in range(6)]
        try:
            storage.save_config(config)
        except storage.ConfigSaveError:
            MsgBox.warning(self, i18n._t("error_title"), i18n._t("config_save_failed"))
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

        self.category_filter.setItemText(0, i18n._t("category_all"))
        self.category_filter.setItemText(1, i18n._t("category_website"))
        self.category_filter.setItemText(2, i18n._t("category_email"))
        self.category_filter.setItemText(3, i18n._t("category_social"))
        self.category_filter.setItemText(4, i18n._t("category_bank"))
        self.category_filter.setItemText(5, i18n._t("category_other"))

        self.gen_tool_btn.setText(i18n._t("generator_btn"))
        self.import_btn.setText(i18n._t("import_btn"))
        self.export_btn.setText(i18n._t("export_btn"))
        self.backup_btn.setText(i18n._t("backup_btn"))
        self.restore_btn.setText(i18n._t("restore_btn"))
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
            storage.save_passwords(self.passwords, self.master_key, self.master_salt)
        except storage.PasswordSaveError:
            MsgBox.critical(self, i18n._t("error_title"), i18n._t("storage_save_failed"))
            return False

        config = self.load_config_safe()
        if config.get("auto_backup", False):
            os.makedirs(storage.BACKUP_DIR, exist_ok=True)
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = os.path.join(storage.BACKUP_DIR, f"passwords_backup_{timestamp}.json")
            try:
                storage.create_backup(backup_path)
            except storage.BackupError:
                self.statusBar().showMessage(i18n._t("backup_failed"), 3000)
        self.refresh_table()
        return True

    def open_generator(self):
        self.reset_idle_timer()
        gen = PasswordGenerator(self)
        gen.exec()

    def open_settings(self):
        self.reset_idle_timer()
        dialog = SettingsDialog(self)
        if dialog.exec():
            self.apply_auto_lock_settings()

    def change_master_password(self):
        self.reset_idle_timer()
        dialog = ChangePasswordDialog(self.master_key, self.master_salt, self)
        if dialog.exec():
            new_password = dialog.get_new_password()
            new_salt = crypto_utils.generate_salt()
            new_key = crypto_utils.derive_key(new_password, new_salt)
            self.master_key = new_key
            self.master_salt = new_salt
            if self.save_and_refresh():
                MsgBox.information(self, i18n._t("change_pass_title"), i18n._t("change_pass_success"))

    def create_backup(self):
        self.reset_idle_timer()
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        default_name = f"passwords_backup_{timestamp}.json"
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            i18n._t("backup_title"),
            default_name,
            "JSON Files (*.json);;All Files (*)",
        )
        if not file_path:
            return

        try:
            storage.create_backup(file_path)
            MsgBox.information(self, i18n._t("backup_title"), i18n._t("backup_success"))
            return
        except storage.BackupError:
            MsgBox.warning(self, i18n._t("error_title"), i18n._t("backup_failed"))

    def restore_backup(self):
        self.reset_idle_timer()
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            i18n._t("restore_title"),
            "",
            "JSON Files (*.json);;All Files (*)",
        )
        if not file_path:
            return

        reply = MsgBox.question(
            self,
            i18n._t("restore_title"),
            i18n._t("restore_confirm"),
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if reply == QMessageBox.Yes:
            try:
                storage.restore_backup(file_path, self.master_key, self.master_salt)
                result = storage.load_passwords_by_key(self.master_key, self.master_salt)
                self.passwords, self.master_key, self.master_salt = result
                self.refresh_table()
                MsgBox.information(self, i18n._t("restore_title"), i18n._t("restore_success"))
                return
            except (storage.BackupError, storage.PasswordLoadError):
                MsgBox.warning(self, i18n._t("error_title"), i18n._t("restore_failed"))


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

    try:
        config = storage.load_config()
    except storage.ConfigLoadError:
        MsgBox.warning(None, i18n._t("error_title"), i18n._t("config_load_failed"))
        config = storage.DEFAULT_CONFIG.copy()
    lang = config.get("language", "zh")
    i18n.set_language(lang)

    app._qt_translator = QTranslator(app)
    translations_path = QLibraryInfo.path(QLibraryInfo.LibraryPath.TranslationsPath)
    locale_name = "zh_CN" if lang == "zh" else "en"
    app._qt_translator.load(f"qt_{locale_name}", translations_path)
    app.installTranslator(app._qt_translator)

    if storage.is_first_run():
        while True:
            dialog = AuthDialog("setup")
            if not dialog.exec():
                sys.exit(0)

            pwd = dialog.get_password()
            init_salt = crypto_utils.generate_salt()
            init_key = crypto_utils.derive_key(pwd, init_salt)
            try:
                storage.save_passwords([], init_key, init_salt)
            except storage.PasswordSaveError:
                MsgBox.critical(None, i18n._t("error_title"), i18n._t("storage_save_failed"))
                sys.exit(1)
            master_password = pwd
            break
    else:
        while True:
            dialog = AuthDialog("login")
            if not dialog.exec():
                sys.exit(0)

            pwd = dialog.get_password()
            try:
                storage.load_passwords(pwd)
                master_password = pwd
                break
            except storage.PasswordLoadError as exc:
                if exc.reason == "wrong_password":
                    MsgBox.warning(None, i18n._t("error_title"), i18n._t("decrypt_error"))
                    continue
                MsgBox.critical(None, i18n._t("error_title"), i18n._t("storage_load_failed"))
                sys.exit(1)

    window = MainWindow(master_password)
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
