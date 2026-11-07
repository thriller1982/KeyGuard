import secrets
import string
import sys
import uuid

from PySide6.QtCore import QLibraryInfo, Qt, QTimer, QTranslator
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
    QFormLayout,
    QHeaderView,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QStyle,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QToolButton,
    QVBoxLayout,
)

import crypto_utils
import i18n
import storage
from crypto_utils import evaluate_password_strength, get_strength_color


CLIPBOARD_CLEAR_MS = 300000
PASSWORD_GENERATOR_MAX_LENGTH = 128


class MsgBox:
    """无声消息框。QMessageBox 在 Windows 上会触发系统提示音。"""

    _ICON_MAP = {
        QMessageBox.Information: QStyle.StandardPixmap.SP_MessageBoxInformation,
        QMessageBox.Warning: QStyle.StandardPixmap.SP_MessageBoxWarning,
        QMessageBox.Critical: QStyle.StandardPixmap.SP_MessageBoxCritical,
        QMessageBox.Question: QStyle.StandardPixmap.SP_MessageBoxQuestion,
    }

    @classmethod
    def _build(cls, parent, title, text, icon_enum, buttons, default):
        box = QMessageBox(parent)
        box.setWindowTitle(title)
        box.setText(text)
        box.setIcon(QMessageBox.NoIcon)
        sp = cls._ICON_MAP.get(icon_enum)
        if sp is not None:
            pixmap = QApplication.style().standardPixmap(sp)
            box.setIconPixmap(pixmap)
        box.setStandardButtons(buttons)
        box.setDefaultButton(default)
        return box

    @classmethod
    def information(cls, parent, title, text):
        return cls._build(
            parent,
            title,
            text,
            QMessageBox.Information,
            QMessageBox.Ok,
            QMessageBox.Ok,
        ).exec()

    @classmethod
    def warning(cls, parent, title, text):
        return cls._build(
            parent,
            title,
            text,
            QMessageBox.Warning,
            QMessageBox.Ok,
            QMessageBox.Ok,
        ).exec()

    @classmethod
    def critical(cls, parent, title, text):
        return cls._build(
            parent,
            title,
            text,
            QMessageBox.Critical,
            QMessageBox.Ok,
            QMessageBox.Ok,
        ).exec()

    @classmethod
    def question(
        cls,
        parent,
        title,
        text,
        buttons=QMessageBox.Yes | QMessageBox.No,
        default=QMessageBox.No,
    ):
        return cls._build(
            parent,
            title,
            text,
            QMessageBox.Question,
            buttons,
            default,
        ).exec()


class PasswordGenerator(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumWidth(300)

        self.clipboard_timer = QTimer()
        self.clipboard_timer.setSingleShot(True)
        self.clipboard_timer.timeout.connect(self.clear_clipboard)

        layout = QVBoxLayout(self)

        self.length_label = QLabel()
        self.length_input = QLineEdit("16")
        layout.addWidget(self.length_label)
        layout.addWidget(self.length_input)

        self.cb_upper = QCheckBox()
        self.cb_upper.setChecked(True)
        self.cb_lower = QCheckBox()
        self.cb_lower.setChecked(True)
        self.cb_digits = QCheckBox()
        self.cb_digits.setChecked(True)
        self.cb_symbols = QCheckBox()
        self.cb_symbols.setChecked(True)
        layout.addWidget(self.cb_upper)
        layout.addWidget(self.cb_lower)
        layout.addWidget(self.cb_digits)
        layout.addWidget(self.cb_symbols)

        self.result_label = QLabel()
        self.result_display = QLineEdit()
        self.result_display.setReadOnly(True)
        layout.addWidget(self.result_label)
        layout.addWidget(self.result_display)

        self.strength_label = QLabel()
        layout.addWidget(self.strength_label)

        btn_layout = QHBoxLayout()
        self.gen_btn = QPushButton()
        self.gen_btn.clicked.connect(self.generate)
        self.copy_btn = QPushButton()
        self.copy_btn.clicked.connect(self.copy_to_clipboard)
        btn_layout.addWidget(self.gen_btn)
        btn_layout.addWidget(self.copy_btn)
        layout.addLayout(btn_layout)

        self.retranslate_ui()

    def retranslate_ui(self):
        self.setWindowTitle(i18n._t("gen_title"))
        self.length_label.setText(i18n._t("gen_length"))
        self.result_label.setText(i18n._t("gen_result"))
        self.gen_btn.setText(i18n._t("gen_btn"))
        self.copy_btn.setText(i18n._t("gen_copy"))
        self.cb_upper.setText(i18n._t("gen_uppercase"))
        self.cb_lower.setText(i18n._t("gen_lowercase"))
        self.cb_digits.setText(i18n._t("gen_digits"))
        self.cb_symbols.setText(i18n._t("gen_symbols"))
        self.update_strength_display()

    def update_strength_display(self):
        password = self.result_display.text()
        if password:
            result = evaluate_password_strength(password)
            self.strength_label.setText(i18n._t("strength_score").format(result["score"]))

    def generate(self):
        try:
            length = int(self.length_input.text())
            if length < 1 or length > PASSWORD_GENERATOR_MAX_LENGTH:
                MsgBox.warning(self, i18n._t("error_title"), i18n._t("gen_invalid_len"))
                return

            alphabet = ""
            if self.cb_upper.isChecked():
                alphabet += string.ascii_uppercase
            if self.cb_lower.isChecked():
                alphabet += string.ascii_lowercase
            if self.cb_digits.isChecked():
                alphabet += string.digits
            if self.cb_symbols.isChecked():
                alphabet += string.punctuation

            if not alphabet:
                MsgBox.warning(self, i18n._t("error_title"), i18n._t("gen_no_charset"))
                return

            password = "".join(secrets.choice(alphabet) for _ in range(length))
            self.result_display.setText(password)
            self.update_strength_display()
        except ValueError:
            MsgBox.warning(self, i18n._t("error_title"), i18n._t("gen_invalid_len"))

    def copy_to_clipboard(self):
        text = self.result_display.text()
        if not text:
            return

        QApplication.clipboard().setText(text)
        parent = self.parent()
        if parent and hasattr(parent, "clipboard_timer"):
            parent.clipboard_timer.start(CLIPBOARD_CLEAR_MS)
            return
        self.clipboard_timer.start(CLIPBOARD_CLEAR_MS)

    def clear_clipboard(self):
        QApplication.clipboard().clear()


class PasswordHistoryDialog(QDialog):
    def __init__(self, history, parent=None):
        super().__init__(parent)
        self.setMinimumWidth(400)
        self.setMinimumHeight(300)
        self.history = history

        layout = QVBoxLayout(self)

        self.table = None
        if not history:
            layout.addWidget(QLabel(i18n._t("history_empty")))
        else:
            self.table = QTableWidget(len(history), 2, self)
            self.table.setHorizontalHeaderLabels(
                [i18n._t("history_date"), i18n._t("history_password")]
            )
            self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
            self.table.setEditTriggers(QTableWidget.NoEditTriggers)

            for i, item in enumerate(history):
                date_item = QTableWidgetItem(item.get("date", ""))
                pass_item = QTableWidgetItem("********")
                pass_item.setData(Qt.UserRole, item.get("password", ""))
                self.table.setItem(i, 0, date_item)
                self.table.setItem(i, 1, pass_item)

            self.table.cellDoubleClicked.connect(self.on_history_double_click)
            layout.addWidget(self.table)

        btn_layout = QHBoxLayout()
        self.close_btn = QPushButton(i18n._t("btn_ok"))
        self.close_btn.clicked.connect(self.accept)
        btn_layout.addStretch()
        btn_layout.addWidget(self.close_btn)
        layout.addLayout(btn_layout)

        self.retranslate_ui()

    def on_history_double_click(self, row, col):
        if col == 1:
            password = self.table.item(row, 1).data(Qt.UserRole)
            QApplication.clipboard().setText(password)

            p = self.parent()
            while p and not hasattr(p, "clipboard_timer"):
                p = p.parent()
            if p and hasattr(p, "clipboard_timer"):
                p.clipboard_timer.start(CLIPBOARD_CLEAR_MS)

            if p and hasattr(p, "statusBar"):
                p.statusBar().showMessage(i18n._t("copy_password_success"), 2000)

    def retranslate_ui(self):
        self.setWindowTitle(i18n._t("history_title"))
        self.close_btn.setText(i18n._t("btn_ok"))


class EntryDialog(QDialog):
    def __init__(self, parent=None, entry=None):
        super().__init__(parent)
        self.setMinimumWidth(450)
        self.entry = entry

        self.form_layout = QFormLayout(self)

        self.name_edit = QLineEdit(entry.get("name", "") if entry else "")
        self.url_edit = QLineEdit(entry.get("url", "") if entry else "")
        self.username_edit = QLineEdit(entry.get("username", "") if entry else "")
        self.password_edit = QLineEdit(entry.get("password", "") if entry else "")
        self.password_edit.setEchoMode(QLineEdit.Password)

        self.strength_bar = QProgressBar()
        self.strength_bar.setMaximum(100)
        self.strength_bar.setTextVisible(False)
        self.strength_bar.setFixedHeight(8)
        self.strength_label = QLabel()
        self.password_edit.textChanged.connect(self.update_password_strength)

        self.notes_edit = QTextEdit()
        self.notes_edit.setFont(
            QFont("Microsoft YaHei UI", 10)
            if sys.platform == "win32"
            else QFont("Sans Serif", 10)
        )
        self.notes_edit.setPlainText(entry.get("notes", "") if entry else "")
        self.notes_edit.setMaximumHeight(80)

        self.category_combo = QComboBox()
        self.category_combo.addItem(i18n._t("category_website"), "website")
        self.category_combo.addItem(i18n._t("category_email"), "email")
        self.category_combo.addItem(i18n._t("category_social"), "social")
        self.category_combo.addItem(i18n._t("category_bank"), "bank")
        self.category_combo.addItem(i18n._t("category_other"), "other")
        if entry and "category" in entry:
            index = self.category_combo.findData(entry.get("category", "other"))
            if index >= 0:
                self.category_combo.setCurrentIndex(index)

        self.toggle_btn = QToolButton()
        self.toggle_btn.setText(i18n._t("show_password"))
        self.toggle_btn.clicked.connect(self.toggle_password)

        self.save_btn = QPushButton()
        self.save_btn.clicked.connect(self.accept)
        self.cancel_btn = QPushButton()
        self.cancel_btn.clicked.connect(self.reject)

        self.history_btn = QPushButton()
        self.history_btn.clicked.connect(self.view_history)

        self._pass_layout = QHBoxLayout()
        self._pass_layout.addWidget(self.password_edit)
        self._pass_layout.addWidget(self.toggle_btn)

        self._strength_layout = QHBoxLayout()
        self._strength_layout.addWidget(self.strength_bar)
        self._strength_layout.addWidget(self.strength_label)

        self._history_layout = QHBoxLayout()
        if self.entry and self.entry.get("password_history"):
            self.history_btn.setText(i18n._t("entry_view_history"))
            self._history_layout.addWidget(self.history_btn)
        self._history_layout.addStretch()

        self._btn_layout = QHBoxLayout()
        self._btn_layout.addWidget(self.save_btn)
        self._btn_layout.addWidget(self.cancel_btn)

        self._row_labels = {}
        for key in (
            "entry_site",
            "entry_url",
            "entry_user",
            "entry_pass",
            "entry_category",
            "entry_notes",
        ):
            self._row_labels[key] = QLabel()

        self.form_layout.addRow(self._row_labels["entry_site"], self.name_edit)
        self.form_layout.addRow(self._row_labels["entry_url"], self.url_edit)
        self.form_layout.addRow(self._row_labels["entry_user"], self.username_edit)
        self.form_layout.addRow(self._row_labels["entry_pass"], self._pass_layout)
        self.form_layout.addRow("", self._strength_layout)
        self.form_layout.addRow(self._row_labels["entry_category"], self.category_combo)
        self.form_layout.addRow(self._row_labels["entry_notes"], self.notes_edit)
        self.form_layout.addRow("", self._history_layout)
        self.form_layout.addRow(self._btn_layout)

        self.retranslate_ui()
        self.update_password_strength()

    def retranslate_ui(self):
        self.setWindowTitle(i18n._t("entry_title"))
        for key, lbl in self._row_labels.items():
            lbl.setText(i18n._t(key))

        self.toggle_btn.setText(
            i18n._t("hide_password")
            if self.password_edit.echoMode() == QLineEdit.Normal
            else i18n._t("show_password")
        )

        if self.entry and self.entry.get("password_history"):
            self.history_btn.setText(i18n._t("entry_view_history"))

        self.save_btn.setText(i18n._t("entry_save"))
        self.cancel_btn.setText(i18n._t("entry_cancel"))

    def update_password_strength(self):
        password = self.password_edit.text()
        if not password:
            self.strength_bar.setValue(0)
            self.strength_label.setText("")
            return

        result = evaluate_password_strength(password)
        self.strength_bar.setValue(result["score"])

        color = get_strength_color(result["strength"])
        self.strength_bar.setStyleSheet(
            """
            QProgressBar {
                border: 1px solid #ccc;
                border-radius: 4px;
                background-color: #f0f0f0;
            }
            QProgressBar::chunk {
                background-color: %s;
                border-radius: 3px;
            }
        """
            % color
        )

        strength_text = i18n._t(f"strength_{result['strength']}")
        self.strength_label.setText(f"{strength_text} ({result['score']}/100)")

    def toggle_password(self):
        if self.password_edit.echoMode() == QLineEdit.Password:
            self.password_edit.setEchoMode(QLineEdit.Normal)
            self.toggle_btn.setText(i18n._t("hide_password"))
            return

        self.password_edit.setEchoMode(QLineEdit.Password)
        self.toggle_btn.setText(i18n._t("show_password"))

    def view_history(self):
        if self.entry and self.entry.get("password_history"):
            dialog = PasswordHistoryDialog(self.entry.get("password_history", []), self)
            dialog.exec()

    def accept(self):
        if not self.name_edit.text().strip():
            MsgBox.warning(self, i18n._t("error_title"), i18n._t("error_empty_name"))
            return
        super().accept()

    def get_data(self):
        return {
            "id": self.entry.get("id") if self.entry else uuid.uuid4().hex,
            "name": self.name_edit.text(),
            "url": self.url_edit.text(),
            "username": self.username_edit.text(),
            "password": self.password_edit.text(),
            "notes": self.notes_edit.toPlainText(),
            "category": self.category_combo.currentData(),
            "password_history": self.entry.get("password_history", []) if self.entry else [],
        }


class ChangePasswordDialog(QDialog):
    master_key: bytes
    master_salt: bytes

    def __init__(self, master_key: bytes, master_salt: bytes, kdf_spec: dict, parent=None):
        super().__init__(parent)
        self.master_key = master_key
        self.master_salt = master_salt
        self.kdf_spec = kdf_spec
        self.setMinimumWidth(350)

        layout = QVBoxLayout(self)
        self.form_layout = QFormLayout()

        self.old_pass_edit = QLineEdit()
        self.old_pass_edit.setEchoMode(QLineEdit.Password)
        self.new_pass_edit = QLineEdit()
        self.new_pass_edit.setEchoMode(QLineEdit.Password)
        self.confirm_pass_edit = QLineEdit()
        self.confirm_pass_edit.setEchoMode(QLineEdit.Password)

        self.old_pass_label = QLabel()
        self.new_pass_label = QLabel()
        self.confirm_pass_label = QLabel()

        self.form_layout.addRow(self.old_pass_label, self.old_pass_edit)
        self.form_layout.addRow(self.new_pass_label, self.new_pass_edit)
        self.form_layout.addRow(self.confirm_pass_label, self.confirm_pass_edit)
        layout.addLayout(self.form_layout)

        self.buttons = QHBoxLayout()
        self.save_btn = QPushButton()
        self.save_btn.clicked.connect(self.accept)
        self.cancel_btn = QPushButton()
        self.cancel_btn.clicked.connect(self.reject)
        self.buttons.addWidget(self.save_btn)
        self.buttons.addWidget(self.cancel_btn)
        layout.addLayout(self.buttons)

        self.retranslate_ui()

    def retranslate_ui(self):
        self.setWindowTitle(i18n._t("change_pass_title"))
        self.old_pass_label.setText(i18n._t("old_pass_label"))
        self.new_pass_label.setText(i18n._t("new_pass_label"))
        self.confirm_pass_label.setText(i18n._t("confirm_new_pass_label"))
        self.save_btn.setText(i18n._t("entry_save"))
        self.cancel_btn.setText(i18n._t("entry_cancel"))

    def accept(self):
        old_pass = self.old_pass_edit.text()
        new_pass = self.new_pass_edit.text()
        confirm_pass = self.confirm_pass_edit.text()

        derived = crypto_utils.derive_key_for_kdf(
            old_pass, self.master_salt, self.kdf_spec
        )
        if not secrets.compare_digest(derived, self.master_key):
            MsgBox.warning(self, i18n._t("error_title"), i18n._t("error_old_pass"))
            return

        if not new_pass:
            MsgBox.warning(self, i18n._t("error_title"), i18n._t("error_empty_pass"))
            return

        if new_pass != confirm_pass:
            MsgBox.warning(self, i18n._t("error_title"), i18n._t("error_new_pass_match"))
            return

        result = evaluate_password_strength(new_pass)
        if result["strength"] == "weak":
            MsgBox.warning(self, i18n._t("error_title"), i18n._t("password_too_weak"))
            return

        super().accept()

    def get_new_password(self):
        return self.new_pass_edit.text()


class AuthDialog(QDialog):
    def __init__(self, mode: str, parent=None, *, title: str | None = None, message: str | None = None):
        super().__init__(parent)
        self.mode = mode
        self._override_title = title
        self._override_message = message
        self.setMinimumWidth(360)

        layout = QVBoxLayout(self)

        self.message_label = QLabel()
        layout.addWidget(self.message_label)

        form_layout = QFormLayout()
        self.password_label = QLabel()
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)
        form_layout.addRow(self.password_label, self.password_edit)

        self.confirm_label = QLabel()
        self.confirm_edit = QLineEdit()
        self.confirm_edit.setEchoMode(QLineEdit.Password)
        self.strength_label = QLabel()

        if self.mode == "setup":
            form_layout.addRow(self.confirm_label, self.confirm_edit)
            form_layout.addRow("", self.strength_label)
            self.password_edit.textChanged.connect(self.update_strength)

        layout.addLayout(form_layout)

        btn_layout = QHBoxLayout()
        self.submit_btn = QPushButton()
        self.submit_btn.clicked.connect(self.accept)
        self.cancel_btn = QPushButton()
        self.cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(self.submit_btn)
        btn_layout.addWidget(self.cancel_btn)
        layout.addLayout(btn_layout)

        self.password_edit.returnPressed.connect(self.accept)
        self.confirm_edit.returnPressed.connect(self.accept)

        self.retranslate_ui()
        self.password_edit.setFocus()

    def retranslate_ui(self):
        self.password_label.setText(i18n._t("auth_password_label"))
        self.cancel_btn.setText(i18n._t("entry_cancel"))

        if self._override_title:
            self.setWindowTitle(self._override_title)
        elif self.mode == "setup":
            self.setWindowTitle(i18n._t("setup_title"))
        else:
            self.setWindowTitle(i18n._t("login_title"))

        if self._override_message:
            self.message_label.setText(self._override_message)
        elif self.mode == "setup":
            self.message_label.setText(i18n._t("setup_msg"))
        else:
            self.message_label.setText(i18n._t("login_msg"))

        if self.mode == "setup":
            self.confirm_label.setText(i18n._t("confirm_new_pass_label"))
            self.submit_btn.setText(i18n._t("auth_setup_btn"))
            self.update_strength()
            return

        self.submit_btn.setText(i18n._t("auth_login_btn"))

    def update_strength(self):
        if self.mode != "setup":
            return
        password = self.password_edit.text()
        if not password:
            self.strength_label.setText("")
            return
        result = evaluate_password_strength(password)
        strength_text = i18n._t(f"strength_{result['strength']}")
        self.strength_label.setText(
            f"{strength_text} ({result['score']}/100)"
        )

    def accept(self):
        password = self.password_edit.text()
        if not password:
            MsgBox.warning(self, i18n._t("error_title"), i18n._t("error_empty_pass"))
            return

        if self.mode == "setup":
            if password != self.confirm_edit.text():
                MsgBox.warning(self, i18n._t("error_title"), i18n._t("error_new_pass_match"))
                return

            result = evaluate_password_strength(password)
            if result["strength"] == "weak":
                MsgBox.warning(self, i18n._t("error_title"), i18n._t("password_too_weak"))
                return

        super().accept()

    def get_password(self):
        return self.password_edit.text()


class LockScreen(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowFlag(Qt.WindowStaysOnTopHint)
        self.setWindowFlag(Qt.WindowCloseButtonHint, False)
        self.setModal(True)
        self.setMinimumWidth(300)

        layout = QVBoxLayout(self)

        self.title_label = QLabel(i18n._t("lock_screen_title"))
        self.title_label.setStyleSheet("font-size: 18px; font-weight: bold;")
        self.title_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.title_label)

        self.msg_label = QLabel(i18n._t("lock_screen_msg"))
        layout.addWidget(self.msg_label)

        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)
        self.password_edit.returnPressed.connect(self.try_unlock)
        layout.addWidget(self.password_edit)

        self.unlock_btn = QPushButton(i18n._t("unlock_btn"))
        self.unlock_btn.clicked.connect(self.try_unlock)
        layout.addWidget(self.unlock_btn)

    def try_unlock(self):
        self.accept()

    def reject(self):
        return None


class SettingsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumWidth(320)
        self._prefs = self._load_prefs(parent)

        layout = QVBoxLayout(self)
        form = QFormLayout()

        self.auto_lock_combo = QComboBox()
        self.auto_lock_combo.addItem(i18n._t("auto_lock_never"), 0)
        self.auto_lock_combo.addItem(i18n._t("auto_lock_1min"), 1)
        self.auto_lock_combo.addItem(i18n._t("auto_lock_5min"), 5)
        self.auto_lock_combo.addItem(i18n._t("auto_lock_15min"), 15)
        self.auto_lock_combo.addItem(i18n._t("auto_lock_30min"), 30)

        auto_lock = self._prefs.get("auto_lock_minutes", 0)
        index = self.auto_lock_combo.findData(auto_lock)
        if index >= 0:
            self.auto_lock_combo.setCurrentIndex(index)
        form.addRow(i18n._t("settings_auto_lock"), self.auto_lock_combo)

        self.lang_combo = QComboBox()
        self.lang_combo.addItem("English", "en")
        self.lang_combo.addItem("简体中文", "zh")
        lang_index = self.lang_combo.findData(
            self._prefs.get("language", i18n.current_lang)
        )
        if lang_index >= 0:
            self.lang_combo.setCurrentIndex(lang_index)
        form.addRow(i18n._t("settings_language"), self.lang_combo)

        layout.addLayout(form)

        self.change_pass_btn = QPushButton(i18n._t("change_master_pass_btn"))
        self.change_pass_btn.clicked.connect(self.open_change_password)
        layout.addWidget(self.change_pass_btn)

        self.assoc_btn = QPushButton()
        self.assoc_btn.clicked.connect(self.toggle_association)
        layout.addWidget(self.assoc_btn)

        self.assoc_status_label = QLabel()
        layout.addWidget(self.assoc_status_label)

        btn_layout = QHBoxLayout()
        self.save_btn = QPushButton(i18n._t("entry_save"))
        self.save_btn.clicked.connect(self.save_settings)
        self.cancel_btn = QPushButton(i18n._t("entry_cancel"))
        self.cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(self.save_btn)
        btn_layout.addWidget(self.cancel_btn)
        layout.addLayout(btn_layout)

        self.retranslate_ui()

    def _load_prefs(self, parent):
        if parent is not None and hasattr(parent, "preferences"):
            return dict(parent.preferences)
        try:
            return storage.load_config()
        except storage.ConfigLoadError:
            return storage.DEFAULT_PREFERENCES.copy()

    def retranslate_ui(self):
        self.setWindowTitle(i18n._t("settings_title"))
        if hasattr(self, "save_btn"):
            self.save_btn.setText(i18n._t("entry_save"))
            self.cancel_btn.setText(i18n._t("entry_cancel"))
            self.change_pass_btn.setText(i18n._t("change_master_pass_btn"))
            self._refresh_assoc_ui()

    def _refresh_assoc_ui(self):
        if not hasattr(self, "assoc_btn"):
            return
        active = storage.is_kgvault_associated()
        if storage._current_exe_path() is None:
            self.assoc_btn.setText(i18n._t("vault_assoc_btn"))
            self.assoc_btn.setEnabled(False)
            self.assoc_status_label.setText(i18n._t("vault_assoc_unsupported"))
            return
        if active:
            self.assoc_btn.setText(i18n._t("vault_assoc_remove_btn"))
            self.assoc_btn.setEnabled(True)
            self.assoc_status_label.setText(i18n._t("vault_assoc_active"))
        else:
            self.assoc_btn.setText(i18n._t("vault_assoc_btn"))
            self.assoc_btn.setEnabled(True)
            self.assoc_status_label.setText(i18n._t("vault_assoc_inactive"))

    def toggle_association(self):
        if storage._current_exe_path() is None:
            MsgBox.warning(self, i18n._t("error_title"), i18n._t("vault_assoc_unsupported"))
            return
        if storage.is_kgvault_associated():
            storage.unregister_kgvault_association()
            MsgBox.information(self, i18n._t("settings_title"), i18n._t("vault_assoc_removed"))
        else:
            if storage.register_kgvault_association():
                MsgBox.information(self, i18n._t("settings_title"), i18n._t("vault_assoc_success"))
            else:
                MsgBox.warning(self, i18n._t("error_title"), i18n._t("vault_assoc_failed"))
        self._refresh_assoc_ui()

    def save_settings(self):
        new_lang = self.lang_combo.currentData()
        lang_changed = new_lang != self._prefs.get("language", i18n.current_lang)

        self._prefs["auto_lock_minutes"] = self.auto_lock_combo.currentData()
        self._prefs["language"] = new_lang

        parent = self.parent()
        if parent is not None and hasattr(parent, "save_preferences"):
            if not parent.save_preferences(self._prefs):
                MsgBox.warning(self, i18n._t("error_title"), i18n._t("vault_save_failed"))
                return
        else:
            try:
                storage.save_config(self._prefs)
            except storage.ConfigSaveError:
                MsgBox.warning(self, i18n._t("error_title"), i18n._t("config_save_failed"))
                return

        if lang_changed:
            i18n.set_language(new_lang)
            app = QApplication.instance()
            if hasattr(app, "_qt_translator"):
                app.removeTranslator(app._qt_translator)
            app._qt_translator = QTranslator()

            translations_path = QLibraryInfo.path(QLibraryInfo.LibraryPath.TranslationsPath)
            locale_name = "zh_CN" if new_lang == "zh" else "en"
            app._qt_translator.load(f"qt_{locale_name}", translations_path)
            app.installTranslator(app._qt_translator)

            if parent and hasattr(parent, "retranslate_ui"):
                parent.retranslate_ui()
            if parent and hasattr(parent, "refresh_table"):
                parent.refresh_table()
            self.retranslate_ui()

        self.accept()

    def open_change_password(self):
        parent = self.parent()
        if parent and hasattr(parent, "change_master_password"):
            parent.change_master_password()


class VaultPickerDialog(QDialog):
    """启动时让用户选择新建或打开保险库的对话框。"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumWidth(360)
        self.chosen_path = None
        self.chosen_action = None  # "new" | "open"

        layout = QVBoxLayout(self)

        self.title_label = QLabel(i18n._t("vault_picker_title"))
        self.title_label.setStyleSheet("font-size: 16px; font-weight: bold;")
        self.title_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.title_label)

        self.msg_label = QLabel(i18n._t("vault_picker_msg"))
        self.msg_label.setWordWrap(True)
        layout.addWidget(self.msg_label)

        btn_layout = QHBoxLayout()
        self.new_btn = QPushButton(i18n._t("vault_picker_new"))
        self.new_btn.clicked.connect(self.choose_new)
        self.open_btn = QPushButton(i18n._t("vault_picker_open"))
        self.open_btn.clicked.connect(self.choose_open)
        btn_layout.addWidget(self.new_btn)
        btn_layout.addWidget(self.open_btn)
        layout.addLayout(btn_layout)

        cancel_layout = QHBoxLayout()
        self.cancel_btn = QPushButton(i18n._t("entry_cancel"))
        self.cancel_btn.clicked.connect(self.reject)
        cancel_layout.addStretch()
        cancel_layout.addWidget(self.cancel_btn)
        layout.addLayout(cancel_layout)

        self.retranslate_ui()

    def retranslate_ui(self):
        self.setWindowTitle(i18n._t("vault_picker_title"))
        self.title_label.setText(i18n._t("vault_picker_title"))
        self.msg_label.setText(i18n._t("vault_picker_msg"))
        self.new_btn.setText(i18n._t("vault_picker_new"))
        self.open_btn.setText(i18n._t("vault_picker_open"))
        self.cancel_btn.setText(i18n._t("entry_cancel"))

    def choose_new(self):
        path, _ = QFileDialog.getSaveFileName(
            self,
            i18n._t("vault_new_btn"),
            storage.DEFAULT_VAULT_PATH,
            i18n._t("vault_filter"),
        )
        if not path:
            return
        self.chosen_path = path
        self.chosen_action = "new"
        self.accept()

    def choose_open(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            i18n._t("vault_open_btn"),
            "",
            i18n._t("vault_filter"),
        )
        if not path:
            return
        self.chosen_path = path
        self.chosen_action = "open"
        self.accept()


class TwoFactorDialog(QDialog):
    def __init__(self, parent=None, initial_secret=""):
        super().__init__(parent)
        self.setMinimumWidth(380)

        self.current_code = ""

        layout = QVBoxLayout(self)

        self.secret_label = QLabel()
        self.secret_input = QLineEdit(initial_secret)
        self.secret_input.setClearButtonEnabled(True)
        self.secret_input.textChanged.connect(self.on_secret_changed)
        layout.addWidget(self.secret_label)
        layout.addWidget(self.secret_input)

        self.code_display = QLabel("------")
        self.code_display.setAlignment(Qt.AlignCenter)
        code_font = QFont("Consolas, Courier New, Monospace", 26)
        code_font.setBold(True)
        self.code_display.setFont(code_font)
        self.code_display.setStyleSheet(
            "QLabel { background-color: #f0f3f6; border-radius: 6px; padding: 12px; color: #2c3e50; }"
        )
        layout.addWidget(self.code_display)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 30)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setFixedHeight(6)
        layout.addWidget(self.progress_bar)

        self.status_label = QLabel()
        self.status_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.status_label)

        btn_layout = QHBoxLayout()
        self.copy_btn = QPushButton()
        self.copy_btn.clicked.connect(self.copy_code)
        self.close_btn = QPushButton()
        self.close_btn.clicked.connect(self.accept)
        btn_layout.addWidget(self.copy_btn)
        btn_layout.addWidget(self.close_btn)
        layout.addLayout(btn_layout)

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_code)
        self.timer.start(1000)

        self.retranslate_ui()
        self.update_code()

    def retranslate_ui(self):
        self.setWindowTitle(i18n._t("totp_title"))
        self.secret_label.setText(i18n._t("totp_secret_label"))
        self.secret_input.setPlaceholderText(i18n._t("totp_secret_placeholder"))
        self.copy_btn.setText(i18n._t("totp_copy_btn"))
        self.close_btn.setText(i18n._t("btn_ok"))
        self.update_code()

    def on_secret_changed(self):
        self.update_code()

    def update_code(self):
        secret = self.secret_input.text()
        code, remaining, status = crypto_utils.generate_totp(secret)

        self.progress_bar.setValue(remaining)
        if remaining <= 5:
            self.progress_bar.setStyleSheet(
                "QProgressBar { background: #e0e0e0; border-radius: 3px; border: none; }"
                "QProgressBar::chunk { background: #e74c3c; border-radius: 3px; }"
            )
        else:
            self.progress_bar.setStyleSheet(
                "QProgressBar { background: #e0e0e0; border-radius: 3px; border: none; }"
                "QProgressBar::chunk { background: #3498db; border-radius: 3px; }"
            )

        if status == "ok":
            self.current_code = code
            formatted = f"{code[:3]} {code[3:]}" if len(code) == 6 else code
            self.code_display.setText(formatted)
            self.status_label.setText(i18n._t("totp_countdown").format(sec=remaining))
            self.status_label.setStyleSheet("color: #7f8c8d;")
            self.copy_btn.setEnabled(True)
        elif status == "invalid":
            self.current_code = ""
            self.code_display.setText("------")
            self.status_label.setText(i18n._t("totp_invalid_secret"))
            self.status_label.setStyleSheet("color: #e74c3c;")
            self.copy_btn.setEnabled(False)
        else:
            self.current_code = ""
            self.code_display.setText("------")
            self.status_label.setText(i18n._t("totp_empty_hint"))
            self.status_label.setStyleSheet("color: #7f8c8d;")
            self.copy_btn.setEnabled(False)

    def copy_code(self):
        if self.current_code:
            QApplication.clipboard().setText(self.current_code)
            self.copy_btn.setText(i18n._t("totp_copied"))
            QTimer.singleShot(1500, lambda: self.copy_btn.setText(i18n._t("totp_copy_btn")))

    def get_secret(self):
        return self.secret_input.text().strip()
