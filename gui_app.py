import sys
from datetime import datetime
from pathlib import Path

from PyQt6.QtCore import QProcess, QProcessEnvironment, Qt
from PyQt6.QtGui import QAction, QColor, QFont
from PyQt6.QtWidgets import (
    QApplication,
    QDoubleSpinBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPushButton,
    QPlainTextEdit,
    QSpinBox,
    QSystemTrayIcon,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from app_config import get_default_config, get_default_config_path, load_config, save_config


class SafeScreenWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("SafeScreen")
        self.resize(1080, 760)

        self.config_path = get_default_config_path()
        self.config = load_config(self.config_path)

        self.force_close = False
        self.minimize_to_tray_notice_shown = False
        self.stdout_buffer = ""
        self.stderr_buffer = ""
        self.stop_requested = False
        self.stop_force_kill = False

        self.shield_process = QProcess(self)
        self.shield_process.readyReadStandardOutput.connect(self._read_stdout)
        self.shield_process.readyReadStandardError.connect(self._read_stderr)
        self.shield_process.errorOccurred.connect(self._on_process_error)
        self.shield_process.finished.connect(self._on_process_finished)

        self.status_label = QLabel("Защита: ВЫКЛ")
        self.status_label.setObjectName("statusLabel")
        self.log_output = QPlainTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setPlaceholderText("Здесь будут отображаться логи защиты...")

        self.events_list = QListWidget()
        self.events_list.setObjectName("eventsList")

        self.start_button = QPushButton("Запустить защиту")
        self.stop_button = QPushButton("Остановить")
        self.clear_log_button = QPushButton("Очистить лог")
        self.clear_events_button = QPushButton("Очистить события")

        self.start_button.clicked.connect(self.start_protection)
        self.stop_button.clicked.connect(self.stop_protection)
        self.clear_log_button.clicked.connect(self.log_output.clear)
        self.clear_events_button.clicked.connect(self.events_list.clear)

        self.stop_button.setEnabled(False)

        self._build_ui()
        self._apply_style()
        self._setup_tray()
        self._load_settings_to_ui()

    def _build_ui(self) -> None:
        root = QWidget()
        self.setCentralWidget(root)

        layout = QVBoxLayout(root)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(16)

        title = QLabel("Safescreen")
        title.setObjectName("title")
        subtitle = QLabel("Интеллектуальная защита экрана от визуальных утечек данных")
        subtitle.setObjectName("subtitle")

        header = QVBoxLayout()
        header.addWidget(title)
        header.addWidget(subtitle)
        header.setSpacing(6)

        self.tabs = QTabWidget()
        self.tabs.addTab(self._create_monitor_tab(), "Мониторинг")
        self.tabs.addTab(self._create_settings_tab(), "Настройки")

        layout.addLayout(header)
        layout.addWidget(self.tabs)

    def _create_monitor_tab(self) -> QWidget:
        page = QWidget()
        page_layout = QVBoxLayout(page)
        page_layout.setContentsMargins(4, 6, 4, 4)
        page_layout.setSpacing(14)

        top_card = QFrame()
        top_card.setObjectName("card")
        top_layout = QVBoxLayout(top_card)
        top_layout.setContentsMargins(16, 16, 16, 16)
        top_layout.setSpacing(10)

        controls = QHBoxLayout()
        controls.setSpacing(10)
        controls.addWidget(self.start_button)
        controls.addWidget(self.stop_button)
        controls.addWidget(self.clear_log_button)
        controls.addWidget(self.clear_events_button)
        controls.addStretch(1)
        controls.addWidget(self.status_label)

        top_layout.addLayout(controls)

        panel_row = QHBoxLayout()
        panel_row.setSpacing(12)

        events_card = QFrame()
        events_card.setObjectName("cardSub")
        events_layout = QVBoxLayout(events_card)
        events_layout.setContentsMargins(12, 12, 12, 12)
        events_layout.setSpacing(8)
        events_layout.addWidget(QLabel("Лента угроз"))
        events_layout.addWidget(self.events_list)

        logs_card = QFrame()
        logs_card.setObjectName("cardSub")
        logs_layout = QVBoxLayout(logs_card)
        logs_layout.setContentsMargins(12, 12, 12, 12)
        logs_layout.setSpacing(8)
        logs_layout.addWidget(QLabel("Лог процесса"))
        logs_layout.addWidget(self.log_output)

        panel_row.addWidget(events_card, 2)
        panel_row.addWidget(logs_card, 3)

        top_layout.addLayout(panel_row)
        page_layout.addWidget(top_card)

        return page

    def _create_settings_tab(self) -> QWidget:
        page = QWidget()
        page_layout = QVBoxLayout(page)
        page_layout.setContentsMargins(4, 6, 4, 4)
        page_layout.setSpacing(14)

        card = QFrame()
        card.setObjectName("card")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(18, 18, 18, 18)
        card_layout.setSpacing(14)

        self.tesseract_input = QLineEdit()
        self.tesseract_input.setPlaceholderText(r"C:\Program Files\Tesseract-OCR\tesseract.exe")
        self.tesseract_input.setToolTip("Путь к исполняемому файлу tesseract.exe")

        self.protection_level_input = QSpinBox()
        self.protection_level_input.setRange(1, 5)
        self.protection_level_input.setToolTip("1 = только критические слова, 5 = все уровни словаря")
        self.protection_level_input.valueChanged.connect(self._update_level_text)
        self.protection_level_value_label = QLabel()
        self.protection_level_value_label.setObjectName("settingsHint")
        self._update_level_text(self.protection_level_input.value())
        level_widget = QWidget()
        level_layout = QHBoxLayout(level_widget)
        level_layout.setContentsMargins(0, 0, 0, 0)
        level_layout.setSpacing(10)
        level_layout.addWidget(self.protection_level_input, 0)
        level_layout.addWidget(self.protection_level_value_label, 1)

        self.max_windows_input = QSpinBox()
        self.max_windows_input.setRange(1, 30)
        self.max_windows_input.setToolTip("Сколько окон одновременно анализировать")

        self.shield_padding_input = QSpinBox()
        self.shield_padding_input.setRange(0, 200)
        self.shield_padding_input.setToolTip("Отступ защитного слоя вокруг окна")

        self.recheck_interval_input = QDoubleSpinBox()
        self.recheck_interval_input.setRange(1.0, 600.0)
        self.recheck_interval_input.setDecimals(1)
        self.recheck_interval_input.setToolTip("Через сколько секунд повторно сканировать ранее найденную угрозу")

        self.memory_duration_input = QDoubleSpinBox()
        self.memory_duration_input.setRange(1.0, 1200.0)
        self.memory_duration_input.setDecimals(1)
        self.memory_duration_input.setToolTip("Сколько секунд удерживать окно в списке угроз")

        self.scanner_sleep_input = QDoubleSpinBox()
        self.scanner_sleep_input.setRange(0.01, 1.0)
        self.scanner_sleep_input.setSingleStep(0.01)
        self.scanner_sleep_input.setDecimals(2)
        self.scanner_sleep_input.setToolTip("Пауза между итерациями цикла сканирования")

        self.whitelist_input = QTextEdit()
        self.whitelist_input.setPlaceholderText("Слова, которые нужно игнорировать.\nПо одному в строке или через запятую.")

        self.blacklist_input = QTextEdit()
        self.blacklist_input.setPlaceholderText("Слова, которые всегда считаются угрозой.\nПо одному в строке или через запятую.")

        settings_rows = QVBoxLayout()
        settings_rows.setSpacing(10)
        settings_rows.addWidget(
            self._make_setting_row(
                "Путь к Tesseract",
                "Где находится tesseract.exe на компьютере.",
                self.tesseract_input,
            )
        )
        settings_rows.addWidget(
            self._make_setting_row(
                "Уровень защиты",
                "1 = только критические слова (пароль и т.п.), 5 = максимальный охват.",
                level_widget,
            )
        )
        settings_rows.addWidget(
            self._make_setting_row(
                "Максимум окон",
                "Сколько окон одновременно сканировать в одном цикле.",
                self.max_windows_input,
            )
        )
        settings_rows.addWidget(
            self._make_setting_row(
                "Отступ щита",
                "Дополнительная зона перекрытия вокруг окна при блокировке.",
                self.shield_padding_input,
            )
        )
        settings_rows.addWidget(
            self._make_setting_row(
                "Интервал перескана",
                "Как часто повторно проверять окно с уже обнаруженной угрозой.",
                self.recheck_interval_input,
            )
        )
        settings_rows.addWidget(
            self._make_setting_row(
                "Время памяти угрозы",
                "Сколько времени хранить угрозу в активном списке.",
                self.memory_duration_input,
            )
        )
        settings_rows.addWidget(
            self._make_setting_row(
                "Пауза сканера",
                "Пауза между циклами: выше значение снижает нагрузку на CPU.",
                self.scanner_sleep_input,
            )
        )

        self.settings_status = QLabel("Измените параметры и нажмите «Сохранить настройки».")
        self.settings_status.setObjectName("settingsHint")

        btn_row = QHBoxLayout()
        btn_row.setSpacing(10)
        self.save_settings_button = QPushButton("Сохранить настройки")
        self.defaults_button = QPushButton("Сбросить к значениям по умолчанию")
        self.save_settings_button.clicked.connect(self.save_settings)
        self.defaults_button.clicked.connect(self.reset_defaults)
        btn_row.addWidget(self.save_settings_button)
        btn_row.addWidget(self.defaults_button)
        btn_row.addStretch(1)

        word_row = QHBoxLayout()
        word_row.setSpacing(12)

        white_card = QFrame()
        white_card.setObjectName("cardSub")
        white_layout = QVBoxLayout(white_card)
        white_layout.setContentsMargins(10, 10, 10, 10)
        white_layout.setSpacing(6)
        white_title = QLabel("Белый список")
        white_title.setObjectName("sectionTitle")
        white_layout.addWidget(white_title)
        white_layout.addWidget(self.whitelist_input)

        black_card = QFrame()
        black_card.setObjectName("cardSub")
        black_layout = QVBoxLayout(black_card)
        black_layout.setContentsMargins(10, 10, 10, 10)
        black_layout.setSpacing(6)
        black_title = QLabel("Черный список")
        black_title.setObjectName("sectionTitle")
        black_layout.addWidget(black_title)
        black_layout.addWidget(self.blacklist_input)

        word_row.addWidget(white_card)
        word_row.addWidget(black_card)

        card_layout.addLayout(settings_rows)
        card_layout.addLayout(word_row)
        card_layout.addLayout(btn_row)
        card_layout.addWidget(self.settings_status)

        page_layout.addWidget(card)
        return page

    def _apply_style(self) -> None:
        QApplication.instance().setFont(QFont("Segoe UI", 10))
        self.setStyleSheet(
            """
            QMainWindow {
                background-color: #eef2f5;
            }
            QLabel#title {
                font-size: 28px;
                font-weight: 700;
                color: #141b24;
            }
            QLabel#subtitle {
                font-size: 13px;
                color: #566271;
            }
            QTabWidget::pane {
                border: none;
            }
            QTabBar::tab {
                background: #dce4ec;
                color: #2b3a4b;
                border-radius: 8px;
                padding: 8px 14px;
                margin-right: 6px;
                font-weight: 600;
            }
            QTabBar::tab:selected {
                background: #1d3557;
                color: #ffffff;
            }
            QFrame#card {
                background-color: #ffffff;
                border: 1px solid #d7dee6;
                border-radius: 14px;
            }
            QFrame#cardSub {
                background-color: #f8fbff;
                border: 1px solid #d7e2ee;
                border-radius: 12px;
            }
            QPlainTextEdit, QTextEdit, QListWidget, QLineEdit, QSpinBox, QDoubleSpinBox {
                border: 1px solid #c8d3df;
                border-radius: 9px;
                background-color: #ffffff;
                padding: 6px;
                color: #1a2430;
            }
            QPlainTextEdit {
                background-color: #0f141a;
                color: #d9e3ee;
                border: 1px solid #242d37;
                font-family: "Cascadia Mono", "Consolas", monospace;
                font-size: 12px;
            }
            QPushButton {
                background-color: #1d3557;
                color: #ffffff;
                border: none;
                border-radius: 9px;
                padding: 9px 14px;
                font-weight: 600;
            }
            QPushButton:hover {
                background-color: #27466f;
            }
            QPushButton:disabled {
                background-color: #a7b5c5;
                color: #eef3f8;
            }
            QLabel#statusLabel {
                font-weight: 700;
                color: #8f1d1d;
                background: #fdeaea;
                border: 1px solid #f2bcbc;
                border-radius: 8px;
                padding: 6px 10px;
            }
            QLabel#settingsHint {
                color: #4f5c6c;
                font-size: 12px;
            }
            QLabel#settingTitle {
                color: #1b2635;
                font-size: 13px;
                font-weight: 600;
                margin-bottom: 1px;
            }
            QLabel#settingDesc {
                color: #6b7888;
                font-size: 12px;
                margin-bottom: 5px;
            }
            QLabel#sectionTitle {
                color: #1b2635;
                font-size: 13px;
                font-weight: 600;
            }
            """
        )

    def _make_setting_row(self, title: str, description: str, widget: QWidget) -> QFrame:
        row = QFrame()
        row.setObjectName("settingRow")
        layout = QVBoxLayout(row)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)

        title_label = QLabel(title)
        title_label.setObjectName("settingTitle")
        desc_label = QLabel(description)
        desc_label.setObjectName("settingDesc")
        desc_label.setWordWrap(True)

        layout.addWidget(title_label)
        layout.addWidget(desc_label)
        layout.addWidget(widget)
        return row

    def _setup_tray(self) -> None:
        if not QSystemTrayIcon.isSystemTrayAvailable():
            self.tray_icon = None
            return

        self.tray_icon = QSystemTrayIcon(self.style().standardIcon(self.style().StandardPixmap.SP_ComputerIcon), self)

        menu = QMenu(self)
        open_action = QAction("Открыть", self)
        start_action = QAction("Запустить защиту", self)
        stop_action = QAction("Остановить защиту", self)
        exit_action = QAction("Выход", self)

        open_action.triggered.connect(self.show_window)
        start_action.triggered.connect(self.start_protection)
        stop_action.triggered.connect(self.stop_protection)
        exit_action.triggered.connect(self.exit_from_tray)

        menu.addAction(open_action)
        menu.addSeparator()
        menu.addAction(start_action)
        menu.addAction(stop_action)
        menu.addSeparator()
        menu.addAction(exit_action)

        self.tray_icon.setContextMenu(menu)
        self.tray_icon.activated.connect(self._on_tray_activated)
        self.tray_icon.show()

    def _on_tray_activated(self, reason: QSystemTrayIcon.ActivationReason) -> None:
        if reason in (QSystemTrayIcon.ActivationReason.Trigger, QSystemTrayIcon.ActivationReason.DoubleClick):
            self.show_window()

    def show_window(self) -> None:
        self.show()
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def exit_from_tray(self) -> None:
        self.force_close = True
        self.close()

    def _hide_to_tray_from_minimize(self) -> None:
        if not self.tray_icon:
            return
        if self.isVisible():
            self.hide()
        if not self.minimize_to_tray_notice_shown:
            self.tray_icon.showMessage(
                "SafeScreen",
                "Приложение свернуто в системный трей.",
                QSystemTrayIcon.MessageIcon.Information,
                1500,
            )
            self.minimize_to_tray_notice_shown = True

    def _load_settings_to_ui(self) -> None:
        cfg = self.config
        self.tesseract_input.setText(cfg["tesseract_cmd"])
        self.protection_level_input.setValue(int(cfg["protection_level"]))
        self.max_windows_input.setValue(int(cfg["max_windows_to_check"]))
        self.shield_padding_input.setValue(int(cfg["shield_padding"]))
        self.recheck_interval_input.setValue(float(cfg["recheck_interval"]))
        self.memory_duration_input.setValue(float(cfg["memory_duration"]))
        self.scanner_sleep_input.setValue(float(cfg["scanner_sleep"]))
        self.whitelist_input.setPlainText("\n".join(cfg.get("whitelist_words", [])))
        self.blacklist_input.setPlainText("\n".join(cfg.get("blacklist_words", [])))

    @staticmethod
    def _parse_word_list(text: str) -> list[str]:
        chunked = text.replace("\n", ",").split(",")
        out = []
        seen = set()
        for item in chunked:
            word = item.strip().lower()
            if word and word not in seen:
                seen.add(word)
                out.append(word)
        return out

    def _update_level_text(self, level: int) -> None:
        labels = {
            1: "Базовый (только критические)",
            2: "Низкий (критические + высокие)",
            3: "Средний (критические + высокие + средние)",
            4: "Высокий (добавляет низкие)",
            5: "Максимальный (все уровни словаря)",
        }
        self.protection_level_value_label.setText(f"Текущий: {labels.get(level, 'Неизвестно')}")

    def _collect_settings_from_ui(self) -> dict:
        data = {
            "tesseract_cmd": self.tesseract_input.text().strip(),
            "protection_level": self.protection_level_input.value(),
            "max_windows_to_check": self.max_windows_input.value(),
            "shield_padding": self.shield_padding_input.value(),
            "recheck_interval": self.recheck_interval_input.value(),
            "memory_duration": self.memory_duration_input.value(),
            "scanner_sleep": self.scanner_sleep_input.value(),
            "whitelist_words": self._parse_word_list(self.whitelist_input.toPlainText()),
            "blacklist_words": self._parse_word_list(self.blacklist_input.toPlainText()),
        }
        return data

    def save_settings(self) -> None:
        new_cfg = self._collect_settings_from_ui()
        save_config(new_cfg, self.config_path)
        self.config = load_config(self.config_path)
        self._load_settings_to_ui()

        self.settings_status.setText(f"Сохранено: {self.config_path}")
        self._append_log(f"[GUI] Настройки сохранены: {self.config_path}")
        self._append_log(f"[GUI] Уровень защиты: {self.config['protection_level']}")

        if self.shield_process.state() != QProcess.ProcessState.NotRunning:
            self._append_log("[GUI] Применение настроек: перезапуск защиты...")
            self.stop_protection()
            self.start_protection()

    def reset_defaults(self) -> None:
        self.config = get_default_config()
        self._load_settings_to_ui()
        self.settings_status.setText("Загружены значения по умолчанию. Нажмите «Сохранить настройки».")

    def start_protection(self) -> None:
        if self.shield_process.state() != QProcess.ProcessState.NotRunning:
            return

        script_path = Path(__file__).resolve().with_name("main_shield.py")
        if not script_path.exists():
            QMessageBox.critical(self, "Ошибка", f"Файл не найден: {script_path}")
            return

        env = QProcessEnvironment.systemEnvironment()
        env.insert("SAFESCREEN_CONFIG", str(self.config_path))
        env.insert("PYTHONIOENCODING", "utf-8")
        env.insert("PYTHONUTF8", "1")
        self.shield_process.setProcessEnvironment(env)
        self.shield_process.setProgram(sys.executable)
        self.shield_process.setArguments(["-u", str(script_path), "--config", str(self.config_path)])
        self.shield_process.setWorkingDirectory(str(script_path.parent))
        self.stop_requested = False
        self.stop_force_kill = False
        self.shield_process.start()

        if not self.shield_process.waitForStarted(2500):
            QMessageBox.critical(self, "Ошибка", "Не удалось запустить процесс защиты.")
            return

        self._set_running_ui(True)
        self._append_log("[GUI] Процесс защиты запущен.")

    def stop_protection(self) -> None:
        if self.shield_process.state() == QProcess.ProcessState.NotRunning:
            return

        self.stop_requested = True
        self.stop_force_kill = False
        self._append_log("[GUI] Остановка процесса защиты...")
        self.shield_process.write(b"STOP\n")
        self.shield_process.waitForBytesWritten(500)
        self.shield_process.closeWriteChannel()
        if not self.shield_process.waitForFinished(4000):
            self.stop_force_kill = True
            self._append_log("[GUI] Штатная остановка не ответила, выполняется принудительное завершение...")
            self.shield_process.kill()
            self.shield_process.waitForFinished(1000)

    def _set_running_ui(self, running: bool) -> None:
        self.start_button.setEnabled(not running)
        self.stop_button.setEnabled(running)
        if running:
            self.status_label.setText("Защита: ВКЛ")
            self.status_label.setStyleSheet(
                "color: #14522b; background: #eafaf0; border: 1px solid #b9e8c6; border-radius: 8px; padding: 6px 10px;"
            )
        else:
            self.status_label.setText("Защита: ВЫКЛ")
            self.status_label.setStyleSheet(
                "color: #8f1d1d; background: #fdeaea; border: 1px solid #f2bcbc; border-radius: 8px; padding: 6px 10px;"
            )

    def _read_stdout(self) -> None:
        chunk = self._decode_process_bytes(bytes(self.shield_process.readAllStandardOutput()))
        self.stdout_buffer += chunk
        self.stdout_buffer = self._consume_lines(self.stdout_buffer, is_error=False)

    def _read_stderr(self) -> None:
        chunk = self._decode_process_bytes(bytes(self.shield_process.readAllStandardError()))
        self.stderr_buffer += chunk
        self.stderr_buffer = self._consume_lines(self.stderr_buffer, is_error=True)

    @staticmethod
    def _decode_process_bytes(data: bytes) -> str:
        if not data:
            return ""
        for encoding in ("utf-8", "cp1251", "cp866"):
            try:
                return data.decode(encoding)
            except UnicodeDecodeError:
                continue
        return data.decode("utf-8", errors="replace")

    def _consume_lines(self, buffer: str, is_error: bool) -> str:
        lines = buffer.splitlines(keepends=True)
        remainder = ""
        for raw in lines:
            if raw.endswith("\n"):
                line = raw.rstrip("\r\n")
                if is_error:
                    self._append_log(f"[ERR] {line}")
                else:
                    self._handle_stdout_line(line)
            else:
                remainder = raw
        return remainder

    def _handle_stdout_line(self, line: str) -> None:
        if line.startswith("[EVENT]|"):
            event = self._parse_event_line(line)
            if event:
                self._append_event_card(event)
        self._append_log(line)

    @staticmethod
    def _parse_event_line(line: str) -> dict | None:
        payload = line[len("[EVENT]|") :]
        data = {}
        for part in payload.split("|"):
            if "=" not in part:
                continue
            key, value = part.split("=", 1)
            data[key.strip()] = value.strip()
        if "kind" not in data:
            return None
        return data

    def _append_event_card(self, event: dict) -> None:
        event_kind = event.get("kind")
        if event_kind not in {"threat", "clear"}:
            return

        now = datetime.now().strftime("%H:%M:%S")
        level = event.get("level", "?")
        title = event.get("title", "<unknown>")
        words = event.get("words", "")
        if event_kind == "threat":
            text = f"[{now}] L{level}  {title}\nОбнаружено: {words}"
        else:
            reason_map = {
                "rescanned_clean": "после перескана угроза не подтверждена",
                "window_gone": "окно исчезло",
            }
            reason = reason_map.get(event.get("reason", ""), "защита снята")
            text = f"[{now}] Снята защита  {title}\nПричина: {reason}"

        item = QListWidgetItem(text)
        if event_kind == "clear":
            item.setBackground(QColor("#eaf7ee"))
        else:
            level_num = int(level) if str(level).isdigit() else 0
            if level_num >= 5:
                item.setBackground(QColor("#f8d7da"))
            elif level_num >= 4:
                item.setBackground(QColor("#fff3cd"))
            elif level_num >= 3:
                item.setBackground(QColor("#fff9db"))

        self.events_list.insertItem(0, item)
        while self.events_list.count() > 300:
            self.events_list.takeItem(self.events_list.count() - 1)

    def _on_process_error(self, error: QProcess.ProcessError) -> None:
        if self.stop_requested and error == QProcess.ProcessError.Crashed:
            return
        self._append_log(f"[GUI] Ошибка процесса: {error}")
        self._set_running_ui(False)

    def _on_process_finished(self, exit_code: int, _exit_status) -> None:
        if self.stop_requested:
            if self.stop_force_kill:
                self._append_log(f"[GUI] Процесс защиты принудительно завершен (код={exit_code}).")
            else:
                self._append_log("[GUI] Процесс защиты остановлен.")
        else:
            self._append_log(f"[GUI] Процесс защиты завершен (код={exit_code}).")
        self.stop_requested = False
        self.stop_force_kill = False
        self._set_running_ui(False)

    def _append_log(self, line: str) -> None:
        self.log_output.appendPlainText(line)
        bar = self.log_output.verticalScrollBar()
        bar.setValue(bar.maximum())

    def changeEvent(self, event) -> None:
        super().changeEvent(event)

    def closeEvent(self, event) -> None:
        if self.shield_process.state() != QProcess.ProcessState.NotRunning:
            self.stop_protection()
        if self.tray_icon:
            self.tray_icon.hide()
        event.accept()
        QApplication.instance().quit()

def main() -> int:
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setQuitOnLastWindowClosed(False)
    window = SafeScreenWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
