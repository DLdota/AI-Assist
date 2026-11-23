# -*- coding: utf-8 -*-
"""
Settings dialog with separate Ollama and Cloud provider configurations,
dynamic model fetching, and per-1M token pricing.
"""
import copy
import json
import threading
from PySide6 import QtCore, QtGui, QtWidgets
from ..api import fetch_available_models
from ..config import DEFAULT_CLOUD_CFG, DEFAULT_OLLAMA_CFG, clean_host
from .i18n import tr, translate_widget_tree
from ..config import normalize_theme_name
from .theme import UI_THEME_LABELS, build_stylesheet, make_qpalette, ui_theme

class SettingsDialog(QtWidgets.QDialog):
    models_loaded = QtCore.Signal(str, object, bool, str)

    def __init__(self, cfg, parent=None):
        super().__init__(parent)
        self.cfg_copy = copy.deepcopy(cfg)
        self.ui_language = str(self.cfg_copy.get("interface_language", "Russian"))
        self.setWindowTitle(tr("AI Assistant — Настройки", self.ui_language))
        self.setMinimumSize(650, 560)
        self.resize(760, 680)
        self.models_loaded.connect(self._on_models_loaded)
        self._model_fetch_buttons = {}

        self._apply_ui_theme()


        main_lay = QtWidgets.QVBoxLayout(self)
        main_lay.setContentsMargins(10, 10, 10, 9)
        main_lay.setSpacing(7)

        mode_box = QtWidgets.QHBoxLayout()
        mode_box.addWidget(QtWidgets.QLabel("<b>" + tr("Активный режим работы:", self.ui_language) + "</b>"))
        self.mode_combo = QtWidgets.QComboBox()
        self.mode_combo.addItem(tr("Локальная модель (Ollama)", self.ui_language), "ollama")
        self.mode_combo.addItem(tr("Облачный API (OpenAI-Compatible)", self.ui_language), "cloud")
        idx = 1 if self.cfg_copy.get("active_mode") == "cloud" else 0
        self.mode_combo.setCurrentIndex(idx)
        mode_box.addWidget(self.mode_combo, 1)
        main_lay.addLayout(mode_box)

        self.tabs = QtWidgets.QTabWidget()
        self.tabs.addTab(self._build_ollama_tab(), tr("Ollama (Локально)", self.ui_language))
        self.tabs.addTab(self._build_cloud_tab(), tr("Облачные API", self.ui_language))
        self.tabs.addTab(self._build_general_tab(), tr("Общие", self.ui_language))
        self.tabs.addTab(self._build_prompts_tab(), tr("Промпты и API", self.ui_language))
        self.tabs.setCurrentIndex(idx)
        main_lay.addWidget(self.tabs, 1)
        self.mode_combo.currentIndexChanged.connect(lambda i: self.tabs.setCurrentIndex(i))

        bb = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.StandardButton.Save | QtWidgets.QDialogButtonBox.StandardButton.Cancel
        )
        bb.button(QtWidgets.QDialogButtonBox.StandardButton.Save).setText(tr("Сохранить", self.ui_language))
        bb.button(QtWidgets.QDialogButtonBox.StandardButton.Save).setProperty("variant", "primary")
        bb.button(QtWidgets.QDialogButtonBox.StandardButton.Cancel).setText(tr("Отмена", self.ui_language))
        bb.accepted.connect(self._on_accept)
        bb.rejected.connect(self.reject)
        main_lay.addWidget(bb)
        translate_widget_tree(self, self.ui_language)

    def _scroll_page(self, content):
        area = QtWidgets.QScrollArea()
        area.setWidgetResizable(True)
        area.setFrameShape(QtWidgets.QFrame.Shape.NoFrame)
        area.setWidget(content)
        return area

    def _apply_ui_theme(self):
        """Use the same plugin-owned Light/Dark theme as the main panel."""
        p = ui_theme(self.cfg_copy.get("ui_theme", "Light"))
        self.setPalette(make_qpalette(p))
        self.setStyleSheet(build_stylesheet(p, root_selector="QDialog") + """
            QTabWidget::pane { border-radius: 8px; border-top-left-radius: 0px; }
            QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox { min-height: 20px; }
            QPushButton { min-height: 20px; }
            QPlainTextEdit { padding: 4px; }
        """)

    def _build_ollama_tab(self):
        w = QtWidgets.QWidget()
        lay = QtWidgets.QFormLayout(w)
        oc = self.cfg_copy["ollama"]

        self.ol_host = QtWidgets.QLineEdit(str(oc.get("host", DEFAULT_OLLAMA_CFG["host"])))
        lay.addRow(tr("Ollama URL:", self.ui_language), self.ol_host)

        model_row = QtWidgets.QHBoxLayout()
        self.ol_model = QtWidgets.QComboBox()
        self.ol_model.setEditable(True)
        saved_ol = list(oc.get("saved_models") or [oc.get("model", "qwen3:8b")])
        if oc.get("model") and oc["model"] not in saved_ol:
            saved_ol.insert(0, oc["model"])
        self.ol_model.addItems(saved_ol)
        self.ol_model.setCurrentText(str(oc.get("model", "qwen3:8b")))
        model_row.addWidget(self.ol_model, 1)

        btn_fetch_ol = QtWidgets.QPushButton(tr("Загрузить список", self.ui_language))
        self._model_fetch_buttons["ollama"] = btn_fetch_ol
        btn_fetch_ol.clicked.connect(self._fetch_ollama_models)
        model_row.addWidget(btn_fetch_ol)
        lay.addRow(tr("Модель Ollama:", self.ui_language), model_row)

        self.ol_ctx = QtWidgets.QSpinBox()
        self.ol_ctx.setRange(1024, 262144)
        self.ol_ctx.setSingleStep(1024)
        self.ol_ctx.setValue(int(oc.get("num_ctx", 8192)))
        lay.addRow(tr("Context Length (num_ctx):", self.ui_language), self.ol_ctx)

        self.ol_predict = QtWidgets.QSpinBox()
        self.ol_predict.setRange(128, 32768)
        self.ol_predict.setSingleStep(128)
        self.ol_predict.setValue(int(oc.get("num_predict", 1500)))
        lay.addRow(tr("Max Predict (num_predict):", self.ui_language), self.ol_predict)

        self.ol_temp = QtWidgets.QDoubleSpinBox()
        self.ol_temp.setRange(0.0, 2.0)
        self.ol_temp.setSingleStep(0.05)
        self.ol_temp.setValue(float(oc.get("temperature", 0.2)))
        lay.addRow(tr("Temperature:", self.ui_language), self.ol_temp)

        self.ol_think = QtWidgets.QComboBox()
        self.ol_think.addItems(["false", "true"])
        self.ol_think.setCurrentText(str(oc.get("think", "false")))
        lay.addRow(tr("Режим Think (Qwen3/DeepSeek):", self.ui_language), self.ol_think)

        return w

    def _build_cloud_tab(self):
        w = QtWidgets.QWidget()
        lay = QtWidgets.QFormLayout(w)
        cc = self.cfg_copy["cloud"]

        self.cl_provider = QtWidgets.QLineEdit(str(cc.get("provider_name", "OpenAI-Compatible")))
        self.cl_provider.setPlaceholderText("Например: OpenAI, OpenRouter, Polza, DeepSeek")
        lay.addRow(tr("Название провайдера:", self.ui_language), self.cl_provider)

        self.cl_host = QtWidgets.QLineEdit(str(cc.get("host", DEFAULT_CLOUD_CFG["host"])))
        self.cl_host.setPlaceholderText("https://api.openai.com/v1 или https://polza.ai/api/v1")
        lay.addRow(tr("API Base URL:", self.ui_language), self.cl_host)

        self.cl_key = QtWidgets.QLineEdit(str(cc.get("api_key", "")))
        self.cl_key.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
        self.cl_key.setPlaceholderText("sk-...")
        lay.addRow(tr("API Key:", self.ui_language), self.cl_key)

        model_row = QtWidgets.QHBoxLayout()
        self.cl_model = QtWidgets.QComboBox()
        self.cl_model.setEditable(True)
        saved_cl = list(cc.get("saved_models") or [cc.get("model", "gpt-4o-mini")])
        if cc.get("model") and cc["model"] not in saved_cl:
            saved_cl.insert(0, cc["model"])
        self.cl_model.addItems(saved_cl)
        self.cl_model.setCurrentText(str(cc.get("model", "gpt-4o-mini")))
        model_row.addWidget(self.cl_model, 1)

        btn_fetch_cl = QtWidgets.QPushButton(tr("Список моделей API", self.ui_language))
        self._model_fetch_buttons["cloud"] = btn_fetch_cl
        btn_fetch_cl.clicked.connect(self._fetch_cloud_models)
        model_row.addWidget(btn_fetch_cl)
        lay.addRow(tr("Модель (Model ID):", self.ui_language), model_row)

        self.cl_ctx = QtWidgets.QSpinBox()
        self.cl_ctx.setRange(2048, 2000000)
        self.cl_ctx.setSingleStep(4096)
        self.cl_ctx.setValue(int(cc.get("context_length", 128000)))
        lay.addRow(tr("Context Length:", self.ui_language), self.cl_ctx)

        self.cl_max_out = QtWidgets.QSpinBox()
        self.cl_max_out.setRange(128, 65536)
        self.cl_max_out.setSingleStep(256)
        self.cl_max_out.setValue(int(cc.get("max_output_tokens", 2000)))
        lay.addRow(tr("Max Output Tokens:", self.ui_language), self.cl_max_out)

        self.cl_temp = QtWidgets.QDoubleSpinBox()
        self.cl_temp.setRange(0.0, 2.0)
        self.cl_temp.setSingleStep(0.05)
        self.cl_temp.setValue(float(cc.get("temperature", 0.2)))
        lay.addRow(tr("Temperature:", self.ui_language), self.cl_temp)

        self.cl_in_cost = QtWidgets.QDoubleSpinBox()
        self.cl_in_cost.setRange(0.0, 1000.0)
        self.cl_in_cost.setDecimals(4)
        self.cl_in_cost.setSingleStep(0.05)
        self.cl_in_cost.setPrefix("$ ")
        self.cl_in_cost.setValue(float(cc.get("input_cost_per_1m", 0.15)))
        lay.addRow(tr("Цена Input (за 1M токенов):", self.ui_language), self.cl_in_cost)

        self.cl_out_cost = QtWidgets.QDoubleSpinBox()
        self.cl_out_cost.setRange(0.0, 1000.0)
        self.cl_out_cost.setDecimals(4)
        self.cl_out_cost.setSingleStep(0.05)
        self.cl_out_cost.setPrefix("$ ")
        self.cl_out_cost.setValue(float(cc.get("output_cost_per_1m", 0.60)))
        lay.addRow(tr("Цена Output (за 1M токенов):", self.ui_language), self.cl_out_cost)

        self.cl_cached_cost = QtWidgets.QDoubleSpinBox()
        self.cl_cached_cost.setRange(0.0, 1000.0)
        self.cl_cached_cost.setDecimals(4)
        self.cl_cached_cost.setSingleStep(0.01)
        self.cl_cached_cost.setPrefix("$ ")
        self.cl_cached_cost.setValue(float(cc.get("cached_input_cost_per_1m", 0.0) or 0.0))
        self.cl_cached_cost.setToolTip(tr("Цена входных токенов из кэша провайдера; 0 — как обычный Input", self.ui_language))
        lay.addRow(tr("Цена Input из кэша (за 1M):", self.ui_language), self.cl_cached_cost)

        return w

    def _build_general_tab(self):
        page = QtWidgets.QWidget()
        outer = QtWidgets.QVBoxLayout(page)
        outer.setContentsMargins(12, 12, 12, 12)
        outer.setSpacing(10)

        language_box = QtWidgets.QGroupBox(tr("Язык и поведение", self.ui_language))
        lay = QtWidgets.QFormLayout(language_box)
        self.interface_lang = QtWidgets.QComboBox()
        for label, value in (("Русский", "Russian"), ("English", "English"), ("中文", "Chinese")):
            self.interface_lang.addItem(label, value)
        idx = self.interface_lang.findData(self.cfg_copy.get("interface_language", "Russian"))
        self.interface_lang.setCurrentIndex(max(0, idx))
        lay.addRow(tr("Язык интерфейса:", self.ui_language), self.interface_lang)

        self.gen_lang = QtWidgets.QComboBox()
        for label, value in (("Русский", "Russian"), ("English", "English"), ("中文", "Chinese")):
            self.gen_lang.addItem(label, value)
        response_lang = str(self.cfg_copy.get("language", "Russian"))
        lang_idx = self.gen_lang.findData(response_lang)
        if lang_idx < 0:
            self.gen_lang.addItem(response_lang, response_lang)
            lang_idx = self.gen_lang.count() - 1
        self.gen_lang.setCurrentIndex(lang_idx)
        lay.addRow(tr("Язык ответов модели:", self.ui_language), self.gen_lang)

        self.gen_timeout = QtWidgets.QSpinBox()
        self.gen_timeout.setRange(10, 3600)
        self.gen_timeout.setValue(int(self.cfg_copy.get("timeout", 300)))
        lay.addRow(tr("Таймаут (сек):", self.ui_language), self.gen_timeout)

        self.gen_max_chars = QtWidgets.QSpinBox()
        self.gen_max_chars.setRange(500, 100000)
        self.gen_max_chars.setSingleStep(500)
        self.gen_max_chars.setValue(int(self.cfg_copy.get("max_code_chars", 6000)))
        lay.addRow(tr("Лимит кода функции (симв.):", self.ui_language), self.gen_max_chars)

        self.gen_depth = QtWidgets.QSpinBox()
        self.gen_depth.setRange(0, 3)
        self.gen_depth.setValue(max(0, min(3, int(self.cfg_copy.get("deep_depth", 1)))))
        lay.addRow(tr("Глубина Deep Scan по умолчанию:", self.ui_language), self.gen_depth)

        self.chat_reasoning_chk = QtWidgets.QCheckBox(tr("Разрешить рассуждения модели в чате (может увеличить время и расход токенов)", self.ui_language))
        self.chat_reasoning_chk.setChecked(bool(self.cfg_copy.get("chat_reasoning", False)))
        lay.addRow(tr("Рассуждения в чате:", self.ui_language), self.chat_reasoning_chk)
        self.chat_max_out = QtWidgets.QSpinBox()
        self.chat_max_out.setRange(512, 65536)
        self.chat_max_out.setSingleStep(512)
        self.chat_max_out.setSuffix(" " + tr("токенов", self.ui_language))
        self.chat_max_out.setValue(int(self.cfg_copy.get("chat_max_output_tokens", 8192)))
        self.chat_max_out.setToolTip(tr("Ограничивает один ответ чата вместе с рассуждениями. Если лимит исчерпан на рассуждениях, запрос повторяется без них.", self.ui_language))
        lay.addRow(tr("Лимит ответа чата:", self.ui_language), self.chat_max_out)
        outer.addWidget(language_box)

        limits_box = QtWidgets.QGroupBox(tr("Лимиты вывода Deep Scan", self.ui_language))
        limits = QtWidgets.QFormLayout(limits_box)
        saved_limits = self.cfg_copy.get("deep_output_limits") or {}
        self.deep_limit_spins = {}
        levels = [(0, "Поверхностный анализ", 1800), (1, "Базовый анализ", 10000), (2, "Глубокий анализ", 16000), (3, "Очень глубокий анализ", 24000)]
        for depth, label, default in levels:
            spin = QtWidgets.QSpinBox()
            spin.setRange(256, 65536)
            spin.setSingleStep(256)
            spin.setSuffix(" " + tr("токенов", self.ui_language))
            spin.setValue(int(saved_limits.get(str(depth), default)))
            self.deep_limit_spins[depth] = spin
            limits.addRow(tr(label, self.ui_language) + ":", spin)
        note = QtWidgets.QLabel(tr("Лимит применяется отдельно к каждому уровню. Повторная попытка не превысит заданное значение.", self.ui_language))
        note.setWordWrap(True)
        note.setStyleSheet(f"color: {ui_theme(self.cfg_copy.get('ui_theme', 'Light'))['muted']}; font-size: 9pt;")
        limits.addRow(note)
        outer.addWidget(limits_box)

        network_box = QtWidgets.QGroupBox(tr("Сеть и отображение", self.ui_language))
        net = QtWidgets.QFormLayout(network_box)
        self.proxy_mode_combo = QtWidgets.QComboBox()
        self.proxy_mode_combo.addItem(tr("Прямое соединение (по умолчанию)", self.ui_language), "direct")
        self.proxy_mode_combo.addItem(tr("Системный прокси Windows", self.ui_language), "system")
        self.proxy_mode_combo.addItem(tr("Собственный прокси", self.ui_language), "custom")
        proxy_mode = str(self.cfg_copy.get("network_proxy_mode", "direct") or "direct")
        proxy_index = self.proxy_mode_combo.findData(proxy_mode)
        self.proxy_mode_combo.setCurrentIndex(max(0, proxy_index))
        net.addRow(tr("Сетевое соединение:", self.ui_language), self.proxy_mode_combo)

        self.proxy_url_edit = QtWidgets.QLineEdit(str(self.cfg_copy.get("network_proxy_url", "") or ""))
        self.proxy_url_edit.setPlaceholderText("http://127.0.0.1:8080")
        self.proxy_url_edit.setEnabled(proxy_mode == "custom")
        self.proxy_mode_combo.currentIndexChanged.connect(lambda _index: self.proxy_url_edit.setEnabled(self.proxy_mode_combo.currentData() == "custom"))
        net.addRow(tr("URL собственного прокси:", self.ui_language), self.proxy_url_edit)

        self.gen_max_funcs = QtWidgets.QSpinBox()
        self.gen_max_funcs.setRange(1, 100)
        self.gen_max_funcs.setValue(int(self.cfg_copy.get("max_deep_funcs", 15)))
        net.addRow(tr("Лимит функций Deep Scan:", self.ui_language), self.gen_max_funcs)

        self.theme_combo = QtWidgets.QComboBox()
        for key in ("Dark", "Light", "Midnight"):
            self.theme_combo.addItem(key, key)
        current_theme = normalize_theme_name(self.cfg_copy.get("theme"), ("Dark", "Light", "Midnight"), "Dark")
        self.theme_combo.setCurrentIndex(max(0, self.theme_combo.findData(current_theme)))
        net.addRow(tr("Тема псевдокода:", self.ui_language), self.theme_combo)

        self.ui_theme_combo = QtWidgets.QComboBox()
        for key, label in UI_THEME_LABELS:
            self.ui_theme_combo.addItem(tr(label, self.ui_language), key)
        ui_idx = self.ui_theme_combo.findData(self.cfg_copy.get("ui_theme", "Light"))
        self.ui_theme_combo.setCurrentIndex(max(0, ui_idx))
        self.ui_theme_combo.setToolTip(tr("Тема панели плагина не зависит от темы IDA", self.ui_language))
        net.addRow(tr("Тема интерфейса:", self.ui_language), self.ui_theme_combo)

        self.debug_chk = QtWidgets.QCheckBox(tr("Подробные логи в окне Output IDA", self.ui_language))
        self.debug_chk.setChecked(bool(self.cfg_copy.get("debug", True)))
        net.addRow(tr("Debug режим:", self.ui_language), self.debug_chk)
        outer.addWidget(network_box)

        about_box = QtWidgets.QGroupBox(tr("Об авторе", self.ui_language))
        about_layout = QtWidgets.QHBoxLayout(about_box)
        about_layout.setContentsMargins(9, 7, 9, 7)
        author_label = QtWidgets.QLabel("Inpaire")
        author_label.setStyleSheet("font-weight: 600;")
        about_layout.addWidget(author_label)
        about_layout.addStretch(1)
        author_link = QtWidgets.QLabel('<a href="https://github.com/DLdota">github.com/DLdota</a>')
        author_link.setOpenExternalLinks(True)
        about_layout.addWidget(author_link)
        outer.addWidget(about_box)
        outer.addStretch(1)
        return self._scroll_page(page)

    def _build_prompts_tab(self):
        page = QtWidgets.QWidget()
        outer = QtWidgets.QVBoxLayout(page)
        outer.setContentsMargins(12, 12, 12, 12)
        prompt_box = QtWidgets.QGroupBox(tr("Дополнительные инструкции для модели", self.ui_language))
        prompt_lay = QtWidgets.QVBoxLayout(prompt_box)
        self.prompt_edit = QtWidgets.QPlainTextEdit(str(self.cfg_copy.get("custom_prompt", "") or ""))
        self.prompt_edit.setMinimumHeight(190)
        self.prompt_edit.setPlaceholderText("Дополнительные системные инструкции...")
        prompt_lay.addWidget(self.prompt_edit)
        outer.addWidget(prompt_box, 2)

        api_box = QtWidgets.QGroupBox("Extra API JSON")
        api_lay = QtWidgets.QVBoxLayout(api_box)
        self.extra_api_edit = QtWidgets.QPlainTextEdit(str(self.cfg_copy.get("extra_api_json", "{}") or "{}"))
        self.extra_api_edit.setMinimumHeight(130)
        self.extra_api_edit.setFont(QtGui.QFont("Consolas", 9))
        api_lay.addWidget(self.extra_api_edit)
        outer.addWidget(api_box, 1)
        return self._scroll_page(page)

    def _start_model_fetch(self, mode, temp_cfg):
        button = self._model_fetch_buttons.get(mode)
        if button:
            button.setEnabled(False)
            button.setText(tr("Загрузка…", self.ui_language))

        def worker():
            try:
                models, ok = fetch_available_models(temp_cfg)
                error = ""
            except Exception as exc:
                models, ok, error = [], False, str(exc)
            try:
                self.models_loaded.emit(mode, list(models or []), bool(ok), error)
            except RuntimeError:
                pass

        threading.Thread(
            target=worker, name=f"IDA-AI-Models-{mode}", daemon=True
        ).start()

    @QtCore.Slot(str, object, bool, str)
    def _on_models_loaded(self, mode, models, ok, error):
        button = self._model_fetch_buttons.get(mode)
        if button:
            button.setEnabled(True)
            button.setText(tr("Загрузить список", self.ui_language) if mode == "ollama" else tr("Список моделей API", self.ui_language))
        if mode == "ollama":
            combo = self.ol_model
            title = "Ollama"
            if ok and models:
                cur = combo.currentText().strip()
                combo.clear()
                combo.addItems(models)
                if cur in models:
                    combo.setCurrentText(cur)
                QtWidgets.QMessageBox.information(self, tr(title, self.ui_language), f"{tr('Загружено моделей: ', self.ui_language)}{len(models)}")
            else:
                QtWidgets.QMessageBox.warning(
                    self, title,
                    "Не удалось получить список моделей. Проверьте URL Ollama." + (f"\n{error}" if error else "")
                )
        else:
            combo = self.cl_model
            if ok and models:
                cur = combo.currentText().strip()
                combo.clear()
                combo.addItems(models)
                if cur in models:
                    combo.setCurrentText(cur)
                QtWidgets.QMessageBox.information(self, tr("Cloud API", self.ui_language), f"{tr('Загружено моделей из API: ', self.ui_language)}{len(models)}")
            else:
                QtWidgets.QMessageBox.information(
                    self,
                    "Cloud API",
                    "Провайдер не вернул список /models или требуется ручной ввод Model ID."
                    + (f"\n{error}" if error else ""),
                )

    def _fetch_ollama_models(self):
        temp_cfg = copy.deepcopy(self.cfg_copy)
        temp_cfg["active_mode"] = "ollama"
        temp_cfg["ollama"]["host"] = clean_host(self.ol_host.text(), DEFAULT_OLLAMA_CFG["host"])
        self._start_model_fetch("ollama", temp_cfg)

    def _fetch_cloud_models(self):
        temp_cfg = copy.deepcopy(self.cfg_copy)
        temp_cfg["active_mode"] = "cloud"
        temp_cfg["cloud"]["host"] = clean_host(self.cl_host.text(), DEFAULT_CLOUD_CFG["host"])
        temp_cfg["cloud"]["api_key"] = self.cl_key.text().strip()
        self._start_model_fetch("cloud", temp_cfg)

    def _on_accept(self):
        raw_extra = self.extra_api_edit.toPlainText().strip()
        if raw_extra:
            try:
                parsed = json.loads(raw_extra)
                if not isinstance(parsed, dict):
                    raise ValueError("Ожидается JSON-объект { ... }")
            except Exception as e:
                error_prefix = tr("Некорректный Extra API JSON:\n", self.ui_language)
                QtWidgets.QMessageBox.warning(self, tr("Ошибка JSON", self.ui_language), error_prefix + str(e))
                return
        self.accept()

    def get_updated_cfg(self):
        out = copy.deepcopy(self.cfg_copy)
        out["active_mode"] = self.mode_combo.currentData()

        # Ollama profile
        ol_m = self.ol_model.currentText().strip() or DEFAULT_OLLAMA_CFG["model"]
        ol_items = [self.ol_model.itemText(i) for i in range(self.ol_model.count())]
        if ol_m not in ol_items:
            ol_items.insert(0, ol_m)
        out["ollama"] = {
            "host": clean_host(self.ol_host.text(), DEFAULT_OLLAMA_CFG["host"]),
            "model": ol_m,
            "num_ctx": int(self.ol_ctx.value()),
            "num_predict": int(self.ol_predict.value()),
            "temperature": float(self.ol_temp.value()),
            "think": self.ol_think.currentText(),
            "saved_models": ol_items[:50],
        }

        # Cloud profile
        cl_host = clean_host(self.cl_host.text(), DEFAULT_CLOUD_CFG["host"])
        cl_m = self.cl_model.currentText().strip() or DEFAULT_CLOUD_CFG["model"]
        cl_items = [self.cl_model.itemText(i) for i in range(self.cl_model.count())]
        if cl_m not in cl_items:
            cl_items.insert(0, cl_m)
        models_by_host = dict(out["cloud"].get("models_by_host") or {})
        models_by_host[cl_host] = cl_m

        out["cloud"] = {
            "provider_name": self.cl_provider.text().strip() or "OpenAI-Compatible",
            "host": cl_host,
            "api_key": self.cl_key.text().strip(),
            "model": cl_m,
            "context_length": int(self.cl_ctx.value()),
            "max_output_tokens": int(self.cl_max_out.value()),
            "temperature": float(self.cl_temp.value()),
            "input_cost_per_1m": float(self.cl_in_cost.value()),
            "output_cost_per_1m": float(self.cl_out_cost.value()),
            "cached_input_cost_per_1m": float(self.cl_cached_cost.value()),
            "saved_models": cl_items[:100],
            "models_by_host": models_by_host,
        }

        # General
        out["language"] = self.gen_lang.currentData() or "Russian"
        out["interface_language"] = self.interface_lang.currentData() or "Russian"
        out["deep_output_limits"] = {str(depth): int(spin.value()) for depth, spin in self.deep_limit_spins.items()}
        out["timeout"] = int(self.gen_timeout.value())
        out["max_code_chars"] = int(self.gen_max_chars.value())
        out["deep_depth"] = int(self.gen_depth.value())
        out["chat_reasoning"] = self.chat_reasoning_chk.isChecked()
        out["chat_max_output_tokens"] = int(self.chat_max_out.value())
        out["network_proxy_mode"] = self.proxy_mode_combo.currentData() or "direct"
        out["network_proxy_url"] = self.proxy_url_edit.text().strip()
        out["max_deep_funcs"] = int(self.gen_max_funcs.value())
        out["debug"] = self.debug_chk.isChecked()
        out["theme"] = self.theme_combo.currentData() or "Dark"
        out["ui_theme"] = self.ui_theme_combo.currentData() or "Light"
        out["custom_prompt"] = self.prompt_edit.toPlainText().strip()
        raw_extra = self.extra_api_edit.toPlainText().strip()
        out["extra_api_json"] = json.dumps(json.loads(raw_extra), ensure_ascii=False, indent=2) if raw_extra else "{}"
        return out
