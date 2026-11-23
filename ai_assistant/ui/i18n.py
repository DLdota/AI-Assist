# -*- coding: utf-8 -*-
"""Small UI translation catalog. Model response language remains independent."""
_TRANSLATIONS = {
    "English": {
        "AI Assistant — Настройки": "AI Assistant — Settings", "Активный режим работы:": "Active mode:",
        "Локальная модель (Ollama)": "Local model (Ollama)", "Облачный API (OpenAI-Compatible)": "Cloud API (OpenAI-compatible)",
        "Ollama (Локально)": "Ollama (Local)", "Облачные API": "Cloud APIs", "Общие": "General",
        "Промпты и API": "Prompts & API", "Язык интерфейса:": "Interface language:",
        "Язык ответов модели:": "Model response language:", "Русский": "Russian", "Английский": "English", "Китайский": "Chinese",
        "Таймаут (сек):": "Timeout (sec):", "Лимит кода функции (симв.):": "Function code limit (chars):",
        "Глубина Deep Scan по умолчанию:": "Default Deep Scan depth:", "Рассуждения в чате:": "Chat reasoning:", "Лимит ответа чата:": "Chat answer limit:", "Ограничивает один ответ чата вместе с рассуждениями. Если лимит исчерпан на рассуждениях, запрос повторяется без них.": "Caps one chat answer including reasoning. If reasoning exhausts the limit, the request is repeated without reasoning.",
        "Разрешить рассуждения модели в чате (может увеличить время и расход токенов)": "Allow model reasoning in chat (may increase time and token usage)",
        "Сетевое соединение:": "Network connection:", "Прямое соединение (по умолчанию)": "Direct connection (default)",
        "Системный прокси Windows": "Windows system proxy", "Собственный прокси": "Custom proxy", "URL собственного прокси:": "Custom proxy URL:",
        "Лимит функций Deep Scan:": "Deep Scan function limit:", "Тема псевдокода:": "Pseudocode theme:",
        "Подробные логи в окне Output IDA": "Verbose logs in IDA Output", "Debug режим:": "Debug mode:",
        "Лимиты вывода Deep Scan": "Deep Scan output limits", "Поверхностный:": "Surface:", "Базовый:": "Basic:",
        "Глубокий:": "Deep:", "Очень глубокий:": "Very deep:", "токенов": "tokens",
        "Дополнительные инструкции для модели": "Additional model instructions", "Custom Prompt:": "Custom prompt:",
        "Extra API JSON:": "Extra API JSON:", "Сохранить": "Save", "Отмена": "Cancel",
        "Загрузить список": "Load list", "Список моделей API": "API model list", "Загрузка…": "Loading…",
        "Ошибка JSON": "JSON error", "Некорректный Extra API JSON:\n": "Invalid Extra API JSON:\n",
        "Ожидается JSON-объект { ... }": "Expected a JSON object { ... }",
        "Модель Ollama:": "Ollama model:", "Ollama URL:": "Ollama URL:", "Context Length (num_ctx):": "Context length (num_ctx):",
        "Max Predict (num_predict):": "Max predict (num_predict):", "Режим Think (Qwen3/DeepSeek):": "Think mode (Qwen3/DeepSeek):",
        "Название провайдера:": "Provider name:", "API Base URL:": "API base URL:", "API Key:": "API key:",
        "Модель (Model ID):": "Model (ID):", "Context Length:": "Context length:", "Max Output Tokens:": "Max output tokens:",
        "Temperature:": "Temperature:", "Цена Input (за 1M токенов):": "Input price (per 1M tokens):", "Цена Output (за 1M токенов):": "Output price (per 1M tokens):",
        "Поверхностный анализ": "Surface analysis", "Базовый анализ": "Basic analysis", "Глубокий анализ": "Deep analysis", "Очень глубокий анализ": "Very deep analysis",
        "Готово": "Ready", "Отмена": "Cancel", "Псевдокод": "Pseudocode", "Глубокое сканирование": "Deep Scan", "Чат с ИИ": "AI Chat",
        "Запустить анализ": "Run analysis", "Применить выбранные изменения": "Apply selected changes", "Применить": "Apply",
        "Анализировать псевдокод": "Analyze pseudocode", "Поиск в псевдокоде...": "Search pseudocode...", "Копировать": "Copy",
        "Предложения ИИ:": "AI suggestions:", "Введите вопрос по функции... (Ctrl+Enter для отправки)": "Ask about the function... (Ctrl+Enter to send)",
        "Отправить": "Send", "Глубина:": "Depth:", "Обновить список моделей": "Refresh model list", "Настройки AI Assistant": "AI Assistant settings",
    "Тип": "Type", "Цель": "Target", "Предложение": "Suggestion", "Сейчас": "Current", "Увер.": "Conf.", "Новое": "New", "ВЫ": "YOU", "ИИ": "AI",
    "Обновление списка моделей…": "Refreshing model list…", "Облачная API-модель": "Cloud API model", "Локальная модель": "Local model",
    },
    "Chinese": {
        "AI Assistant — Настройки": "AI Assistant — 设置", "Активный режим работы:": "当前工作模式：",
        "Локальная модель (Ollama)": "本地模型（Ollama）", "Облачный API (OpenAI-Compatible)": "云端 API（兼容 OpenAI）",
        "Ollama (Локально)": "Ollama（本地）", "Облачные API": "云端 API", "Общие": "常规", "Промпты и API": "提示词与 API",
        "Язык интерфейса:": "界面语言：", "Язык ответов модели:": "模型回复语言：", "Русский": "俄语", "Английский": "英语", "Китайский": "中文",
        "Таймаут (сек):": "超时（秒）：", "Лимит кода функции (симв.):": "函数代码长度限制（字符）：", "Глубина Deep Scan по умолчанию:": "默认 Deep Scan 深度：",
        "Рассуждения в чате:": "聊天推理：", "Лимит ответа чата:": "聊天回答上限：", "Ограничивает один ответ чата вместе с рассуждениями. Если лимит исчерпан на рассуждениях, запрос повторяется без них.": "限制单次聊天回答（含推理）。若推理耗尽上限，将在关闭推理后重试。", "Разрешить рассуждения модели в чате (может увеличить время и расход токенов)": "允许模型在聊天中推理（可能增加耗时和 token 消耗）",
        "Сетевое соединение:": "网络连接：", "Прямое соединение (по умолчанию)": "直接连接（默认）", "Системный прокси Windows": "Windows 系统代理",
        "Собственный прокси": "自定义代理", "URL собственного прокси:": "自定义代理 URL：", "Лимит функций Deep Scan:": "Deep Scan 函数数量限制：",
        "Тема псевдокода:": "伪代码主题：", "Подробные логи в окне Output IDA": "在 IDA Output 中显示详细日志", "Debug режим:": "调试模式：",
        "Лимиты вывода Deep Scan": "Deep Scan 输出限制", "Поверхностный:": "浅层：", "Базовый:": "基础：", "Глубокий:": "深度：", "Очень глубокий:": "超深度：", "токенов": "tokens",
        "Дополнительные инструкции для модели": "模型附加指令", "Custom Prompt:": "自定义提示词：", "Extra API JSON:": "额外 API JSON：",
        "Сохранить": "保存", "Отмена": "取消", "Загрузить список": "加载列表", "Список моделей API": "API 模型列表", "Загрузка…": "加载中…",
        "Ошибка JSON": "JSON 错误", "Некорректный Extra API JSON:\n": "Extra API JSON 无效：\n", "Ожидается JSON-объект { ... }": "需要 JSON 对象 { ... }",
        "Модель Ollama:": "Ollama 模型：", "Ollama URL:": "Ollama URL：", "Context Length (num_ctx):": "上下文长度（num_ctx）：", "Max Predict (num_predict):": "最大预测长度（num_predict）：",
        "Режим Think (Qwen3/DeepSeek):": "Think 模式（Qwen3/DeepSeek）：", "Название провайдера:": "服务提供商名称：", "API Base URL:": "API Base URL：", "API Key:": "API 密钥：",
        "Модель (Model ID):": "模型（ID）：", "Context Length:": "上下文长度：", "Max Output Tokens:": "最大输出 tokens：", "Temperature:": "Temperature：",
        "Цена Input (за 1M токенов):": "输入价格（每百万 tokens）：", "Цена Output (за 1M токенов):": "输出价格（每百万 tokens）：",
        "Поверхностный анализ": "浅层分析", "Базовый анализ": "基础分析", "Глубокий анализ": "深度分析", "Очень глубокий анализ": "超深度分析",
        "Готово": "就绪", "Псевдокод": "伪代码", "Глубокое сканирование": "深度扫描", "Чат с ИИ": "AI 聊天", "Запустить анализ": "开始分析",
        "Применить выбранные изменения": "应用所选更改", "Применить": "应用", "Анализировать псевдокод": "分析伪代码", "Поиск в псевдокоде...": "搜索伪代码...",
        "Копировать": "复制", "Предложения ИИ:": "AI 建议：", "Введите вопрос по функции... (Ctrl+Enter для отправки)": "输入有关函数的问题…（Ctrl+Enter 发送）",
        "Отправить": "发送", "Глубина:": "深度：", "Обновить список моделей": "刷新模型列表", "Настройки AI Assistant": "AI Assistant 设置",
    }
}

def tr(text, language="Russian"):
    if text is None:
        return text
    value = str(text)
    canonical = value
    # Reverse-map an already translated label so changing English <-> Chinese
    # during the same IDA session does not leave a mixed-language interface.
    for catalog in _TRANSLATIONS.values():
        for source, translated in catalog.items():
            if value == translated:
                canonical = source
                break
        if canonical != value:
            break
    target = _TRANSLATIONS.get(language, {})
    if canonical in target:
        return target[canonical]
    if language == "Russian":
        return canonical
    if value.startswith("Готово ("):
        return "Ready (" + value[len("Готово ("):]
    if value.startswith("Применено: "):
        return "Applied: " + value[len("Применено: "):]
    if value.startswith("Не удалось обновить список моделей: "):
        return "Could not refresh model list: " + value.split(": ", 1)[1]
    if value.startswith("Ошибка в разделе ["):
        return "Error in section [" + value.split("[", 1)[1]
    return target.get(canonical, canonical)

# Additional labels shared by the main panel and provider pages.
_TRANSLATIONS["English"].update({
    "Язык и поведение": "Language & behavior", "Сеть и отображение": "Network & appearance",
    "Облачная API-модель": "Cloud API model", "Локальная модель": "Local model",
    "Не удалось получить список моделей. Проверьте URL Ollama.": "Could not load models. Check the Ollama URL.",
    "Например: OpenAI, OpenRouter, Polza, DeepSeek": "For example: OpenAI, OpenRouter, Polza, DeepSeek",
    "http://127.0.0.1:8080 или https://proxy.example:8443": "http://127.0.0.1:8080 or https://proxy.example:8443",
    "Дополнительные системные инструкции...": "Additional system instructions...",
    "Активный режим работы:": "Active mode:", "Язык и поведение": "Language & behavior",
    "Лимит применяется отдельно к каждому уровню. Повторная попытка не превысит заданное значение.": "The limit is applied independently to each level. Retries will not exceed this value.",
    "Модель:": "Model:", "Загрузить список": "Load list", "Список моделей API": "API model list",
    "Загрузка…": "Loading…", "Ошибка JSON": "JSON error", "Cloud API": "Cloud API",
    "Не удалось получить список моделей. Проверьте URL Ollama.": "Could not load models. Check the Ollama URL.",
    "Загружено моделей: ": "Models loaded: ", "Облачная API-модель": "Cloud API model", "Локальная модель": "Local model",
    "Поверхностный — только выбранная функция\nБазовый — функция, её Xref и непосредственные вызовы\nГлубокий — рекурсивный граф вызовов, типы, структуры и дизассемблер\nОчень глубокий — дополнительно поиск callback и function-pointer связей": "Surface — selected function only\nBasic — function, its xrefs and direct calls\nDeep — recursive call graph, types, structures and disassembly\nVery deep — additionally searches callback and function-pointer relationships",
    "Быстрый анализ функции, имени и локальных переменных.": "Quick analysis of the function, name and local variables.",
    "Анализ функции, Xref, подфункций, структур и callback-связей.": "Analysis of the function, xrefs, callees, structures and callback relationships.",
    "ЛКМ — открыть результаты анализа и псевдокод. ПКМ — показать функцию в окне IDA.": "Left-click — open analysis results and pseudocode. Right-click — show the function in IDA.",
    "● НОВЫЙ — анализ выполнен в текущем сеансе IDA\n○ КЭШ — результат сохранён в базе IDB ранее": "● NEW — analyzed in the current IDA session\n○ CACHE — result was saved in the IDB earlier",
})
_TRANSLATIONS["Chinese"].update({
    "Язык и поведение": "语言与行为", "Сеть и отображение": "网络与外观",
    "Дополнительные инструкции для модели": "模型附加指令", "Дополнительные системные инструкции...": "模型附加系统指令…",
    "Активный режим работы:": "当前工作模式：", "Например: OpenAI, OpenRouter, Polza, DeepSeek": "例如：OpenAI、OpenRouter、Polza、DeepSeek",
    "http://127.0.0.1:8080 или https://proxy.example:8443": "http://127.0.0.1:8080 或 https://proxy.example:8443",
    "Лимит применяется отдельно к каждому уровню. Повторная попытка не превысит заданное значение.": "每个深度级别单独应用此限制。重试不会超过设定值。",
    "Модель:": "模型：", "Облачная API-модель": "云端 API 模型", "Локальная модель": "本地模型",
    "Быстрый анализ функции, имени и локальных переменных.": "快速分析函数、名称和局部变量。",
    "Анализ функции, Xref, подфункций, структур и callback-связей.": "分析函数、交叉引用、子函数、结构和回调关系。",
    "ЛКМ — открыть результаты анализа и псевдокод. ПКМ — показать функцию в окне IDA.": "左键：打开分析结果和伪代码。右键：在 IDA 窗口中定位函数。",
    "● НОВЫЙ — анализ выполнен в текущем сеансе IDA\n○ КЭШ — результат сохранён в базе IDB ранее": "● NEW — 在当前 IDA 会话中分析\n○ CACHE — 结果此前已保存到 IDB",
    "Поверхностный анализ": "浅层分析", "Базовый анализ": "基础分析", "Глубокий анализ": "深度分析", "Очень глубокий анализ": "超深度分析",
    "Глубина:": "深度：", "Готово": "就绪", "Отмена": "取消", "Псевдокод": "伪代码", "Глубокое сканирование": "深度扫描", "Чат с ИИ": "AI 聊天",
    "Запустить анализ": "开始分析", "Применить выбранные изменения": "应用所选更改", "Анализировать псевдокод": "分析伪代码", "Поиск в псевдокоде...": "搜索伪代码...", "Копировать": "复制", "Предложения ИИ:": "AI 建议：", "Отправить": "发送",
})


_TRANSLATIONS["English"].update({
    "Повторно выполнить анализ открытой функции без использования кэша": "Reanalyze the displayed function without using cache",
    "Повторный анализ": "Reanalyze", "Цветовая схема:": "Color scheme:",
    "Цветовая схема интерфейса и псевдокода наследуется от текущей темы IDA.": "The interface and pseudocode colors follow the current IDA theme.",
    "Об авторе": "About", "История функций": "Function history",
})
_TRANSLATIONS["Chinese"].update({
    "Повторно выполнить анализ открытой функции без использования кэша": "不使用缓存重新分析当前显示的函数",
    "Повторный анализ": "重新分析", "Цветовая схема:": "配色方案：",
    "Цветовая схема интерфейса и псевдокода наследуется от текущей темы IDA.": "界面和伪代码颜色跟随当前 IDA 主题。",
    "Об авторе": "关于作者", "История функций": "函数历史",
})

def translate_widget_tree(root, language="Russian"):
    """Translate static Qt widget strings without touching user-entered text."""
    from PySide6 import QtWidgets
    for widget in root.findChildren(QtWidgets.QWidget) + [root]:
        try:
            if isinstance(widget, QtWidgets.QGroupBox):
                widget.setTitle(tr(widget.title(), language))
            if hasattr(widget, "text") and callable(widget.text):
                old = widget.text()
                new = tr(old, language)
                if old.startswith("<b>") and old.endswith("</b>"):
                    plain = old[3:-4]
                    if plain.endswith(":"):
                        plain = plain[:-1]
                    new = "<b>" + tr(plain, language) + "</b>"
                if new != old and hasattr(widget, "setText"):
                    widget.setText(new)
            if isinstance(widget, QtWidgets.QAbstractButton):
                widget.setToolTip(tr(widget.toolTip(), language))
                widget.setAccessibleName(tr(widget.accessibleName(), language))
            if isinstance(widget, QtWidgets.QLineEdit):
                widget.setPlaceholderText(tr(widget.placeholderText(), language))
            elif isinstance(widget, QtWidgets.QPlainTextEdit) or isinstance(widget, QtWidgets.QTextEdit):
                widget.setPlaceholderText(tr(widget.placeholderText(), language))
            elif isinstance(widget, QtWidgets.QComboBox):
                for i in range(widget.count()):
                    widget.setItemText(i, tr(widget.itemText(i), language))
            elif isinstance(widget, QtWidgets.QTabWidget):
                for i in range(widget.count()):
                    widget.setTabText(i, tr(widget.tabText(i), language))
            elif isinstance(widget, QtWidgets.QTreeWidget):
                for i in range(widget.columnCount()):
                    item = widget.headerItem()
                    if item:
                        item.setText(i, tr(item.text(i), language))
            if widget.toolTip():
                widget.setToolTip(tr(widget.toolTip(), language))
        except (RuntimeError, AttributeError):
            pass

_TRANSLATIONS["English"].update({
    "● НОВЫЙ": "● NEW", "○ КЭШ": "○ CACHE",
    "Проанализирована в текущем сеансе IDA": "Analyzed in the current IDA session",
    "Загружена из постоянного кеша IDB (предыдущий сеанс)": "Loaded from persistent IDB cache (previous session)",
    "Показать функцию в IDA": "Show function in IDA", "Ничего не выбрано для применения.": "Nothing selected to apply.",
    "Запрос отменён": "Request cancelled", "Ошибка": "Error", "Список моделей обновлён": "Model list refreshed",
    "Показаны сохранённые модели": "Showing saved models", "Список моделей обновлён": "Model list refreshed",
    "Загружено моделей из API: ": "Models loaded from API: ", "Загружено моделей: ": "Models loaded: ",
    "Применить": "Apply", "Обновление списка моделей…": "Refreshing model list…",
})
_TRANSLATIONS["Chinese"].update({
    "● НОВЫЙ": "● NEW", "○ КЭШ": "○ CACHE",
    "Проанализирована в текущем сеансе IDA": "在当前 IDA 会话中分析",
    "Загружена из постоянного кеша IDB (предыдущий сеанс)": "从持久 IDB 缓存加载（之前的会话）",
    "Показать функцию в IDA": "在 IDA 中显示函数", "Ничего не выбрано для применения.": "未选择要应用的项目。",
    "Запрос отменён": "请求已取消", "Ошибка": "错误", "Список моделей обновлён": "模型列表已刷新",
    "Показаны сохранённые модели": "显示已保存的模型", "Загружено моделей из API: ": "从 API 加载的模型：", "Загружено моделей: ": "已加载模型：",
    "Применить": "应用",
})

_TRANSLATIONS["English"].update({
    "Поверхностный": "Surface", "Базовый": "Basic", "Глубокий": "Deep", "Очень глубокий": "Very deep",
    "Глубокий анализ": "Deep analysis", "Обнаружено узлов в графе": "Graph nodes found", "Режим обхода": "Traversal mode",
    "Глубина": "Depth", "Статус": "Status", "Предложение": "Suggestion", "Уверенность": "Confidence",
    "Назначение": "Purpose", "Обоснование": "Reasoning", "Связь": "Relationship", "кандидат на callback/function pointer": "callback/function pointer candidate",
    "Ссылки на функции": "Function references", "Подтверждённые факты": "Confirmed facts", "Гипотезы": "Hypotheses",
    "Поля/смещения": "Fields/offsets", "Условия и ветвления": "Conditions and branches", "Циклы и контейнеры": "Loops and containers", "Вспомогательные вызовы": "Helper calls",
    "Итоги": "Summary", "проанализировано": "analyzed", "предложено имён": "names proposed", "уже именованы": "already named", "недостаточно данных": "insufficient data", "ошибок": "errors",
    "Имя функции": "Function name", "Переменная": "Variable", "Комментарий": "Comment", "Комментарий функции": "Function comment", "Тип переменной": "Variable type", "Прототип": "Prototype",
    "Сканирование": "Scan", "Анализ псевдокода": "Pseudocode analysis", "Реконструкция структуры": "Structure reconstruction",
})
_TRANSLATIONS["Chinese"].update({
    "Поверхностный": "浅层", "Базовый": "基础", "Глубокий": "深度", "Очень глубокий": "超深度",
    "Глубокий анализ": "深度分析", "Обнаружено узлов в графе": "图中发现节点", "Режим обхода": "遍历模式",
    "Глубина": "深度", "Статус": "状态", "Предложение": "建议", "Уверенность": "置信度", "Назначение": "用途", "Обоснование": "依据",
    "Связь": "关系", "кандидат на callback/function pointer": "callback/function pointer 候选", "Ссылки на функции": "函数引用",
    "Подтверждённые факты": "已确认事实", "Гипотезы": "假设", "Поля/смещения": "字段/偏移", "Условия и ветвления": "条件与分支",
    "Циклы и контейнеры": "循环与容器", "Вспомогательные вызовы": "辅助调用", "Итоги": "汇总", "проанализировано": "已分析",
    "предложено имён": "建议名称", "уже именованы": "已有名称", "недостаточно данных": "数据不足", "ошибок": "错误",
    "Имя функции": "函数名称", "Переменная": "变量", "Комментарий": "注释", "Комментарий функции": "函数注释", "Тип переменной": "变量类型", "Прототип": "原型",
    "Сканирование": "扫描", "Анализ псевдокода": "伪代码分析", "Реконструкция структуры": "结构重建",
})
_TRANSLATIONS["English"].update({
    "уже подходит": "Already suitable", "предложено": "Proposed", "ошибка анализа": "Analysis error",
    "высокая": "High", "средняя": "Medium", "низкая": "Low",
})
_TRANSLATIONS["Chinese"].update({
    "уже подходит": "名称已合适", "предложено": "已建议", "ошибка анализа": "分析错误",
    "высокая": "高", "средняя": "中", "низкая": "低",
})

# Labels of the redesigned panel (mock-up based UI) and interface themes.
_TRANSLATIONS["English"].update({
    "Анализ Xref и связей.": "Xref and relationship analysis.", "Запустить": "Run",
    "Применить выбранные": "Apply selected", "Выбрать все / Снять": "Select all / none",
    "Предложений": "Proposals", "Режим": "Mode", "глубина": "depth", "Узлов": "Nodes", "Имён": "Names", "Ошибок": "Errors",
    "Узел": "Node", "Токены:": "Tokens:", "Цена:": "Cost:", "Время:": "Time:", "Поток:": "Stream:", "Оценка:": "Estimate:",
    "Тест": "Test", "Лог": "Log", "Очистить": "Clear", "Повторить": "Retry", "Сброс": "Reset", "Сбросить ошибку": "Dismiss error",
    "Анализ...": "Analyzing...", "НОВЫЙ": "NEW", "КЭШ": "CACHE", "Контекст": "Context", "ВЫ": "YOU", "ИИ": "AI",
    "Имя": "Name", "Тип перем.": "Var type", "Коммент.": "Comment", "(без изменений)": "(unchanged)",
    "Тип": "Type", "Цель": "Target", "Сейчас": "Current", "Увер.": "Conf.", "Новое": "New",
    "Результаты анализа появятся здесь": "Analysis results will appear here",
    "Прервать текущий запрос к LLM": "Abort the current LLM request",
    "Открыть журнал плагина в окне Output IDA": "Open the plugin log in IDA Output",
    "Проверить подключение и обновить список моделей": "Check connection and refresh the model list",
    "Сбросить отображаемую статистику запросов": "Reset displayed request statistics",
    "Запустить анализ": "Run analysis",
    "Тема интерфейса:": "Interface theme:", "Светлая": "Light", "Тёмная": "Dark",
    "Тема панели плагина не зависит от темы IDA": "The plugin panel theme is independent from the IDA theme",
})
_TRANSLATIONS["Chinese"].update({
    "Анализ Xref и связей.": "Xref 与关联分析。", "Запустить": "运行",
    "Применить выбранные": "应用所选", "Выбрать все / Снять": "全选 / 取消",
    "Предложений": "建议数", "Режим": "模式", "глубина": "深度", "Узлов": "节点", "Имён": "名称", "Ошибок": "错误",
    "Узел": "节点", "Токены:": "Tokens：", "Цена:": "费用：", "Время:": "时间：", "Поток:": "流：", "Оценка:": "估算：",
    "Тест": "测试", "Лог": "日志", "Очистить": "清除", "Повторить": "重试", "Сброс": "重置", "Сбросить ошибку": "清除错误",
    "Анализ...": "分析中...", "НОВЫЙ": "新", "КЭШ": "缓存", "Контекст": "上下文", "ВЫ": "你", "ИИ": "AI",
    "Имя": "名称", "Тип перем.": "变量类型", "Коммент.": "注释", "(без изменений)": "（无变化）",
    "Тип": "类型", "Цель": "目标", "Сейчас": "当前", "Увер.": "置信", "Новое": "新值",
    "Результаты анализа появятся здесь": "分析结果将显示在这里",
    "Прервать текущий запрос к LLM": "中止当前 LLM 请求",
    "Открыть журнал плагина в окне Output IDA": "在 IDA Output 中打开插件日志",
    "Проверить подключение и обновить список моделей": "检查连接并刷新模型列表",
    "Сбросить отображаемую статистику запросов": "重置显示的请求统计",
    "Запустить анализ": "开始分析",
    "Тема интерфейса:": "界面主题：", "Светлая": "浅色", "Тёмная": "深色",
    "Тема панели плагина не зависит от темы IDA": "插件面板主题与 IDA 主题无关",
})

_TRANSLATIONS["English"].update({
    "Цена Input из кэша (за 1M):": "Cached input price (per 1M):",
    "Цена входных токенов из кэша провайдера; 0 — как обычный Input": "Price of provider cache hits; 0 = same as regular input",
})
_TRANSLATIONS["Chinese"].update({
    "Цена Input из кэша (за 1M):": "缓存输入价格（每 1M）：",
    "Цена входных токенов из кэша провайдера; 0 — как обычный Input": "提供商缓存命中的输入价格；0 = 与普通输入相同",
})
