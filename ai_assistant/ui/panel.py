# -*- coding: utf-8 -*-
"""
Main docked PluginForm Panel: provider/model switcher, function history with an
operation card, and tabs for Deep Scan, Pseudocode and Interactive Chat.

The visual design follows the supplied HTML mock-up and uses plugin-owned
Light / Dark interface themes that are independent from the IDA theme.
"""
import copy
import html
import json
import re
import threading
import ida_funcs
import ida_kernwin
from PySide6 import QtCore, QtGui, QtWidgets

from ..analysis import KIND_LABEL
from ..api import fetch_available_models
from ..config import get_active_profile, log_msg, normalize_theme_name, save_cfg
from .theme import (HexRaysHighlighter, THEMES, build_stylesheet, make_qpalette,
                    mono_font, ui_theme, MONO_FAMILIES)
from .i18n import tr, translate_widget_tree

Qt = QtCore.Qt
CHECKED = Qt.CheckState.Checked
UNCHECKED = Qt.CheckState.Unchecked
ITEM_FLAGS = (
    Qt.ItemFlag.ItemIsUserCheckable
    | Qt.ItemFlag.ItemIsEnabled
    | Qt.ItemFlag.ItemIsSelectable
    | Qt.ItemFlag.ItemIsEditable
)
ROLE_IDX = Qt.ItemDataRole.UserRole
ROLE_NAME = Qt.ItemDataRole.UserRole + 1
ROLE_NEW = Qt.ItemDataRole.UserRole + 2
ROLE_KIND = Qt.ItemDataRole.UserRole + 3
ROLE_CONF = Qt.ItemDataRole.UserRole + 4
ROLE_EA = Qt.ItemDataRole.UserRole + 5

MONO_CSS = "'Consolas','Cascadia Mono','JetBrains Mono','Menlo','DejaVu Sans Mono','Courier New',monospace"

# Short labels for the "Type" pill and the semantic color of every proposal kind.
KIND_SHORT = {
    "rename_func": "Имя", "rename_lvar": "Переменная", "lvar_type": "Тип перем.",
    "proto": "Прототип", "func_comment": "Коммент.", "comment": "Коммент.",
}
KIND_COLOR = {
    "rename_func": "blue", "rename_lvar": "purple", "lvar_type": "teal",
    "proto": "green", "func_comment": "amber", "comment": "amber",
}
CODE_KINDS = ("rename_func", "rename_lvar", "lvar_type", "proto")


def _t(ctl, text):
    return tr(text, ctl.cfg.get("interface_language", "Russian"))


def _conf_color(conf):
    if conf is None:
        return "grey"
    if conf >= 0.8:
        return "green"
    if conf >= 0.5:
        return "amber"
    return "red"


def _draw_pill(painter, rect, text, colors, font, align=Qt.AlignmentFlag.AlignLeft, dot=None, hollow_dot=False):
    """Paint a rounded badge inside ``rect``; returns the occupied width."""
    bg, border, fg = colors
    fm = QtGui.QFontMetrics(font)
    dot_w = 9 if dot else 0
    w = fm.horizontalAdvance(text) + 12 + dot_w
    h = min(rect.height() - 2, fm.height() + 3)
    if align & Qt.AlignmentFlag.AlignHCenter:
        x = rect.x() + (rect.width() - w) / 2.0
    elif align & Qt.AlignmentFlag.AlignRight:
        x = rect.right() - w
    else:
        x = rect.x()
    y = rect.y() + (rect.height() - h) / 2.0
    box = QtCore.QRectF(x + 0.5, y + 0.5, w - 1, h - 1)
    painter.save()
    painter.setRenderHint(QtGui.QPainter.RenderHint.Antialiasing, True)
    painter.setPen(QtGui.QPen(QtGui.QColor(border), 1))
    painter.setBrush(QtGui.QColor(bg))
    painter.drawRoundedRect(box, 5, 5)
    tx = box.x() + 6
    if dot:
        r = 2.6
        cy = box.center().y()
        if hollow_dot:
            painter.setPen(QtGui.QPen(QtGui.QColor(dot), 1.1))
            painter.setBrush(Qt.BrushStyle.NoBrush)
        else:
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QtGui.QColor(dot))
        painter.drawEllipse(QtCore.QPointF(tx + r, cy), r, r)
        tx += dot_w
    painter.setPen(QtGui.QColor(fg))
    painter.setFont(font)
    painter.drawText(QtCore.QRectF(tx, box.y(), box.width(), box.height()),
                     int(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft), text)
    painter.restore()
    return w


class FunctionListDelegate(QtWidgets.QStyledItemDelegate):
    """Row: [● НОВЫЙ | ○ КЭШ]  name (mono) ............ 0xaddress"""

    def __init__(self, panel):
        super().__init__(panel.function_list)
        self.panel = panel
        self.row_height = 0

    def _fonts(self, option):
        base = QtGui.QFont(option.font)
        mono = mono_font(0.0, base=base)
        pill = QtGui.QFont(base)
        size = base.pointSizeF() if base.pointSizeF() > 0 else 9.0
        pill.setPointSizeF(max(6.5, size - 1.5))
        pill.setBold(True)
        addr = mono_font(-1.0, base=base)
        return mono, pill, addr

    def sizeHint(self, option, index):
        mono, pill, _ = self._fonts(option)
        h = max(QtGui.QFontMetrics(mono).height(), QtGui.QFontMetrics(pill).height() + 3) + 9
        return QtCore.QSize(200, max(h, self.row_height))

    def paint(self, painter, option, index):
        p = self.panel.ui_palette
        mono, pill_font, addr_font = self._fonts(option)
        rect = QtCore.QRect(option.rect)
        selected = bool(option.state & QtWidgets.QStyle.StateFlag.State_Selected)
        hover = bool(option.state & QtWidgets.QStyle.StateFlag.State_MouseOver)
        is_new = bool(index.data(ROLE_NEW))
        name = str(index.data(ROLE_NAME) or "")
        ea = int(index.data(ROLE_IDX) or 0)

        painter.save()
        painter.setRenderHint(QtGui.QPainter.RenderHint.Antialiasing, True)
        if selected or hover:
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QtGui.QColor(p["selection"] if selected else p["row_hover"]))
            painter.drawRoundedRect(QtCore.QRectF(rect).adjusted(1, 0.5, -1, -0.5), 5, 5)
        if selected:
            painter.setBrush(QtGui.QColor(p["accent"]))
            painter.drawRoundedRect(QtCore.QRectF(rect.x() + 1, rect.y() + 3, 3, rect.height() - 6), 1.5, 1.5)
        elif index.row() < index.model().rowCount() - 1:
            painter.setPen(QtGui.QPen(QtGui.QColor(p["row_divider"]), 1))
            painter.drawLine(rect.x() + 6, rect.bottom(), rect.right() - 6, rect.bottom())
        painter.restore()

        x = rect.x() + 8
        inner = rect.adjusted(0, 1, 0, -1)
        label = _t(self.panel.ctl, "НОВЫЙ") if is_new else _t(self.panel.ctl, "КЭШ")
        colors = p["green"] if is_new else p["grey"]
        pill_w = _draw_pill(painter, QtCore.QRect(x, inner.y(), 200, inner.height()), label, colors, pill_font,
                            dot=(p["green_dot"] if is_new else p["muted"]), hollow_dot=not is_new)
        x += pill_w + 7

        addr_text = f"{ea:#x}"
        addr_w = QtGui.QFontMetrics(addr_font).horizontalAdvance(addr_text)
        addr_rect = QtCore.QRect(rect.right() - addr_w - 8, rect.y(), addr_w + 2, rect.height())
        painter.save()
        painter.setFont(addr_font)
        painter.setPen(QtGui.QColor(p["new_addr"] if is_new else p["muted"]))
        painter.drawText(addr_rect, int(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignRight), addr_text)

        is_auto = bool(re.match(r"^(sub|nullsub|j_sub|unknown_libname|loc)_", name))
        name_font = QtGui.QFont(mono)
        name_font.setBold(is_new)
        if is_new:
            color = p["new_fg"]
        elif not is_auto:
            color = p["named_fg"]
        else:
            color = p["fg"]
        painter.setFont(name_font)
        painter.setPen(QtGui.QColor(color))
        name_rect = QtCore.QRect(x, rect.y(), max(10, addr_rect.x() - x - 8), rect.height())
        elided = QtGui.QFontMetrics(name_font).elidedText(name, Qt.TextElideMode.ElideRight, name_rect.width())
        painter.drawText(name_rect, int(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft), elided)
        painter.restore()


class ProposalDelegate(QtWidgets.QStyledItemDelegate):
    """Colored type badges, confidence badges and monospace identifiers."""

    def __init__(self, panel, tree):
        super().__init__(tree)
        self.panel = panel

    def initStyleOption(self, option, index):
        super().initStyleOption(option, index)
        p = self.panel.ui_palette
        col = index.column()
        kind = index.sibling(index.row(), 1).data(ROLE_KIND)
        pal = option.palette
        def set_fg(color):
            for group in (QtGui.QPalette.ColorGroup.Active, QtGui.QPalette.ColorGroup.Inactive):
                pal.setColor(group, QtGui.QPalette.ColorRole.Text, QtGui.QColor(color))
                pal.setColor(group, QtGui.QPalette.ColorRole.HighlightedText, QtGui.QColor(color))
        if col == 2:
            option.font = mono_font(-0.5, base=option.font)
            set_fg(p["fg"])
        elif col == 3:
            if kind in CODE_KINDS:
                option.font = mono_font(0.0, bold=True, base=option.font)
                set_fg(p["suggest_fg"])
            else:
                set_fg(p["fg"])
        elif col == 4:
            option.font = mono_font(-0.5, base=option.font)
            set_fg(p["muted"])
            if not option.text:
                option.text = "—"
        option.palette = pal

    def paint(self, painter, option, index):
        col = index.column()
        if col not in (1, 5):
            super().paint(painter, option, index)
            return
        p = self.panel.ui_palette
        opt = QtWidgets.QStyleOptionViewItem(option)
        self.initStyleOption(opt, index)
        opt.text = ""
        style = opt.widget.style() if opt.widget else QtWidgets.QApplication.style()
        style.drawControl(QtWidgets.QStyle.ControlElement.CE_ItemViewItem, opt, painter, opt.widget)
        font = QtGui.QFont(option.font)
        size = font.pointSizeF() if font.pointSizeF() > 0 else 9.0
        font.setPointSizeF(max(6.5, size - 1.0))
        font.setBold(True)
        rect = option.rect.adjusted(4, 2, -4, -2)
        if col == 1:
            kind = index.data(ROLE_KIND)
            text = _t(self.panel.ctl, KIND_SHORT.get(kind, str(index.data() or kind or "")))
            colors = p.get(KIND_COLOR.get(kind, "grey"), p["grey"])
            _draw_pill(painter, rect, text, colors, font)
        else:
            conf = index.data(ROLE_CONF)
            if conf is None:
                return
            mono = mono_font(-1.0, bold=True, base=option.font)
            colors = p[_conf_color(conf)]
            _draw_pill(painter, rect, f"{conf * 100:.0f}%", (colors[0], colors[0], colors[2]), mono,
                       align=Qt.AlignmentFlag.AlignHCenter)

    def sizeHint(self, option, index):
        size = super().sizeHint(option, index)
        return QtCore.QSize(size.width(), max(size.height(), QtGui.QFontMetrics(option.font).height() + 10))



def _chat_inline_markdown(text):
    """Render a safe, small Markdown subset for Qt rich text."""
    value = html.escape(text, quote=False)
    value = re.sub(r"`([^`]+)`", r"<code>\1</code>", value)
    value = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", value)
    value = re.sub(r"(?<!\*)\*([^*]+)\*(?!\*)", r"<em>\1</em>", value)
    value = re.sub(r"~~(.+?)~~", r"<del>\1</del>", value)
    value = re.sub(
        r"\[([^\]]+)\]\((https?://[^\s)]+)\)",
        r'<a href="\2">\1</a>', value,
    )
    return value


def _render_chat_markdown(text, palette):
    """Convert common Markdown blocks to readable, Qt-compatible HTML."""
    lines = str(text or "").replace("\r\n", "\n").replace("\r", "\n").split("\n")
    out = []
    paragraph = []
    list_kind = None
    code_lines = []
    in_code = False
    code_lang = ""

    def flush_paragraph():
        if paragraph:
            body = "<br>".join(_chat_inline_markdown(x) for x in paragraph)
            out.append(f'<p style="margin:5px 0 9px 0;">{body}</p>')
            paragraph.clear()

    def close_list():
        nonlocal list_kind
        if list_kind:
            out.append(f"</{list_kind}>")
            list_kind = None

    for line in lines:
        fence = re.match(r"^\s*```\s*([A-Za-z0-9_+.-]*)\s*$", line)
        if fence:
            flush_paragraph()
            close_list()
            if not in_code:
                in_code = True
                code_lang = fence.group(1)
                code_lines = []
            else:
                label = (f'<div style="color:{palette["muted"]};font-size:8pt;'
                         f'padding:3px 8px 0 8px;">{html.escape(code_lang or "CODE")}</div>')
                code = html.escape("\n".join(code_lines), quote=False)
                out.append(
                    f'<div style="background:{palette["code"]};border:1px solid {palette["border"]};'
                    f'border-radius:6px;margin:7px 0 10px 0;">{label}'
                    f'<pre style="white-space:pre-wrap;margin:5px 8px 8px 8px;'
                    f'font-family:Consolas,monospace;font-size:9pt;color:{palette["fg"]};">{code}</pre></div>'
                )
                in_code = False
                code_lang = ""
            continue
        if in_code:
            code_lines.append(line)
            continue

        if not line.strip():
            flush_paragraph()
            close_list()
            continue
        if re.match(r"^\s*(---+|\*\*\*+|___+)\s*$", line):
            flush_paragraph()
            close_list()
            out.append(f'<hr style="border:0;border-top:1px solid {palette["border"]};margin:9px 0;">')
            continue

        heading = re.match(r"^(#{1,4})\s+(.+)$", line)
        if heading:
            flush_paragraph()
            close_list()
            level = len(heading.group(1))
            size = {1: "14pt", 2: "12pt", 3: "11pt", 4: "10pt"}[level]
            out.append(
                f'<p style="font-size:{size};font-weight:700;margin:10px 0 5px 0;">'
                f'{_chat_inline_markdown(heading.group(2))}</p>'
            )
            continue

        quote = re.match(r"^\s*>\s?(.*)$", line)
        if quote:
            flush_paragraph()
            close_list()
            out.append(
                f'<blockquote style="margin:5px 0 8px 5px;padding:4px 9px;'
                f'border-left:3px solid {palette["muted"]};color:{palette["muted"]};">'
                f'{_chat_inline_markdown(quote.group(1))}</blockquote>'
            )
            continue

        bullet = re.match(r"^\s*[-*+]\s+(.+)$", line)
        numbered = re.match(r"^\s*\d+[.)]\s+(.+)$", line)
        kind = "ul" if bullet else ("ol" if numbered else None)
        if kind:
            flush_paragraph()
            if list_kind != kind:
                close_list()
                out.append(f'<{kind} style="margin:4px 0 9px 0;padding-left:22px;">')
                list_kind = kind
            item = bullet.group(1) if bullet else numbered.group(1)
            out.append(f'<li style="margin:2px 0;">{_chat_inline_markdown(item)}</li>')
            continue

        close_list()
        paragraph.append(line)

    if in_code:
        label = (f'<div style="color:{palette["muted"]};font-size:8pt;padding:3px 8px 0 8px;">'
                 f'{html.escape(code_lang or "CODE")}</div>')
        code = html.escape("\n".join(code_lines), quote=False)
        out.append(f'<div style="background:{palette["code"]};border:1px solid {palette["border"]};'
                   f'border-radius:6px;margin:7px 0 10px 0;">{label}'
                   f'<pre style="white-space:pre-wrap;margin:5px 8px 8px 8px;'
                   f'font-family:Consolas,monospace;font-size:9pt;color:{palette["fg"]};">{code}</pre></div>')
    flush_paragraph()
    close_list()
    return "".join(out)



# ---------------------------------------------------------------------------
# Chat-only rich Markdown rendering
# ---------------------------------------------------------------------------
def _render_chat_table(rows, palette):
    """Render a Markdown pipe table as a Qt-compatible HTML table."""
    parsed = []
    for row in rows:
        cells = [cell.strip() for cell in row.strip().strip("|").split("|")]
        parsed.append(cells)
    if len(parsed) < 2:
        return ""
    if not all(re.match(r"^:?-{3,}:?$", c.replace(" ", "")) for c in parsed[1]):
        return ""
    headers = parsed[0]
    body = parsed[2:]
    count = max(1, len(headers))
    out = [
        f'<table cellspacing="0" cellpadding="5" width="100%" '
        f'style="border-collapse:collapse;margin:7px 0 11px 0;'
        f'border:1px solid {palette["border"]};">'
    ]
    out.append("<tr>")
    for i in range(count):
        value = headers[i] if i < len(headers) else ""
        out.append(
            f'<th align="left" style="background:{palette["code"]};'
            f'border:1px solid {palette["border"]};padding:6px;'
            f'font-weight:700;">{_chat_inline_markdown(value)}</th>'
        )
    out.append("</tr>")
    for row in body:
        out.append("<tr>")
        for i in range(count):
            value = row[i] if i < len(row) else ""
            out.append(
                f'<td valign="top" style="border:1px solid {palette["border"]};'
                f'padding:6px;">{_chat_inline_markdown(value)}</td>'
            )
        out.append("</tr>")
    out.append("</table>")
    return "".join(out)


def _render_chat_code_block(code_lines, language, palette):
    """Render code with preserved whitespace and optional unified-diff colors."""
    safe_lang = html.escape((language or "CODE")[:32])
    is_diff = (language or "").lower() in ("diff", "patch", "udiff")
    rendered = []
    for line in code_lines:
        safe = html.escape(line, quote=False) or "&nbsp;"
        color = palette["fg"]
        bg = "transparent"
        weight = "normal"
        if is_diff:
            if line.startswith(("+++", "---")):
                color, weight = palette["muted"], "bold"
            elif line.startswith("@@"):
                color, bg, weight = palette.get("accent", palette["fg"]), palette["code"], "bold"
            elif line.startswith("+"):
                color, bg = "#16803c", "#e8f5e9"
            elif line.startswith("-"):
                color, bg = "#c0392b", "#fdecea"
        rendered.append(
            f'<tr><td style="padding:0 7px;background:{bg};">'
            f'<span style="color:{color};font-weight:{weight};">{safe}</span></td></tr>'
        )
    if not rendered:
        rendered.append("<tr><td>&nbsp;</td></tr>")
    return (
        f'<table width="100%" cellspacing="0" cellpadding="0" '
        f'style="background:{palette["code"]};border:1px solid {palette["border"]};'
        f'border-radius:6px;margin:7px 0 10px 0;">'
        f'<tr><td style="padding:4px 8px;color:{palette["muted"]};font-size:8pt;'
        f'border-bottom:1px solid {palette["border"]};">{safe_lang}</td></tr>'
        f'<tr><td><table width="100%" cellspacing="0" cellpadding="0" '
        f'style="font-family:Consolas,monospace;font-size:9pt;white-space:pre;">'
        f'{"".join(rendered)}</table></td></tr></table>'
    )


def _looks_like_unfenced_code(line):
    """Recognize common long decompiler/C++ lines without Markdown fences."""
    value = line.strip()
    if len(value) < 180:
        return False
    markers = (
        "__fastcall", "__int64", "uintptr_t", "DWORD", "QWORD",
        "LODWORD(", "LOBYTE(", "switch (", "return 1;",
    )
    return ("{" in value and "}" in value and ";" in value
            and sum(marker in value for marker in markers) >= 2)


def _render_chat_message_markdown(text, palette):
    """Enhanced Markdown renderer used only by the AI chat history."""
    lines = str(text or "").replace("\r\n", "\n").replace("\r", "\n").split("\n")
    out, paragraph = [], []
    list_kind = None
    code_lines, code_fence, code_len, code_lang = [], None, 0, ""
    table_lines = []

    def flush_paragraph():
        if paragraph:
            out.append('<p style="margin:5px 0 9px 0;">' +
                       "<br>".join(_chat_inline_markdown(x) for x in paragraph) +
                       "</p>")
            paragraph.clear()

    def close_list():
        nonlocal list_kind
        if list_kind:
            out.append(f"</{list_kind}>")
            list_kind = None

    def flush_table():
        if table_lines:
            rendered = _render_chat_table(table_lines, palette)
            if rendered:
                out.append(rendered)
            else:
                paragraph.extend(table_lines)
            table_lines.clear()

    def flush_code():
        out.append(_render_chat_code_block(code_lines, code_lang, palette))
        code_lines.clear()

    for line in lines:
        fence = re.match(r"^\s*(`{3,}|~{3,})\s*([A-Za-z0-9_+#.-]*)\s*$", line)
        if fence:
            flush_paragraph()
            flush_table()
            close_list()
            marker = fence.group(1)
            if code_fence is None:
                code_fence, code_len, code_lang = marker[0], len(marker), fence.group(2)
            elif marker[0] == code_fence and len(marker) >= code_len:
                flush_code()
                code_fence, code_len, code_lang = None, 0, ""
            else:
                code_lines.append(line)
            continue

        if code_fence is not None:
            code_lines.append(line)
            continue

        if line.strip().startswith("|") and line.strip().endswith("|"):
            flush_paragraph()
            close_list()
            table_lines.append(line)
            continue
        elif table_lines:
            flush_table()

        if _looks_like_unfenced_code(line):
            flush_paragraph()
            close_list()
            out.append(_render_chat_code_block([line], "C/C++ (detected)", palette))
            continue

        if not line.strip():
            flush_paragraph()
            close_list()
            continue
        if re.match(r"^\s*(---+|\*\*\*+|___+)\s*$", line):
            flush_paragraph()
            close_list()
            out.append(f'<hr style="border:0;border-top:1px solid {palette["border"]};margin:9px 0;">')
            continue

        heading = re.match(r"^(#{1,4})\s+(.+)$", line)
        if heading:
            flush_paragraph()
            close_list()
            size = {1: "14pt", 2: "12pt", 3: "11pt", 4: "10pt"}[len(heading.group(1))]
            out.append(f'<p style="font-size:{size};font-weight:700;margin:10px 0 5px 0;">'
                       f'{_chat_inline_markdown(heading.group(2))}</p>')
            continue

        quote = re.match(r"^\s*>\s?(.*)$", line)
        if quote:
            flush_paragraph()
            close_list()
            out.append(f'<blockquote style="margin:5px 0 8px 5px;padding:4px 9px;'
                       f'border-left:3px solid {palette["muted"]};color:{palette["muted"]};">'
                       f'{_chat_inline_markdown(quote.group(1))}</blockquote>')
            continue

        bullet = re.match(r"^\s*[-*+]\s+(.+)$", line)
        numbered = re.match(r"^\s*\d+[.)]\s+(.+)$", line)
        kind = "ul" if bullet else ("ol" if numbered else None)
        if kind:
            flush_paragraph()
            if list_kind != kind:
                close_list()
                out.append(f'<{kind} style="margin:4px 0 9px 0;padding-left:22px;">')
                list_kind = kind
            item = bullet.group(1) if bullet else numbered.group(1)
            out.append(f'<li style="margin:2px 0;">{_chat_inline_markdown(item)}</li>')
            continue

        close_list()
        paragraph.append(line)

    if code_fence is not None:
        flush_code()
    flush_table()
    flush_paragraph()
    close_list()
    return "".join(out)


# ---------------------------------------------------------------------------
# Deep Scan report rendering (structured cards instead of raw Markdown)
# ---------------------------------------------------------------------------
_REPORT_LABELS = ("Глубокий анализ", "Глубина", "Статус", "Предложение", "Уверенность", "Назначение",
                  "Обоснование", "Связь", "Ссылки на функции", "Подтверждённые факты", "Гипотезы",
                  "Поля/смещения", "Условия и ветвления", "Циклы и контейнеры", "Вспомогательные вызовы", "Итоги")
_STATUS_COLOR = {"предложено": "blue", "уже подходит": "green", "недостаточно данных": "amber", "ошибка анализа": "red"}
_CONF_CAT_COLOR = {"высокая": "green", "средняя": "amber", "низкая": "red"}


def _md_unescape(text):
    return re.sub(r"\\([\\`*_{}\[\]()#+\-.!|>~])", r"\1", str(text or ""))


def _canon(value, lang, choices):
    value = str(value or "").strip()
    for c in choices:
        if value == c or value == tr(c, lang) or value.lower() == tr(c, lang).lower():
            return c
    return value


def parse_deep_report(md, lang):
    """Parse the Markdown produced by Controller._deep_job into structured data."""
    report = {"mode": "", "nodes": None, "limit": None, "graph_depth": None, "items": [], "summary": []}
    current = None
    header_bullets = 0
    for raw in str(md or "").replace("\r\n", "\n").split("\n"):
        line = _md_unescape(raw.rstrip())
        if not line.strip() or line.strip() == "---":
            continue
        m = re.match(r"^###\s+(.+?)\s+\(`@(0x[0-9a-fA-F]+)`\)\s*$", line)
        if m:
            current = {"name": m.group(1).strip(), "ea": m.group(2), "depth": None, "status": "", "fields": []}
            report["items"].append(current)
            continue
        m = re.match(r"^###\s+(.+?):\s+(.+)$", line)
        if m and not report["items"]:
            report["mode"] = m.group(2).strip()
            continue
        m = re.match(r"^\s*-\s+\*\*\[Depth\s+(\d+)\]\s+(.+?)\*\*\s+\(`@(0x[0-9a-fA-F]+)`\)\s*(?:\|\s*[^:]+:\s*\*(.*?)\*)?\s*$", line)
        if m:
            current = {"name": m.group(2).strip(), "ea": m.group(3), "depth": int(m.group(1)),
                       "status": (m.group(4) or "").strip(), "fields": []}
            report["items"].append(current)
            continue
        m = re.match(r"^\*\*(.+?):\*\*\s*(.*)$", line)
        if m and _canon(m.group(1), lang, ("Итоги",)) == "Итоги":
            report["summary"] = [int(x) for x in re.findall(r"\d+", m.group(2))]
            current = None
            continue
        m = re.match(r"^\s*-\s+\*\*(.+?):\*\*\s*(.*)$", line)
        if m and current is not None:
            label = _canon(m.group(1), lang, _REPORT_LABELS)
            value = m.group(2).strip()
            if label == "Глубина":
                dm = re.match(r"^(\d+)\s*·\s*\*\*[^*]+:\*\*\s*\*(.*?)\*", value)
                if dm:
                    current["depth"] = int(dm.group(1))
                    current["status"] = dm.group(2).strip()
                continue
            current["fields"].append([label, value])
            continue
        if not report["items"] and re.match(r"^\s*-\s+", line):
            nums = [int(x) for x in re.findall(r"\*\*(\d+)\*\*", line)]
            bolds = re.findall(r"\*\*([^*]+)\*\*", line)
            if header_bullets == 0:
                report["nodes"] = nums[0] if nums else None
                lim = re.search(r"\(\s*[^:]+:\s*(\d+)\s*\)", line)
                report["limit"] = int(lim.group(1)) if lim else None
            elif header_bullets == 1:
                if bolds:
                    report["mode"] = report["mode"] or bolds[0]
                report["graph_depth"] = nums[-1] if nums else None
            header_bullets += 1
            continue
        if current is not None and current["fields"]:
            current["fields"][-1][1] += "\n" + line.strip()
    return report


def _pill_html(text, colors, mono=False, size="8pt"):
    bg, _border, fg = colors
    fam = f"font-family:{MONO_CSS};" if mono else ""
    return (f'<span style="background-color:{bg};color:{fg};font-weight:700;font-size:{size};{fam}">'
            f'&nbsp;{html.escape(str(text))}&nbsp;</span>')


def _field_value_html(value, p):
    value = str(value or "").strip()
    if value.startswith("[") and value.endswith("]"):
        try:
            items = json.loads(value)
            if isinstance(items, list):
                lis = "".join(f'<li style="margin:1px 0;">{_chat_inline_markdown(str(x))}</li>' for x in items)
                return f'<ul style="margin:2px 0 2px 0; -qt-list-indent:1;">{lis}</ul>'
        except (ValueError, TypeError):
            pass
    return "<br>".join(_chat_inline_markdown(x) for x in value.split("\n"))


def render_deep_report_html(report, p, lang):
    T = lambda s: tr(s, lang)
    cards = []
    for item in report["items"]:
        status = _canon(item.get("status"), lang, tuple(_STATUS_COLOR))
        depth = item.get("depth")
        conf_cat = ""
        suggestion = None
        unchanged = False
        rows = []
        for label, value in item["fields"]:
            if label == "Предложение":
                m = re.match(r"^`([^`]*)`\s*(?:\(|·)?\s*(?:[^:()`]+:\s*([^)]+))?\)?\s*$", value)
                if m:
                    suggestion = m.group(1)
                    conf_cat = (m.group(2) or "").strip()
                else:
                    suggestion = value
                unchanged = suggestion in ("(без изменений)", T("(без изменений)"))
                continue
            rows.append((label, value))

        anchor = f'ea{item["ea"].lower().replace("0x", "")}'
        head_left = []
        if depth is not None:
            head_left.append(_pill_html(f"Depth {depth}", p["blue"], mono=True))
        head_left.append(f'&nbsp;<a name="{anchor}"></a><span style="font-family:{MONO_CSS};font-weight:700;'
                         f'color:{p["fg"]};">{html.escape(item["name"])}</span>')
        head_left.append(f'&nbsp;<span style="font-family:{MONO_CSS};color:{p["muted"]};font-size:8.5pt;">'
                         f'@ {html.escape(item["ea"])}</span>')
        if status:
            head_left.append("&nbsp;&nbsp;" + _pill_html(T(status), p[_STATUS_COLOR.get(status, "grey")]))
        head_right = ""
        if conf_cat:
            cat = _canon(conf_cat, lang, tuple(_CONF_CAT_COLOR))
            head_right = _pill_html(f'{T("Уверенность")}: {T(cat)}', p[_CONF_CAT_COLOR.get(cat, "grey")])

        body = []
        if suggestion is not None:
            if unchanged:
                sug = f'<span style="color:{p["muted"]};font-style:italic;">{html.escape(T("(без изменений)"))}</span>'
            else:
                sug = (f'<span style="font-family:{MONO_CSS};font-weight:700;color:{p["suggest_fg"]};'
                       f'background-color:{p["suggest_bg"]};">&nbsp;{html.escape(suggestion)}&nbsp;</span>')
            body.append(f'<p style="margin:0 0 6px 0;"><span style="color:{p["muted"]};font-weight:600;">'
                        f'{html.escape(T("Предложение"))}:</span>&nbsp; {sug}</p>')
        for label, value in rows:
            if label == "Обоснование":
                body.append(
                    f'<table width="100%" cellspacing="0" cellpadding="0" style="margin:4px 0 6px 0;">'
                    f'<tr><td width="3" bgcolor="{p["accent"]}"></td>'
                    f'<td bgcolor="{p["reason_bg"]}" style="padding:5px 9px;">'
                    f'<span style="color:{p["fg_soft"]};font-weight:600;">{html.escape(T(label))}: </span>'
                    f'<span style="color:{p["fg"]};">{_field_value_html(value, p)}</span></td></tr></table>'
                )
            else:
                body.append(f'<p style="margin:0 0 6px 0;"><span style="color:{p["muted"]};font-weight:600;">'
                            f'{html.escape(T(label))}: </span>{_field_value_html(value, p)}</p>')

        cards.append(
            f'<table width="100%" cellspacing="0" cellpadding="0" border="1" '
            f'style="border-collapse:collapse;border-color:{p["border"]};border-style:solid;margin:0 0 10px 0;">'
            f'<tr><td bgcolor="{p["strip"]}" style="padding:5px 9px;">'
            f'<table width="100%" cellspacing="0" cellpadding="0" border="0"><tr>'
            f'<td>{"".join(head_left)}</td><td align="right">{head_right}</td></tr></table></td></tr>'
            f'<tr><td bgcolor="{p["surface"]}" style="padding:8px 11px 4px 11px;">{"".join(body)}</td></tr></table>'
        )
    return "".join(cards)


def render_deep_footer(report, lang):
    T = lambda s: tr(s, lang)
    left = ""
    if report.get("mode"):
        left = f'{html.escape(T("Режим"))}: <b>{html.escape(T(report["mode"]))}</b>'
        if report.get("graph_depth") is not None:
            left += f' ({html.escape(T("глубина"))} {report["graph_depth"]})'
    parts = []
    total = report.get("nodes")
    done = len(report.get("items") or [])
    if total is not None:
        parts.append(f'{T("Узлов")}: {done}/{total}')
    summary = report.get("summary") or []
    if len(summary) >= 5:
        parts.append(f'{T("Имён")}: {summary[1]}')
        parts.append(f'{T("Ошибок")}: {summary[4]}')
    return left, " · ".join(parts)


class ChatTextEdit(QtWidgets.QTextEdit):
    send_requested = QtCore.Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptRichText(False)
        self.setMaximumHeight(58)

    def keyPressEvent(self, event):
        if event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            if event.modifiers() & Qt.KeyboardModifier.ControlModifier:
                self.send_requested.emit(self.toPlainText())
                event.accept()
                return
        super().keyPressEvent(event)


def _button(text, variant=None, tooltip=None, fixed_width=None, fixed_height=None):
    b = QtWidgets.QPushButton(text)
    if variant:
        b.setProperty("variant", variant)
    if tooltip:
        b.setToolTip(tooltip)
    if fixed_width:
        b.setFixedWidth(fixed_width)
    if fixed_height:
        b.setFixedHeight(fixed_height)
    b.setCursor(Qt.CursorShape.PointingHandCursor)
    return b


def _scaled_font(widget, delta, bold=False, mono=False):
    font = mono_font(delta, bold=bold, base=widget.font()) if mono else QtGui.QFont(widget.font())
    if not mono:
        size = font.pointSizeF() if font.pointSizeF() > 0 else 9.0
        font.setPointSizeF(max(6.5, size + delta))
        font.setBold(bold)
    widget.setFont(font)
    return widget


def _divider():
    line = QtWidgets.QFrame()
    line.setObjectName("cardDivider")
    line.setFixedHeight(1)
    return line


class Panel(QtWidgets.QWidget):
    models_loaded = QtCore.Signal(object)

    def __init__(self, ctl):
        super().__init__()
        self.ctl = ctl
        self.current_streaming_text = ""
        self.current_function = None
        self.current_function_suffix = ""
        self.function_results = []
        self.active_function_record = None
        self._models_request_id = 0
        self._busy = False
        self._last_error_section = None
        self.models_loaded.connect(self._on_models_loaded)
        self.deep_summary_details = ""
        self.deep_summary_props = []
        self.ui_palette = ui_theme(self.ctl.cfg.get("ui_theme", "Light"))

        self.setObjectName("aiAssistantPanel")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setAutoFillBackground(True)
        root = QtWidgets.QVBoxLayout(self)
        root.setContentsMargins(7, 7, 7, 7)
        root.setSpacing(7)

        # ---- 1. Top toolbar: model, provider badge, refresh, settings ----
        top = QtWidgets.QHBoxLayout()
        top.setSpacing(5)
        self.model_combo = QtWidgets.QComboBox()
        self.model_combo.setEditable(True)
        self.model_combo.setMinimumWidth(140)
        self.model_combo.setSizePolicy(QtWidgets.QSizePolicy.Policy.Expanding, QtWidgets.QSizePolicy.Policy.Fixed)
        self.model_combo.currentTextChanged.connect(self.on_model_changed)
        top.addWidget(self.model_combo, 1)

        self.provider_badge = QtWidgets.QLabel()
        self.provider_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.provider_badge.setMinimumHeight(22)
        top.addWidget(self.provider_badge)

        self.b_ref = _button("↻", "icon", _t(ctl, "Обновить список моделей"), 28, 26)
        self.b_ref.setAccessibleName(_t(ctl, "Обновить список моделей"))
        self.b_ref.clicked.connect(self.refresh_models)
        top.addWidget(self.b_ref)

        self.b_set = _button("⚙", "icon", _t(ctl, "Настройки AI Assistant"), 28, 26)
        self.b_set.setAccessibleName(_t(ctl, "Настройки AI Assistant"))
        self.b_set.clicked.connect(ctl.settings)
        top.addWidget(self.b_set)
        root.addLayout(top)

        # ---- 2. Function history (left) + compact operation card (right) ----
        history_row = QtWidgets.QHBoxLayout()
        history_row.setSpacing(7)
        self.function_list = QtWidgets.QListWidget()
        self.function_list.setObjectName("deepFunctionList")
        self.function_list.setSelectionMode(QtWidgets.QAbstractItemView.SelectionMode.SingleSelection)
        self.function_list.setUniformItemSizes(True)
        self.function_list.setMouseTracking(True)
        self.function_list.setVerticalScrollMode(QtWidgets.QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.function_list.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.function_list.itemClicked.connect(self.on_function_item_clicked)
        self.function_list.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.function_list.customContextMenuRequested.connect(self.on_function_context_menu)
        self.function_list.setToolTip("● НОВЫЙ — анализ выполнен в текущем сеансе IDA\n○ КЭШ — результат сохранён в базе IDB ранее")
        self.function_delegate = FunctionListDelegate(self)
        self.function_list.setItemDelegate(self.function_delegate)
        history_row.addWidget(self.function_list, 69)

        self.operation_card = QtWidgets.QFrame()
        self.operation_card.setObjectName("operationCard")
        self.operation_card.setMinimumWidth(160)
        self.operation_card.setMaximumWidth(215)
        card_layout = QtWidgets.QVBoxLayout(self.operation_card)
        card_layout.setContentsMargins(7, 6, 7, 6)
        card_layout.setSpacing(0)
        self.operation_stack = QtWidgets.QStackedWidget()
        card_layout.addWidget(self.operation_stack, 1)
        self._build_card_idle(ctl)
        self._build_card_busy(ctl)
        self._build_card_error(ctl)
        self.operation_stack.setCurrentIndex(0)
        history_row.addWidget(self.operation_card, 31)
        self.history_row_widget = QtWidgets.QWidget()
        self.history_row_widget.setObjectName("plainPage")
        self.history_row_widget.setLayout(history_row)
        history_row.setContentsMargins(0, 0, 0, 0)
        root.addWidget(self.history_row_widget)

        # ---- 3. Tabs ----
        self.tabs = QtWidgets.QTabWidget()
        self.tabs.setDocumentMode(False)
        # Keep the legacy Scan workspace object for cache compatibility, but do not expose it as a tab.
        self.tab_scan = self.create_workspace_tab("scan", "Быстрый анализ функции, имени и локальных переменных.")
        self.tab_deep = self.create_workspace_tab("deep", "Анализ Xref и связей.")
        self.tab_pseudo = self.create_pseudocode_tab()
        self.tab_chat = self.create_chat_tab()
        self.tabs.addTab(self.tab_deep, _t(ctl, "Глубокое сканирование"))
        self.tabs.addTab(self.tab_pseudo, _t(ctl, "Псевдокод"))
        self.tabs.addTab(self.tab_chat, _t(ctl, "Чат с ИИ"))
        root.addWidget(self.tabs, 1)

        self.refresh_models()
        self.apply_theme()
        translate_widget_tree(self, self.ctl.cfg.get("interface_language", "Russian"))
        self._update_history_height()
        self._update_apply_state(self.tab_deep.tree)
        # Show functions cached in the IDB right away, before the cursor moves.
        self.refresh_function_list()
        QtCore.QTimer.singleShot(0, self.refresh_function_list)

    # ------------------------------------------------------------------
    # Operation card
    # ------------------------------------------------------------------
    def _card_grid(self, rows, value_names):
        grid = QtWidgets.QGridLayout()
        grid.setContentsMargins(0, 0, 0, 0)
        grid.setHorizontalSpacing(6)
        grid.setVerticalSpacing(1)
        values = []
        for row, (key, initial) in enumerate(rows):
            k = _scaled_font(QtWidgets.QLabel(_t(self.ctl, key)), -1.0)
            k.setObjectName("cardKey")
            v = _scaled_font(QtWidgets.QLabel(initial), -1.0, mono=True)
            v.setObjectName(value_names[row])
            v.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            v.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            grid.addWidget(k, row, 0)
            grid.addWidget(v, row, 1)
            values.append((k, v))
        grid.setColumnStretch(1, 1)
        return grid, values

    def _build_card_idle(self, ctl):
        page = QtWidgets.QWidget()
        page.setObjectName("cardPage")
        lay = QtWidgets.QVBoxLayout(page)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(4)
        head = QtWidgets.QHBoxLayout()
        head.setSpacing(4)
        self.status = _scaled_font(QtWidgets.QLabel("● " + _t(ctl, "Готово")), -0.5, bold=True)
        self.status.setProperty("pill", "green")
        head.addWidget(self.status, 0)
        head.addStretch(1)
        self.b_test = _scaled_font(_button("▶ " + _t(ctl, "Тест"), "small",
                                           _t(ctl, "Проверить подключение и обновить список моделей")), -1.0)
        self.b_test.clicked.connect(self.refresh_models)
        head.addWidget(self.b_test)
        lay.addLayout(head)
        grid, values = self._card_grid((("Токены:", "0 / 0"), ("Цена:", "—"), ("Время:", "—")),
                                       ("cardValue", "cardCost", "cardValue"))
        (self.k_tokens, self.idle_tokens), (self.k_cost, self.idle_cost), (self.k_time, self.idle_time) = values
        lay.addLayout(grid)
        lay.addStretch(1)
        lay.addWidget(_divider())
        buttons = QtWidgets.QHBoxLayout()
        buttons.setSpacing(4)
        self.b_log = _scaled_font(_button("☰ " + _t(ctl, "Лог"), "small", _t(ctl, "Открыть журнал плагина в окне Output IDA")), -1.0)
        self.b_log.clicked.connect(self.open_log_output)
        self.b_clear_stats = _scaled_font(_button("⌫ " + _t(ctl, "Очистить"), "small", _t(ctl, "Сбросить отображаемую статистику запросов")), -1.0)
        self.b_clear_stats.clicked.connect(self.clear_operation_stats)
        buttons.addWidget(self.b_log, 1)
        buttons.addWidget(self.b_clear_stats, 1)
        lay.addLayout(buttons)
        self.operation_stack.addWidget(page)

    def _build_card_busy(self, ctl):
        page = QtWidgets.QWidget()
        page.setObjectName("cardPage")
        lay = QtWidgets.QVBoxLayout(page)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(4)
        head = QtWidgets.QHBoxLayout()
        head.setSpacing(4)
        self.busy_status = _scaled_font(QtWidgets.QLabel("◌ " + _t(ctl, "Анализ...")), -0.5, bold=True)
        self.busy_status.setObjectName("busyTitle")
        head.addWidget(self.busy_status, 1)
        self.b_cancel = _scaled_font(_button("✕ " + _t(ctl, "Отмена"), "danger", _t(ctl, "Прервать текущий запрос к LLM")), -1.0)
        self.b_cancel.setProperty("variant", "danger")
        self.b_cancel.clicked.connect(self.ctl.cancel)
        self.b_cancel.setEnabled(False)
        head.addWidget(self.b_cancel)
        lay.addLayout(head)
        self.busy = QtWidgets.QProgressBar()
        self.busy.setRange(0, 100)
        self.busy.setValue(0)
        self.busy.setTextVisible(False)
        self.busy.setFixedHeight(8)
        lay.addWidget(self.busy)
        meta = QtWidgets.QHBoxLayout()
        self.busy_node = _scaled_font(QtWidgets.QLabel(_t(ctl, "Узел 0/0")), -1.5, mono=True)
        self.busy_node.setObjectName("cardMeta")
        self.busy_elapsed = _scaled_font(QtWidgets.QLabel("0.0с"), -1.5, mono=True)
        self.busy_elapsed.setObjectName("cardMeta")
        meta.addWidget(self.busy_node, 1)
        meta.addWidget(self.busy_elapsed)
        lay.addLayout(meta)
        lay.addStretch(1)
        lay.addWidget(_divider())
        grid, values = self._card_grid((("Поток:", "0 / 0 tok"), ("Оценка:", "—")), ("cardStream", "cardValue"))
        (self.k_stream, self.busy_tokens), (self.k_estimate, self.busy_cost) = values
        lay.addLayout(grid)
        self.operation_stack.addWidget(page)

    def _build_card_error(self, ctl):
        page = QtWidgets.QWidget()
        page.setObjectName("cardPage")
        lay = QtWidgets.QVBoxLayout(page)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(4)
        head = QtWidgets.QHBoxLayout()
        self.error_title = _scaled_font(QtWidgets.QLabel("⚠ " + _t(ctl, "Ошибка")), -0.5, bold=True)
        self.error_title.setProperty("pill", "red")
        head.addWidget(self.error_title)
        head.addStretch(1)
        lay.addLayout(head)
        self.error_text = _scaled_font(QtWidgets.QLabel(""), -1.5)
        self.error_text.setObjectName("cardError")
        self.error_text.setWordWrap(True)
        self.error_text.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
        self.error_text.setSizePolicy(QtWidgets.QSizePolicy.Policy.Ignored, QtWidgets.QSizePolicy.Policy.Ignored)
        lay.addWidget(self.error_text, 1)
        lay.addWidget(_divider())
        buttons = QtWidgets.QHBoxLayout()
        buttons.setSpacing(4)
        self.b_retry = _scaled_font(_button("↻ " + _t(ctl, "Повторить"), "primary"), -1.0)
        self.b_retry.setProperty("variant", "primary")
        self.b_retry.clicked.connect(self.retry_last_error)
        self.b_reset_error = _scaled_font(_button(_t(ctl, "Сброс"), "small", _t(ctl, "Сбросить ошибку")), -1.0)
        self.b_reset_error.clicked.connect(lambda: self.operation_stack.setCurrentIndex(0))
        buttons.addWidget(self.b_retry, 1)
        buttons.addWidget(self.b_reset_error)
        lay.addLayout(buttons)
        self.operation_stack.addWidget(page)

    def _update_history_height(self):
        """Exactly four function rows are visible; the card matches that height."""
        opt = QtWidgets.QStyleOptionViewItem()
        opt.font = self.function_list.font()
        self.function_delegate.row_height = 0
        row_h = self.function_delegate.sizeHint(opt, QtCore.QModelIndex()).height()
        frame = self.function_list.frameWidth() * 2 + 6
        list_h = row_h * 4 + frame
        card_h = self.operation_card.minimumSizeHint().height()
        height = max(list_h, card_h)
        # Stretch the rows so that exactly four functions fill the list.
        self.function_delegate.row_height = max(row_h, (height - frame) // 4)
        height = self.function_delegate.row_height * 4 + frame
        self.function_list.doItemsLayout()
        self.function_list.setFixedHeight(height)
        self.operation_card.setFixedHeight(height)

    def _set_status(self, text, kind="green"):
        glyph = {"green": "●", "amber": "●", "red": "⚠", "blue": "●"}.get(kind, "●")
        self.status.setText(f"{glyph} {text}")
        self.status.setProperty("pill", kind)
        self._repolish(self.status)

    @staticmethod
    def _repolish(widget):
        try:
            widget.style().unpolish(widget)
            widget.style().polish(widget)
            widget.update()
        except RuntimeError:
            pass

    # ------------------------------------------------------------------
    # Language / telemetry
    # ------------------------------------------------------------------
    def apply_language(self):
        """Refresh the primary visible controls after changing interface language."""
        t = lambda value: _t(self.ctl, value)
        translate_widget_tree(self, self.ctl.cfg.get("interface_language", "Russian"))
        self.b_ref.setToolTip(t("Обновить список моделей"))
        self.b_ref.setAccessibleName(t("Обновить список моделей"))
        self.b_set.setToolTip(t("Настройки AI Assistant"))
        self.b_set.setAccessibleName(t("Настройки AI Assistant"))
        self._set_status(t("Готово"), "green")
        self.busy_status.setText("◌ " + t("Анализ..."))
        self.b_cancel.setText("✕ " + t("Отмена"))
        self.b_test.setText("▶ " + t("Тест"))
        self.b_log.setText("☰ " + t("Лог"))
        self.b_clear_stats.setText("⌫ " + t("Очистить"))
        self.b_retry.setText("↻ " + t("Повторить"))
        self.b_reset_error.setText(t("Сброс"))
        self.error_title.setText("⚠ " + t("Ошибка"))
        for label, key in ((self.k_tokens, "Токены:"), (self.k_cost, "Цена:"), (self.k_time, "Время:"),
                           (self.k_stream, "Поток:"), (self.k_estimate, "Оценка:")):
            label.setText(t(key))
        for index, key in enumerate(("Глубокое сканирование", "Псевдокод", "Чат с ИИ")):
            self.tabs.setTabText(index, t(key))
        if hasattr(self, "depth_combo"):
            for index, key in enumerate(("Поверхностный анализ", "Базовый анализ", "Глубокий анализ", "Очень глубокий анализ")):
                self.depth_combo.setItemText(index, t(key))
        for attr, key in (("b_run", "Запустить"), ("b_pseudo_fetch", "Анализировать псевдокод"),
                          ("b_chat_send", "Отправить"), ("b_apply_pseudo", "Применить")):
            widget = getattr(self, attr, None)
            if widget:
                prefix = {"b_run": "▶ ", "b_pseudo_fetch": "▶ ", "b_apply_pseudo": "✓ "}.get(attr, "")
                widget.setText(prefix + t(key))
        if hasattr(self, "b_copy"):
            self.b_copy.setText(t("Копировать"))
        if hasattr(self, "b_toggle_all"):
            self.b_toggle_all.setText(t("Выбрать все / Снять"))
        if hasattr(self, "b_reanalyze"):
            self.b_reanalyze.setToolTip(t("Повторно выполнить анализ открытой функции без использования кэша"))
            self.b_reanalyze.setAccessibleName(t("Повторный анализ"))
        if hasattr(self, "pseudo_search"):
            self.pseudo_search.setPlaceholderText(t("Поиск в псевдокоде..."))
        if hasattr(self, "chat_input"):
            self.chat_input.setPlaceholderText(t("Введите вопрос по функции... (Ctrl+Enter для отправки)"))
        for tab in (self.tab_scan, self.tab_deep):
            if getattr(tab, "hint_label", None) is not None:
                tab.hint_label.setText(t(tab.hint_key))
        self.update_provider_badge()
        self._update_apply_state(self.tab_deep.tree)
        self._render_details(self.tab_deep)
        self.function_list.viewport().update()

    def update_provider_badge(self):
        mode, _ = get_active_profile(self.ctl.cfg)
        is_cloud = mode == "cloud"
        self.provider_badge.setText("● API" if is_cloud else "● LOCAL")
        self.provider_badge.setProperty("pill", "green" if is_cloud else "purple")
        self.provider_badge.setToolTip(_t(self.ctl, "Облачная API-модель" if is_cloud else "Локальная модель"))
        self._repolish(self.provider_badge)

    def _format_metrics(self, meta):
        in_tok = int(meta.get("prompt_tokens", 0) or 0)
        out_tok = int(meta.get("completion_tokens", 0) or 0)
        est = "~" if meta.get("tokens_estimated") else ""
        cost = float(meta.get("cost_usd", 0.0) or 0.0)
        dt = float(meta.get("duration", 0.0) or 0.0)
        mode = meta.get("provider", get_active_profile(self.ctl.cfg)[0])

        def compact(value):
            return f"{value / 1000:.1f}k" if value >= 1000 else str(value)
        return in_tok, out_tok, est, cost, dt, mode, compact

    def update_telemetry(self, meta):
        if not meta:
            return
        self._last_metrics = dict(meta)
        self.update_provider_badge()
        in_tok, out_tok, est, cost, dt, mode, compact = self._format_metrics(meta)
        self.idle_tokens.setText(f"{est}{compact(in_tok)} / {est}{compact(out_tok)}")
        cached = int(meta.get("cached_prompt_tokens", 0) or 0)
        tip = f"Prompt: {in_tok:,} · Completion: {out_tok:,}"
        if cached:
            tip += f" · Cache hit: {cached:,} ({cached * 100 // max(1, in_tok)}%)"
        self.idle_tokens.setToolTip(tip)
        self.idle_cost.setText(f"${cost:.4f}" if mode == "cloud" else "local")
        retries = int(meta.get("retries", 0) or 0)
        self.idle_time.setText(f"{dt:.1f}с · {retries} req" if retries else f"{dt:.1f}с")

    def update_operation_progress(self, payload):
        if not payload:
            return
        done = int(payload.get("done", 0))
        total = max(1, int(payload.get("total", 1)))
        elapsed = float(payload.get("elapsed", 0.0))
        metrics = payload.get("metrics", {}) or {}
        in_tok, out_tok, est, cost, _dt, mode, compact = self._format_metrics(metrics)
        self.busy.setRange(0, 100)
        self.busy.setValue(min(100, int(done * 100 / total)))
        self.busy_node.setText(f"{_t(self.ctl, 'Узел')} {done}/{total}")
        self.busy_elapsed.setText(f"{elapsed:.1f}с")
        self.busy_tokens.setText(f"{est}{compact(in_tok)} / {est}{compact(out_tok)} tok")
        self.busy_cost.setText(f"~${cost:.4f}" if mode == "cloud" else "local")
        self._last_metrics = dict(metrics)

    def clear_operation_stats(self):
        self._last_metrics = {}
        self.idle_tokens.setText("0 / 0")
        self.idle_tokens.setToolTip("")
        self.idle_cost.setText("—")
        self.idle_time.setText("—")

    def open_log_output(self):
        try:
            ida_kernwin.msg("\n[AI Assistant] Окно вывода IDA содержит журнал плагина.\n")
            show = getattr(ida_kernwin, "show_output_window", None)
            if callable(show):
                show()
        except Exception as e:
            log_msg("ERROR", "UI", f"Cannot open IDA output window: {e}", self.ctl.cfg)

    def on_model_changed(self, text):
        new_model = text.strip()
        if not new_model:
            return
        mode, prof = get_active_profile(self.ctl.cfg)
        prof["model"] = new_model
        saved = prof.setdefault("saved_models", [])
        if new_model not in saved:
            saved.insert(0, new_model)
        save_cfg(self.ctl.cfg)
        log_msg("INFO", "Config", f"Active model switched to '{new_model}' ({mode})", self.ctl.cfg)

    def refresh_models(self):
        """Fetch model names off the IDA UI thread."""
        self.update_provider_badge()
        _, prof = get_active_profile(self.ctl.cfg)
        current_model = prof.get("model", "")
        self._models_request_id += 1
        request_id = self._models_request_id
        cfg_snapshot = copy.deepcopy(self.ctl.cfg)
        self.model_combo.setEnabled(False)
        self.model_combo.setToolTip(_t(self.ctl, "Обновление списка моделей…"))

        def worker():
            try:
                models, remote_ok = fetch_available_models(cfg_snapshot)
                payload = (request_id, list(models or []), current_model, remote_ok, "")
            except Exception as exc:
                payload = (request_id, [], current_model, False, str(exc))
            try:
                self.models_loaded.emit(payload)
            except RuntimeError:
                pass

        threading.Thread(target=worker, name="IDA-AI-Models", daemon=True).start()

    @QtCore.Slot(object)
    def _on_models_loaded(self, payload):
        request_id, models, current_model, remote_ok, error = payload
        if request_id != self._models_request_id:
            return
        models = list(models or [])
        if current_model and current_model not in models:
            models.insert(0, current_model)
        self.model_combo.blockSignals(True)
        self.model_combo.clear()
        self.model_combo.addItems(models)
        self.model_combo.setCurrentText(current_model)
        self.model_combo.blockSignals(False)
        self.model_combo.setEnabled(True)
        self.model_combo.setToolTip(
            _t(self.ctl, "Список моделей обновлён") if remote_ok else
            (_t(self.ctl, f"Не удалось обновить список моделей: {error}") if error else _t(self.ctl, "Показаны сохранённые модели"))
        )

    # ------------------------------------------------------------------
    # Theme
    # ------------------------------------------------------------------
    def apply_theme(self, *_args):
        """Apply the plugin-owned Light/Dark interface theme (independent from IDA)."""
        p = ui_theme(self.ctl.cfg.get("ui_theme", "Light"))
        self.ui_palette = p
        self.setPalette(make_qpalette(p))
        self.setStyleSheet(build_stylesheet(p))

        # Pseudocode keeps its own three syntax themes (Dark / Light / Midnight).
        pseudo_name = normalize_theme_name(self.ctl.cfg.get("theme"), tuple(THEMES), "Dark")
        self.ctl.cfg["theme"] = pseudo_name
        pc = THEMES[pseudo_name]
        editor = getattr(self, "pseudo_editor", None)
        highlighter = getattr(self, "pseudo_highlighter", None)
        if highlighter is not None:
            try:
                highlighter.update_theme(pseudo_name)
            except RuntimeError:
                pass
        if editor is not None:
            try:
                editor.setStyleSheet(
                    f"QPlainTextEdit {{ background-color: {pc['bg']}; color: {pc['fg']};"
                    f" border: 1px solid {p['border']}; border-radius: 8px; padding: 4px;"
                    f" selection-background-color: {p['accent']}; selection-color: {p['accent_fg']};"
                    f" font-family: 'Consolas', 'Cascadia Mono', 'Courier New', monospace; font-size: 10pt; }}"
                )
            except RuntimeError:
                pass

        self._chat_palette = {
            "page": p["surface"], "assistant": p["chat_ai"], "assistant_border": p["chat_ai_border"],
            "user": p["chat_user"], "user_border": p["chat_user_border"], "fg": p["fg"], "user_fg": p["fg"],
            "muted": p["muted"], "border": p["border"], "code": p["code_bg"], "code_fg": p["code_fg"],
            "link": p["link"], "accent": p["link"],
        }
        for tab in (getattr(self, "tab_deep", None), getattr(self, "tab_scan", None)):
            if tab is not None and hasattr(tab, "details"):
                self._style_document(tab.details)
                self._render_details(tab)
        chat = getattr(self, "chat_history_view", None)
        if chat is not None and hasattr(self, "chat_history_cache"):
            self.set_chat_history(self.chat_history_cache)
        for widget in (getattr(self, "function_list", None),
                       getattr(getattr(self, "tab_deep", None), "tree", None),
                       getattr(getattr(self, "tab_pseudo", None), "tree", None)):
            if widget is not None:
                widget.viewport().update()

    def _style_document(self, browser):
        p = self.ui_palette
        browser.document().setDefaultStyleSheet(
            f"code {{ font-family: {MONO_CSS}; background-color: {p['code_bg']}; color: {p['code_fg']}; }}"
            f"a {{ color: {p['link']}; text-decoration: none; }}"
            f"p {{ margin-top: 0px; }}"
        )

    # ------------------------------------------------------------------
    # Tabs
    # ------------------------------------------------------------------
    def _tool_strip(self):
        strip = QtWidgets.QFrame()
        strip.setObjectName("toolStrip")
        lay = QtWidgets.QHBoxLayout(strip)
        lay.setContentsMargins(8, 6, 8, 6)
        lay.setSpacing(6)
        return strip, lay

    def _pane_body(self, margins=(6, 6, 6, 6)):
        body = QtWidgets.QWidget()
        body.setObjectName("paneBody")
        body.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        lay = QtWidgets.QVBoxLayout(body)
        lay.setContentsMargins(*margins)
        lay.setSpacing(6)
        return body, lay

    def _tab_page(self):
        w = QtWidgets.QWidget()
        w.setObjectName("tabPage")
        w.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        layout = QtWidgets.QVBoxLayout(w)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        return w, layout

    def _make_proposal_tree(self, columns, widths):
        tree = QtWidgets.QTreeWidget()
        tree.setColumnCount(len(columns))
        tree.setHeaderLabels(columns)
        tree.setRootIsDecorated(False)
        tree.setUniformRowHeights(True)
        tree.setIndentation(0)
        tree.setMouseTracking(True)
        tree.setAllColumnsShowFocus(True)
        tree.setEditTriggers(QtWidgets.QAbstractItemView.EditTrigger.DoubleClicked
                             | QtWidgets.QAbstractItemView.EditTrigger.EditKeyPressed)
        header = tree.header()
        header.setStretchLastSection(False)
        header.setHighlightSections(False)
        header.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        for col, width in enumerate(widths):
            if width is None:
                header.setSectionResizeMode(col, QtWidgets.QHeaderView.ResizeMode.Stretch)
            else:
                header.setSectionResizeMode(col, QtWidgets.QHeaderView.ResizeMode.Interactive)
                tree.setColumnWidth(col, width)
        header.setSectionResizeMode(0, QtWidgets.QHeaderView.ResizeMode.Fixed)
        tree.setItemDelegate(ProposalDelegate(self, tree))
        tree.props_ref = []
        return tree

    def create_workspace_tab(self, section, desc):
        w, layout = self._tab_page()
        strip, header_layout = self._tool_strip()
        hint = QtWidgets.QLabel(_t(self.ctl, desc))
        hint.setObjectName("stripHint")
        hint.setToolTip(_t(self.ctl, "Анализ функции, Xref, подфункций, структур и callback-связей.") if section == "deep" else "")
        hint.setSizePolicy(QtWidgets.QSizePolicy.Policy.Ignored, QtWidgets.QSizePolicy.Policy.Preferred)
        hint.setMinimumWidth(40)
        header_layout.addWidget(hint, 1)
        w.hint_label = hint
        w.hint_key = desc

        if section == "deep":
            header_layout.addWidget(QtWidgets.QLabel(_t(self.ctl, "Глубина:")))
            self.depth_combo = QtWidgets.QComboBox()
            self.depth_combo.addItem(_t(self.ctl, "Поверхностный анализ"), 0)
            self.depth_combo.addItem(_t(self.ctl, "Базовый анализ"), 1)
            self.depth_combo.addItem(_t(self.ctl, "Глубокий анализ"), 2)
            self.depth_combo.addItem(_t(self.ctl, "Очень глубокий анализ"), 3)
            self.depth_combo.setToolTip(
                "Поверхностный — только выбранная функция\n"
                "Базовый — функция, её Xref и непосредственные вызовы\n"
                "Глубокий — рекурсивный граф вызовов, типы, структуры и дизассемблер\n"
                "Очень глубокий — дополнительно поиск callback и function-pointer связей"
            )
            current_depth = max(0, min(3, int(self.ctl.cfg.get("deep_depth", 1))))
            self.depth_combo.setCurrentIndex(current_depth)
            self.depth_combo.currentIndexChanged.connect(self.on_depth_changed)
            header_layout.addWidget(self.depth_combo)

        b_run = _button("▶ " + _t(self.ctl, "Запустить"), "primary", _t(self.ctl, "Запустить анализ"))
        if section == "deep":
            self.b_run = b_run
        b_run.setObjectName("primaryAnalysisButton")
        b_run.clicked.connect(lambda: self.ctl.run_section(section))
        header_layout.addWidget(b_run)
        if section == "deep":
            self.b_reanalyze = _button("↻", "icon", _t(self.ctl, "Повторно выполнить анализ открытой функции без использования кэша"), 28, 25)
            self.b_reanalyze.setObjectName("reanalyzeButton")
            self.b_reanalyze.setAccessibleName(_t(self.ctl, "Повторный анализ"))
            self.b_reanalyze.setEnabled(False)
            self.b_reanalyze.clicked.connect(self.reanalyze_displayed_function)
            header_layout.addWidget(self.b_reanalyze)
        layout.addWidget(strip)

        body, body_layout = self._pane_body()
        splitter = QtWidgets.QSplitter(Qt.Orientation.Vertical)
        splitter.setChildrenCollapsible(False)
        tree = self._make_proposal_tree(
            ["✓", _t(self.ctl, "Тип"), _t(self.ctl, "Цель"), _t(self.ctl, "Предложение"), _t(self.ctl, "Сейчас"), _t(self.ctl, "Увер.")],
            [34, 92, 120, None, 110, 58],
        )
        tree.itemChanged.connect(lambda *_: self._update_apply_state(tree))
        tree.currentItemChanged.connect(lambda cur, _prev: self._scroll_details_to(w, cur))
        splitter.addWidget(tree)

        inspector = QtWidgets.QFrame()
        inspector.setObjectName("inspector")
        insp_layout = QtWidgets.QVBoxLayout(inspector)
        insp_layout.setContentsMargins(1, 1, 1, 1)
        insp_layout.setSpacing(0)
        details = QtWidgets.QTextBrowser()
        details.setOpenExternalLinks(True)
        details.setFrameShape(QtWidgets.QFrame.Shape.NoFrame)
        insp_layout.addWidget(details, 1)
        footer = QtWidgets.QFrame()
        footer.setObjectName("inspectorFooter")
        footer_layout = QtWidgets.QHBoxLayout(footer)
        footer_layout.setContentsMargins(9, 4, 9, 4)
        footer_left = _scaled_font(QtWidgets.QLabel(""), -1.0)
        footer_left.setObjectName("footerText")
        footer_right = _scaled_font(QtWidgets.QLabel(""), -1.0, mono=True)
        footer_right.setObjectName("footerText")
        footer_right.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        footer_layout.addWidget(footer_left, 1)
        footer_layout.addWidget(footer_right)
        footer.setVisible(False)
        insp_layout.addWidget(footer)
        splitter.addWidget(inspector)
        splitter.setStretchFactor(0, 4)
        splitter.setStretchFactor(1, 6)
        splitter.setSizes([180, 260])
        body_layout.addWidget(splitter, 1)

        apply_layout = QtWidgets.QHBoxLayout()
        apply_layout.setSpacing(6)
        b_apply = _button("✓ " + _t(self.ctl, "Применить выбранные") + " (0)", "primary")
        b_apply.clicked.connect(lambda: self.on_apply(tree))
        apply_layout.addWidget(b_apply)
        b_toggle = _button(_t(self.ctl, "Выбрать все / Снять"))
        b_toggle.clicked.connect(lambda: self.toggle_all_checks(tree))
        apply_layout.addWidget(b_toggle)
        apply_layout.addStretch(1)
        bottom_status = _scaled_font(QtWidgets.QLabel(""), -1.0, mono=True)
        bottom_status.setObjectName("bottomStatus")
        apply_layout.addWidget(bottom_status)
        body_layout.addLayout(apply_layout)
        layout.addWidget(body, 1)
        if section == "deep":
            self.b_apply = b_apply
            self.b_toggle_all = b_toggle

        tree.apply_button = b_apply
        tree.bottom_status = bottom_status
        w.tree = tree
        w.details = details
        w.details_md = ""
        w.footer = footer
        w.footer_left = footer_left
        w.footer_right = footer_right
        return w

    def _checked_count(self, tree):
        return sum(1 for i in range(tree.topLevelItemCount()) if tree.topLevelItem(i).checkState(0) == CHECKED)

    def _update_apply_state(self, tree):
        button = getattr(tree, "apply_button", None)
        if button is None:
            return
        n = self._checked_count(tree)
        total = tree.topLevelItemCount()
        button.setText("✓ " + _t(self.ctl, "Применить выбранные") + f" ({n})")
        button.setEnabled(n > 0)
        status = getattr(tree, "bottom_status", None)
        if status is not None:
            status.setText(f'<span style="color:{self.ui_palette["green_dot"] if total else self.ui_palette["faint"]};">●</span> '
                           f'{html.escape(_t(self.ctl, "Предложений"))}: {total}')

    def toggle_all_checks(self, tree):
        total = tree.topLevelItemCount()
        if not total:
            return
        state = UNCHECKED if self._checked_count(tree) == total else CHECKED
        tree.blockSignals(True)
        for i in range(total):
            tree.topLevelItem(i).setCheckState(0, state)
        tree.blockSignals(False)
        self._update_apply_state(tree)

    def _scroll_details_to(self, tab, item):
        if item is None or not hasattr(tab, "details"):
            return
        ea = item.data(0, ROLE_EA)
        if ea:
            try:
                tab.details.scrollToAnchor(f"ea{int(ea):x}")
            except (TypeError, ValueError, RuntimeError):
                pass

    def _render_details(self, tab):
        if tab is None or not hasattr(tab, "details"):
            return
        md = getattr(tab, "details_md", "") or ""
        lang = self.ctl.cfg.get("interface_language", "Russian")
        p = self.ui_palette
        report = parse_deep_report(md, lang) if md else None
        if report and report["items"]:
            body = render_deep_report_html(report, p, lang)
            left, right = render_deep_footer(report, lang)
            tab.footer_left.setText(left)
            tab.footer_right.setText(right)
            tab.footer.setVisible(bool(left or right))
        else:
            body = _render_chat_markdown(md, {"muted": p["muted"], "code": p["code_bg"], "border": p["border"], "fg": p["fg"]}) if md else ""
            if not md:
                body = (f'<p style="color:{p["faint"]};margin-top:14px;" align="center">'
                        f'{html.escape(_t(self.ctl, "Результаты анализа появятся здесь"))}</p>')
            tab.footer.setVisible(False)
        tab.details.setHtml(
            f'<html><head><meta charset="utf-8"></head>'
            f'<body style="color:{p["fg"]};font-size:9.5pt;">'
            f'<div style="margin:2px 2px;">{body}</div></body></html>'
        )

    def reanalyze_displayed_function(self):
        """Force a fresh DeepScan for the function currently represented in the panel."""
        ea = getattr(self.ctl, "displayed_func_ea", None)
        if ea is None:
            return
        self.ctl.run_section("deep", target_ea=int(ea), force=True)

    def on_depth_changed(self, index):
        val = self.depth_combo.itemData(index)
        if val is None:
            val = index
        self.ctl.cfg["deep_depth"] = max(0, min(3, int(val)))
        save_cfg(self.ctl.cfg)
        log_msg("INFO", "Config", f"Deep scan mode set to {self.depth_combo.currentText()} ({val})", self.ctl.cfg)

    def create_pseudocode_tab(self):
        w, layout = self._tab_page()
        strip, ctrl_layout = self._tool_strip()
        b_fetch = _button("▶ " + _t(self.ctl, "Анализировать псевдокод"), "primary")
        self.b_pseudo_fetch = b_fetch
        b_fetch.clicked.connect(lambda: self.ctl.run_section("pseudo"))
        ctrl_layout.addWidget(b_fetch)

        self.pseudo_search = QtWidgets.QLineEdit()
        self.pseudo_search.setClearButtonEnabled(True)
        self.pseudo_search.setPlaceholderText(_t(self.ctl, "Поиск в псевдокоде..."))
        self.pseudo_search.textChanged.connect(self.on_pseudo_search)
        ctrl_layout.addWidget(self.pseudo_search, 1)

        b_copy = _button(_t(self.ctl, "Копировать"))
        self.b_copy = b_copy
        b_copy.clicked.connect(
            lambda: QtWidgets.QApplication.clipboard().setText(
                self.pseudo_editor.toPlainText() if self.pseudo_editor else ""
            )
        )
        ctrl_layout.addWidget(b_copy)
        layout.addWidget(strip)

        body, body_layout = self._pane_body()
        splitter = QtWidgets.QSplitter(Qt.Orientation.Horizontal)
        splitter.setChildrenCollapsible(False)
        self.pseudo_editor = QtWidgets.QPlainTextEdit()
        self.pseudo_editor.setReadOnly(True)
        self.pseudo_editor.setLineWrapMode(QtWidgets.QPlainTextEdit.LineWrapMode.NoWrap)
        self.pseudo_highlighter = HexRaysHighlighter(self.pseudo_editor.document(), self.ctl.cfg.get("theme", "Dark"))
        splitter.addWidget(self.pseudo_editor)

        side_widget = QtWidgets.QWidget()
        side_widget.setObjectName("plainPage")
        side_layout = QtWidgets.QVBoxLayout(side_widget)
        side_layout.setContentsMargins(0, 0, 0, 0)
        side_layout.setSpacing(5)
        side_title = _scaled_font(QtWidgets.QLabel(_t(self.ctl, "Предложения ИИ:")), 0.0, bold=True)
        side_layout.addWidget(side_title)

        tree = self._make_proposal_tree(["✓", _t(self.ctl, "Тип"), _t(self.ctl, "Цель"), _t(self.ctl, "Новое")],
                                        [34, 88, 96, None])
        side_layout.addWidget(tree, 1)

        b_apply = _button("✓ " + _t(self.ctl, "Применить"), "primary")
        self.b_apply_pseudo = b_apply
        b_apply.clicked.connect(lambda: self.on_apply(tree))
        side_layout.addWidget(b_apply)

        splitter.addWidget(side_widget)
        splitter.setSizes([640, 300])
        body_layout.addWidget(splitter, 1)
        layout.addWidget(body, 1)

        w.tree = tree
        w.details = QtWidgets.QTextBrowser()
        return w

    def create_chat_tab(self):
        w, layout = self._tab_page()
        body, body_layout = self._pane_body((6, 6, 6, 6))
        self.chat_history_view = QtWidgets.QTextBrowser()
        self.chat_history_view.setOpenExternalLinks(True)
        body_layout.addWidget(self.chat_history_view, 1)
        layout.addWidget(body, 1)

        bar = QtWidgets.QFrame()
        bar.setObjectName("chatBar")
        input_layout = QtWidgets.QHBoxLayout(bar)
        input_layout.setContentsMargins(7, 6, 7, 6)
        input_layout.setSpacing(6)
        self.chat_input = ChatTextEdit()
        self.chat_input.setPlaceholderText(_t(self.ctl, "Введите вопрос по функции... (Ctrl+Enter для отправки)"))
        self.chat_input.send_requested.connect(self.on_send_chat)
        input_layout.addWidget(self.chat_input, 1)
        b_send = _button(_t(self.ctl, "Отправить"), "primary")
        self.b_chat_send = b_send
        b_send.clicked.connect(lambda: self.on_send_chat(self.chat_input.toPlainText()))
        input_layout.addWidget(b_send, 0, Qt.AlignmentFlag.AlignBottom)
        layout.addWidget(bar)
        self.chat_history_cache = []
        return w

    def on_send_chat(self, text):
        if not text.strip():
            return
        self.chat_input.clear()
        self.ctl.run_section("chat", text.strip())

    def append_chat_streaming_placeholder(self):
        self.current_streaming_text = ""

    def update_streaming(self, chunk):
        self.current_streaming_text += chunk
        if self.ctl.active_func_ea:
            f = ida_funcs.get_func(self.ctl.active_func_ea)
            if f:
                ent = self.ctl.get_func_db(f)
                history = ent.get("chat_history", [])
                temp_history = history + [{"role": "assistant", "content": self.current_streaming_text + " ▌"}]
                self.set_chat_history(temp_history)

    def remove_streaming_placeholder(self):
        self.current_streaming_text = ""
        if self.ctl.active_func_ea:
            f = ida_funcs.get_func(self.ctl.active_func_ea)
            if f:
                ent = self.ctl.get_func_db(f)
                self.set_chat_history(ent.get("chat_history", []))

    def on_pseudo_search(self, text):
        if not text or not self.pseudo_editor:
            return
        document = self.pseudo_editor.document()
        cursor = document.find(text, self.pseudo_editor.textCursor())
        if cursor.isNull():
            cursor = document.find(text)
        if not cursor.isNull():
            self.pseudo_editor.setTextCursor(cursor)

    # ------------------------------------------------------------------
    # State
    # ------------------------------------------------------------------
    def set_busy(self, on, text=""):
        self._busy = bool(on)
        try:
            if hasattr(self, "b_reanalyze"):
                self.b_reanalyze.setEnabled(bool(self.current_function) and not on)
            if getattr(self, "operation_stack", None) is not None:
                self.operation_stack.setCurrentIndex(1 if on else 0)
            if on:
                self.busy.setRange(0, 0)
                self.busy_node.setText(f"{_t(self.ctl, 'Узел')} 0/0")
                self.busy_elapsed.setText("0.0с")
                self.busy_tokens.setText("0 / 0 tok")
                self.busy_cost.setText("—")
                self.busy_status.setText("◌ " + _t(self.ctl, "Анализ..."))
                self.busy_status.setToolTip(_t(self.ctl, text or "Анализ..."))
            else:
                text = text or "Готово"
                if text.startswith("Ошибка"):
                    kind = "red"
                elif text.startswith("Запрос отменён"):
                    kind = "amber"
                elif text.startswith("Готово"):
                    kind = "green"
                else:
                    kind = "blue"
                # Keep the pill short; the full text (with duration) goes to the tooltip.
                short = _t(self.ctl, "Готово") if text.startswith("Готово") else _t(self.ctl, text)
                self._set_status(short, kind)
                self.status.setToolTip(_t(self.ctl, text))
                self.busy.setRange(0, 100)
                self.busy.setValue(100 if text.startswith("Готово") else 0)
            if getattr(self, "b_cancel", None) is not None:
                self.b_cancel.setEnabled(bool(on))
        except RuntimeError:
            # The dock widget can be destroyed by IDA while a worker is finishing.
            return

    def set_header_info(self, name, ea, suffix=""):
        self.current_function = (str(name), int(ea)) if ea else None
        self.current_function_suffix = str(suffix or "")
        if hasattr(self, "b_reanalyze"):
            self.b_reanalyze.setEnabled(bool(ea) and not getattr(self, "_busy", False))
        self.refresh_function_list()

    def set_function_results(self, records, summary_details=None, summary_props=None):
        # These are subordinate nodes from the current DeepScan report. They are
        # intentionally not added to the user-facing history list.
        self.function_results = list(records or [])
        self.active_function_record = None
        if summary_details is not None:
            self.deep_summary_details = str(summary_details or "")
        if summary_props is not None:
            self.deep_summary_props = list(summary_props or [])

    def refresh_function_list(self):
        if not hasattr(self, "function_list"):
            return
        selected_ea = None
        current = self.function_list.currentItem()
        if current is not None:
            selected_ea = current.data(ROLE_IDX)
        if self.current_function:
            selected_ea = self.current_function[1]
        records = self.ctl.get_analyzed_functions() if self.ctl else []
        self.function_list.blockSignals(True)
        self.function_list.clear()
        for record in records:
            ea = int(record.get("ea", 0))
            if not ea:
                continue
            name = record.get("name") or f"sub_{ea:X}"
            is_new = bool(record.get("is_current_session"))
            marker = _t(self.ctl, "● НОВЫЙ") if is_new else _t(self.ctl, "○ КЭШ")
            item = QtWidgets.QListWidgetItem(f"{marker}  {name}    {ea:#x}")
            item.setData(ROLE_IDX, ea)
            item.setData(ROLE_NAME, name)
            item.setData(ROLE_NEW, is_new)
            if is_new:
                source_text = _t(self.ctl, "Проанализирована в текущем сеансе IDA")
            else:
                source_text = _t(self.ctl, "Загружена из постоянного кеша IDB (предыдущий сеанс)")
            item.setToolTip(f"{source_text}\n{name} @ {ea:#x}")
            self.function_list.addItem(item)
            if selected_ea == ea:
                self.function_list.setCurrentItem(item)
        self.function_list.blockSignals(False)

    def on_function_item_clicked(self, item):
        if not item or not self.ctl:
            return
        ea = item.data(ROLE_IDX)
        if ea is not None:
            self.ctl.select_analyzed_function(int(ea))

    def on_function_context_menu(self, pos):
        item = self.function_list.itemAt(pos)
        if item is None:
            return
        ea = item.data(ROLE_IDX)
        if ea is None:
            return
        menu = QtWidgets.QMenu(self)
        action = menu.addAction(_t(self.ctl, "Показать функцию в IDA"))
        chosen = menu.exec(self.function_list.mapToGlobal(pos))
        if chosen == action:
            try:
                ida_kernwin.jumpto(int(ea))
            except Exception as exc:
                log_msg("WARNING", "UI", f"Не удалось перейти к функции {int(ea):#x}: {exc}", self.ctl.cfg)

    def clear_ui(self):
        self.set_header_info("(нет функции)", 0, "")
        self.set_function_results([], "", [])
        for tab in (self.tab_scan, self.tab_deep):
            if tab and hasattr(tab, "tree"):
                tab.tree.clear()
                tab.tree.props_ref = []
                tab.details_md = ""
                self._render_details(tab)
                self._update_apply_state(tab.tree)
        if self.pseudo_editor:
            self.pseudo_editor.clear()
        if hasattr(self.tab_pseudo, "tree") and self.tab_pseudo.tree:
            self.tab_pseudo.tree.clear()
            self.tab_pseudo.tree.props_ref = []
        if hasattr(self, "chat_history_view") and self.chat_history_view:
            self.chat_history_cache = []
            self.chat_history_view.clear()

    def get_workspace_state(self, section):
        tab = self.tab_scan if section == "scan" else self.tab_deep
        if not tab or not hasattr(tab, "tree"):
            return [], ""
        props = getattr(tab.tree, "props_ref", [])
        for i in range(tab.tree.topLevelItemCount()):
            it = tab.tree.topLevelItem(i)
            idx = it.data(0, ROLE_IDX)
            if idx < len(props):
                props[idx]["checked"] = it.checkState(0) == CHECKED
                props[idx]["value"] = it.text(3)
        # The raw Markdown is kept so the cache round-trips losslessly.
        return props, getattr(tab, "details_md", "") or ""

    def set_workspace_state(self, section, props, details, function_results=None):
        tab = self.tab_scan if section == "scan" else self.tab_deep
        if not tab:
            return
        if hasattr(tab, "details"):
            tab.details_md = str(details or "")
            self._render_details(tab)
        if hasattr(tab, "tree"):
            self.populate_tree(tab.tree, props)
        if section == "deep" and function_results is not None:
            self.set_function_results(function_results, details, props)

    def get_pseudocode_state(self):
        code = self.pseudo_editor.toPlainText() if self.pseudo_editor else ""
        tab = self.tab_pseudo
        if not tab or not hasattr(tab, "tree"):
            return code, [], ""
        props = getattr(tab.tree, "props_ref", [])
        for i in range(tab.tree.topLevelItemCount()):
            it = tab.tree.topLevelItem(i)
            idx = it.data(0, ROLE_IDX)
            if idx < len(props):
                props[idx]["checked"] = it.checkState(0) == CHECKED
                props[idx]["value"] = it.text(3)
        details = tab.details.toPlainText() if hasattr(tab, "details") else ""
        return code, props, details

    def set_pseudocode_state(self, code, props, details):
        if self.pseudo_editor:
            self.pseudo_editor.setPlainText(code or "")
        tab = self.tab_pseudo
        if tab and hasattr(tab, "details"):
            tab.details.setPlainText(details or "")
        if tab and hasattr(tab, "tree"):
            self.populate_tree(tab.tree, props)

    def set_chat_history(self, history):
        if not hasattr(self, "chat_history_view") or not self.chat_history_view:
            return
        self.chat_history_cache = list(history or [])
        p = getattr(self, "_chat_palette", None) or {
            "page": "#ffffff", "assistant": "#f4f6f9", "assistant_border": "#dce3ec", "user": "#e5f1fb",
            "user_border": "#bcd9f5", "fg": "#1e1e1e", "user_fg": "#1e1e1e", "muted": "#6b7280",
            "border": "#c9ced6", "code": "#f4f5f7", "code_fg": "#004c99", "link": "#0052a3", "accent": "#0052a3",
        }
        ctx_name = self.current_function[0] if self.current_function else ""
        html_parts = []
        for h in self.chat_history_cache:
            is_user = h.get("role") == "user"
            if is_user:
                role = _t(self.ctl, "ВЫ")
                role_color = p["muted"]
            else:
                role = "AI Assistant" + (f" · {_t(self.ctl, 'Контекст')}: {ctx_name}" if ctx_name else "")
                role_color = p["accent"]
            bg = p["user"] if is_user else p["assistant"]
            border = p["user_border"] if is_user else p["assistant_border"]
            body = _render_chat_message_markdown(h.get("content", ""), p)
            html_parts.append(
                f'<table width="100%" cellspacing="0" cellpadding="0" border="1" '
                f'style="border-collapse:collapse;border-style:solid;border-color:{border};margin:0 0 8px 0;">'
                f'<tr><td bgcolor="{bg}" style="padding:8px 11px;">'
                f'<div style="color:{role_color};font-size:8pt;font-weight:700;margin-bottom:4px;">'
                f'{html.escape(role)}</div>'
                f'<div style="font-size:9.5pt;color:{p["user_fg"] if is_user else p["fg"]};">{body}</div>'
                f'</td></tr></table>'
            )
        self.chat_history_view.setHtml(
            f'<html><head><meta charset="utf-8"><style>'
            f'code {{ background-color:{p["code"]}; color:{p.get("code_fg", p["fg"])}; font-family:{MONO_CSS}; }} '
            f'a {{ color:{p.get("link", p["fg"])}; text-decoration:none; }} '
            f'</style></head><body style="color:{p["fg"]};">{"".join(html_parts)}</body></html>'
        )
        bar = self.chat_history_view.verticalScrollBar()
        bar.setValue(bar.maximum())

    def show_section_result(self, section, res):
        props = res.get("props", [])
        details = res.get("details", "")
        if res.get("metrics"):
            self.update_telemetry(res["metrics"])
        if section == "scan":
            self.set_workspace_state("scan", props, details)
        elif section == "deep":
            self.set_workspace_state("deep", props, details, res.get("function_results", []))
        elif section == "pseudo":
            self.set_pseudocode_state(res.get("code", ""), props, details)
        elif section in ("chat", "struct"):
            self.set_chat_history(details)

    def populate_tree(self, tree, props):
        tree.blockSignals(True)
        tree.clear()
        tree.props_ref = props
        lang_label = lambda kind: _t(self.ctl, KIND_LABEL.get(kind, kind))
        for i, p in enumerate(props):
            conf = p.get("conf")
            values = ["", lang_label(p["kind"]), str(p["target"]), str(p["value"])]
            if tree.columnCount() > 4:
                values += [str(p.get("current", "")), "" if conf is None else "%.0f%%" % (conf * 100)]
            it = QtWidgets.QTreeWidgetItem(values)
            it.setFlags(ITEM_FLAGS)
            it.setCheckState(0, CHECKED if p.get("checked") else UNCHECKED)
            it.setData(0, ROLE_IDX, i)
            it.setData(1, ROLE_KIND, p["kind"])
            it.setToolTip(1, lang_label(p["kind"]))
            it.setToolTip(2, str(p["target"]))
            it.setToolTip(3, str(p["value"]))
            ea = p.get("ea") or p.get("func")
            if ea:
                try:
                    it.setData(0, ROLE_EA, int(ea))
                except (TypeError, ValueError):
                    pass
            if tree.columnCount() > 5:
                it.setData(5, ROLE_CONF, None if conf is None else float(conf))
            tree.addTopLevelItem(it)
        tree.blockSignals(False)
        self._update_apply_state(tree)

    def show_error(self, section, err):
        message = str(err)
        log_msg("ERROR", section, message, self.ctl.cfg)
        if section in ("chat", "struct"):
            if hasattr(self, "chat_history_view") and self.chat_history_view:
                self.chat_history_view.append(
                    f"<b style='color:{self.ui_palette['red'][2]};'>{_t(self.ctl, 'Ошибка')}:</b> {html.escape(message)}")
        self._last_error_section = section
        code = re.search(r"\b(4\d\d|5\d\d)\b", message)
        self.error_title.setText("⚠ " + (f"{_t(self.ctl, 'Ошибка')} {code.group(1)}" if code else _t(self.ctl, "Ошибка")))
        first = message.strip().splitlines()[0] if message.strip() else _t(self.ctl, "Ошибка")
        self.error_text.setText(first if len(first) <= 140 else first[:137] + "…")
        self.error_text.setToolTip(message)
        self.b_retry.setVisible(section in ("deep", "pseudo", "scan"))
        try:
            self.operation_stack.setCurrentIndex(2)
        except RuntimeError:
            pass

    def retry_last_error(self):
        section = self._last_error_section
        self.operation_stack.setCurrentIndex(0)
        if section in ("deep", "pseudo", "scan"):
            self.ctl.run_section(section)

    def on_apply(self, tree):
        props = getattr(tree, "props_ref", [])
        sel = []
        for i in range(tree.topLevelItemCount()):
            it = tree.topLevelItem(i)
            idx = it.data(0, ROLE_IDX)
            if it.checkState(0) == CHECKED and idx < len(props):
                sel.append((props[idx], it.text(3)))
        if not sel:
            ida_kernwin.info(_t(self.ctl, "Ничего не выбрано для применения."))
            return
        ok, _ = self.ctl.apply(sel)
        self.operation_stack.setCurrentIndex(0)
        self._set_status(_t(self.ctl, f"Применено: {ok}"), "green")
