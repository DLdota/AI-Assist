# -*- coding: utf-8 -*-
"""
Plugin-owned visual themes.

* Interface themes (``UI_THEMES``): "Light" and "Dark". They are fully
  independent from the active IDA theme: every surface, border, scrollbar,
  check indicator and popup is styled explicitly, so IDA's application style
  sheet / palette cannot leak into the panel.
* Pseudocode themes (``THEMES``): Dark, Light, Midnight — syntax colors of the
  Hex-Rays preview editor, selectable separately.
"""
import os
import tempfile

from PySide6 import QtCore, QtGui

MONO_FAMILIES = ["Consolas", "Cascadia Mono", "JetBrains Mono", "Menlo", "DejaVu Sans Mono", "Courier New"]
UI_FAMILIES = ["Segoe UI", "Inter", "Helvetica Neue", "Arial"]

# ---------------------------------------------------------------------------
# Interface palettes (derived from the supplied HTML mock-up)
# ---------------------------------------------------------------------------
UI_THEMES = {
    "Light": {
        "name": "Light",
        "bg_top": "#f4f6f9", "bg_bottom": "#e9edf2",       # panel background gradient
        "surface": "#ffffff", "surface_alt": "#f7f8fa", "strip": "#f5f7fa",
        "card": "#fafbfc", "row_divider": "#eef0f3", "row_hover": "#f2f8ff",
        "border": "#c9ced6", "border_soft": "#dfe3e8", "border_strong": "#adb4bd",
        "fg": "#1e1e1e", "fg_soft": "#333333", "muted": "#6b7280", "faint": "#9aa1ab",
        "accent": "#0066cc", "accent_hover": "#005bb5", "accent_pressed": "#004c99",
        "accent_border": "#0052a3", "accent_fg": "#ffffff", "accent_soft": "#e5f1fb",
        "focus": "#0078d7", "link": "#0052a3",
        "selection": "#cce8ff", "selection_fg": "#0b2540", "selection_row": "#e8f2fc",
        "btn": "#fdfdfd", "btn_hover": "#e5f1fb", "btn_pressed": "#cce4f7", "btn_border": "#b4bac2",
        "disabled_bg": "#f2f3f5", "disabled_fg": "#a0a6ae", "disabled_border": "#d7dbe0",
        "scroll_track": "#f0f2f5", "scroll_thumb": "#c8cdd4", "scroll_thumb_hover": "#a6adb6",
        "tab": "#e6e9ee", "tab_hover": "#eef1f5", "tab_fg": "#4a5160",
        "progress_track": "#e6e9ee", "progress": "#0078d7",
        "code_bg": "#f4f5f7", "code_border": "#e0e3e8", "code_fg": "#004c99",
        "chat_user": "#e5f1fb", "chat_user_border": "#bcd9f5", "chat_ai": "#f4f6f9", "chat_ai_border": "#dce3ec",
        # semantic pills: (background, border, foreground)
        "green": ("#e8f5e9", "#a5d6a7", "#1b5e20"), "green_dot": "#2e7d32",
        "amber": ("#fff8e1", "#ffe082", "#8d6e00"),
        "red": ("#ffebee", "#ef9a9a", "#b71c1c"),
        "blue": ("#e3f2fd", "#bbdefb", "#0d47a1"),
        "purple": ("#f3e5f5", "#e1bee7", "#7b1fa2"),
        "teal": ("#e0f2f1", "#b2dfdb", "#00695c"),
        "grey": ("#f4f4f4", "#dcdcdc", "#666666"),
        "suggest_fg": "#1b5e20", "suggest_bg": "#f1f8e9",
        "named_fg": "#0052a3", "new_fg": "#0b3d14", "new_addr": "#2e6b36",
        "danger_bg": "#fff5f5", "danger_border": "#e0a8a8", "danger_fg": "#b71c1c", "danger_hover": "#ffebee",
        "reason_bg": "#fafafa", "string_fg": "#7b1fa2",
    },
    "Dark": {
        "name": "Dark",
        "bg_top": "#121417", "bg_bottom": "#0b0c0e",
        "surface": "#17191d", "surface_alt": "#1c1f24", "strip": "#1b1e23",
        "card": "#181b1f", "row_divider": "#22262c", "row_hover": "#1e2630",
        "border": "#2d3239", "border_soft": "#262a30", "border_strong": "#3a4049",
        "fg": "#e4e7eb", "fg_soft": "#c9ced5", "muted": "#8a919b", "faint": "#636a74",
        "accent": "#2f7cf6", "accent_hover": "#4a8ff8", "accent_pressed": "#1f66d6",
        "accent_border": "#3b82f6", "accent_fg": "#ffffff", "accent_soft": "#16243a",
        "focus": "#3b82f6", "link": "#7fb0ff",
        "selection": "#1d3a5f", "selection_fg": "#eaf2ff", "selection_row": "#1a2b42",
        "btn": "#20242a", "btn_hover": "#283040", "btn_pressed": "#1b2a40", "btn_border": "#353b44",
        "disabled_bg": "#1a1c20", "disabled_fg": "#5a616b", "disabled_border": "#2a2e34",
        "scroll_track": "#141619", "scroll_thumb": "#30353d", "scroll_thumb_hover": "#444b55",
        "tab": "#1a1d22", "tab_hover": "#20242a", "tab_fg": "#9aa2ad",
        "progress_track": "#23272d", "progress": "#3b82f6",
        "code_bg": "#111317", "code_border": "#2a2f36", "code_fg": "#8ab4ff",
        "chat_user": "#16243a", "chat_user_border": "#24406a", "chat_ai": "#1b1e23", "chat_ai_border": "#2a2f36",
        "green": ("#11291a", "#1f5130", "#6fdc8c"), "green_dot": "#4ade80",
        "amber": ("#2e250b", "#5c4a12", "#f2c94c"),
        "red": ("#341317", "#6b2128", "#ff8a8a"),
        "blue": ("#122540", "#1f4277", "#8ab4ff"),
        "purple": ("#26173a", "#4a2a63", "#d6a8ff"),
        "teal": ("#0f2b2a", "#1d5350", "#5eead4"),
        "grey": ("#1f2227", "#33383f", "#9aa1ab"),
        "suggest_fg": "#7ee2a0", "suggest_bg": "#11291a",
        "named_fg": "#7fb0ff", "new_fg": "#86efac", "new_addr": "#5fbf7f",
        "danger_bg": "#2a1215", "danger_border": "#6b2128", "danger_fg": "#ff8a8a", "danger_hover": "#3a171b",
        "reason_bg": "#1a1d22", "string_fg": "#d6a8ff",
    },
}

UI_THEME_LABELS = (("Light", "Светлая"), ("Dark", "Тёмная"))


def ui_theme(name):
    from ..config import normalize_theme_name
    return UI_THEMES[normalize_theme_name(name, tuple(UI_THEMES), "Light")]


def mono_font(point_delta=0.0, bold=False, base=None):
    font = QtGui.QFont(base) if base is not None else QtGui.QFont()
    font.setFamilies(MONO_FAMILIES)
    font.setStyleHint(QtGui.QFont.StyleHint.Monospace)
    if point_delta:
        size = font.pointSizeF() if font.pointSizeF() > 0 else 9.0
        font.setPointSizeF(max(6.0, size + point_delta))
    font.setBold(bool(bold))
    return font


def make_qpalette(p):
    """A complete QPalette so that unstyled bits never inherit IDA colors."""
    pal = QtGui.QPalette()
    C = QtGui.QColor
    R = QtGui.QPalette.ColorRole
    G = QtGui.QPalette.ColorGroup
    for group in (G.Active, G.Inactive):
        pal.setColor(group, R.Window, C(p["bg_top"]))
        pal.setColor(group, R.WindowText, C(p["fg"]))
        pal.setColor(group, R.Base, C(p["surface"]))
        pal.setColor(group, R.AlternateBase, C(p["surface_alt"]))
        pal.setColor(group, R.Text, C(p["fg"]))
        pal.setColor(group, R.Button, C(p["btn"]))
        pal.setColor(group, R.ButtonText, C(p["fg"]))
        pal.setColor(group, R.Highlight, C(p["selection"]))
        pal.setColor(group, R.HighlightedText, C(p["selection_fg"]))
        pal.setColor(group, R.Link, C(p["link"]))
        pal.setColor(group, R.ToolTipBase, C(p["surface"]))
        pal.setColor(group, R.ToolTipText, C(p["fg"]))
        pal.setColor(group, R.PlaceholderText, C(p["faint"]))
        pal.setColor(group, R.Mid, C(p["border"]))
        pal.setColor(group, R.Midlight, C(p["border_soft"]))
        pal.setColor(group, R.Dark, C(p["border_strong"]))
        pal.setColor(group, R.Light, C(p["surface"]))
        pal.setColor(group, R.Shadow, C("#000000"))
        pal.setColor(group, R.BrightText, C(p["accent_fg"]))
    for role, key in ((R.WindowText, "disabled_fg"), (R.Text, "disabled_fg"), (R.ButtonText, "disabled_fg"),
                      (R.Base, "disabled_bg"), (R.Button, "disabled_bg"), (R.Window, "bg_top"),
                      (R.Highlight, "selection"), (R.HighlightedText, "selection_fg")):
        pal.setColor(G.Disabled, role, C(p[key]))
    return pal


# ---------------------------------------------------------------------------
# Generated indicator images (QSS needs files for check marks / arrows)
# ---------------------------------------------------------------------------
_ICON_CACHE = {}


def _icon_dir():
    path = os.path.join(tempfile.gettempdir(), "ida_ai_assistant_ui_icons")
    os.makedirs(path, exist_ok=True)
    return path


def _render_icon(path, size, painter_fn, scale):
    img = QtGui.QImage(int(size * scale), int(size * scale), QtGui.QImage.Format.Format_ARGB32_Premultiplied)
    img.fill(QtCore.Qt.GlobalColor.transparent)
    qp = QtGui.QPainter(img)
    qp.setRenderHint(QtGui.QPainter.RenderHint.Antialiasing, True)
    qp.scale(scale, scale)
    painter_fn(qp, size)
    qp.end()
    img.save(path, "PNG")


def theme_icons(p):
    """Create (once) and return file paths of small theme-colored images."""
    key = p["name"]
    if key in _ICON_CACHE and all(os.path.exists(v) for v in _ICON_CACHE[key].values()):
        return _ICON_CACHE[key]
    base = _icon_dir()
    out = {}

    def check(qp, s):
        pen = QtGui.QPen(QtGui.QColor(p["accent_fg"]), 2.0)
        pen.setCapStyle(QtCore.Qt.PenCapStyle.RoundCap)
        pen.setJoinStyle(QtCore.Qt.PenJoinStyle.RoundJoin)
        qp.setPen(pen)
        qp.drawPolyline([QtCore.QPointF(s * 0.22, s * 0.52), QtCore.QPointF(s * 0.42, s * 0.72),
                         QtCore.QPointF(s * 0.78, s * 0.30)])

    def chevron(color, up=False):
        def fn(qp, s):
            pen = QtGui.QPen(QtGui.QColor(color), 1.6)
            pen.setCapStyle(QtCore.Qt.PenCapStyle.RoundCap)
            pen.setJoinStyle(QtCore.Qt.PenJoinStyle.RoundJoin)
            qp.setPen(pen)
            if up:
                pts = [QtCore.QPointF(s * 0.22, s * 0.64), QtCore.QPointF(s * 0.5, s * 0.36), QtCore.QPointF(s * 0.78, s * 0.64)]
            else:
                pts = [QtCore.QPointF(s * 0.22, s * 0.38), QtCore.QPointF(s * 0.5, s * 0.66), QtCore.QPointF(s * 0.78, s * 0.38)]
            qp.drawPolyline(pts)
        return fn

    def dash(qp, s):
        pen = QtGui.QPen(QtGui.QColor(p["accent_fg"]), 2.0)
        pen.setCapStyle(QtCore.Qt.PenCapStyle.RoundCap)
        qp.setPen(pen)
        qp.drawLine(QtCore.QPointF(s * 0.26, s * 0.5), QtCore.QPointF(s * 0.74, s * 0.5))

    specs = {
        "check": (12, check),
        "partial": (12, dash),
        "down": (10, chevron(p["muted"])),
        "up": (10, chevron(p["muted"], up=True)),
        "down_disabled": (10, chevron(p["disabled_fg"])),
    }
    for name, (size, fn) in specs.items():
        stem = f"{key.lower()}_{name}"
        path = os.path.join(base, stem + ".png")
        try:
            _render_icon(path, size, fn, 1)
            _render_icon(os.path.join(base, stem + "@2x.png"), size, fn, 2)
        except Exception:
            pass
        out[name] = path.replace("\\", "/")
    _ICON_CACHE[key] = out
    return out


# ---------------------------------------------------------------------------
# Style sheet
# ---------------------------------------------------------------------------
def build_stylesheet(p, root_selector="QWidget#aiAssistantPanel"):
    """Return a complete QSS for the panel (or a dialog) using palette ``p``."""
    ic = theme_icons(p)
    g, a, r, b = p["green"], p["amber"], p["red"], p["blue"]
    return f"""
{root_selector} {{
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 {p['bg_top']}, stop:1 {p['bg_bottom']});
    color: {p['fg']};
}}
QDialog {{
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 {p['bg_top']}, stop:1 {p['bg_bottom']});
    color: {p['fg']};
}}
QLabel {{ background: transparent; color: {p['fg']}; }}
QLabel:disabled {{ color: {p['disabled_fg']}; }}
QWidget#tabPage, QWidget#plainPage {{ background: transparent; }}
QToolTip {{
    background-color: {p['surface']}; color: {p['fg']};
    border: 1px solid {p['border']}; border-radius: 6px; padding: 4px 6px;
}}

/* ---------- Buttons ---------- */
QPushButton, QToolButton {{
    background-color: {p['btn']}; color: {p['fg']};
    border: 1px solid {p['btn_border']}; border-radius: 6px;
    padding: 3px 10px; min-height: 18px;
}}
QPushButton:hover, QToolButton:hover {{ background-color: {p['btn_hover']}; border-color: {p['focus']}; }}
QPushButton:pressed, QToolButton:pressed {{ background-color: {p['btn_pressed']}; border-color: {p['accent_pressed']}; }}
QPushButton:disabled, QToolButton:disabled {{
    background-color: {p['disabled_bg']}; color: {p['disabled_fg']}; border-color: {p['disabled_border']};
}}
QPushButton:focus {{ outline: none; }}
QPushButton[variant="primary"] {{
    background-color: {p['accent']}; color: {p['accent_fg']};
    border: 1px solid {p['accent_border']}; font-weight: 600;
}}
QPushButton[variant="primary"]:hover {{ background-color: {p['accent_hover']}; border-color: {p['accent_hover']}; }}
QPushButton[variant="primary"]:pressed {{ background-color: {p['accent_pressed']}; }}
QPushButton[variant="primary"]:disabled {{
    background-color: {p['disabled_bg']}; color: {p['disabled_fg']}; border-color: {p['disabled_border']};
}}
QPushButton[variant="danger"] {{
    background-color: {p['danger_bg']}; color: {p['danger_fg']}; border: 1px solid {p['danger_border']}; font-weight: 600;
}}
QPushButton[variant="danger"]:hover {{ background-color: {p['danger_hover']}; border-color: {p['danger_fg']}; }}
QPushButton[variant="danger"]:disabled {{
    background-color: {p['disabled_bg']}; color: {p['disabled_fg']}; border-color: {p['disabled_border']};
}}
QPushButton[variant="small"] {{ padding: 1px 7px; min-height: 16px; border-radius: 5px; }}
QPushButton[variant="icon"] {{ padding: 0px; border-radius: 6px; }}

/* ---------- Inputs ---------- */
QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox {{
    background-color: {p['surface']}; color: {p['fg']};
    border: 1px solid {p['btn_border']}; border-radius: 6px;
    padding: 2px 8px; min-height: 18px;
    selection-background-color: {p['accent']}; selection-color: {p['accent_fg']};
}}
QLineEdit:hover, QComboBox:hover, QSpinBox:hover, QDoubleSpinBox:hover,
QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QDoubleSpinBox:focus {{ border-color: {p['focus']}; }}
QLineEdit:disabled, QComboBox:disabled, QSpinBox:disabled, QDoubleSpinBox:disabled {{
    background-color: {p['disabled_bg']}; color: {p['disabled_fg']}; border-color: {p['disabled_border']};
}}
QComboBox {{ padding-right: 22px; }}
QComboBox::drop-down {{
    subcontrol-origin: padding; subcontrol-position: center right;
    width: 20px; border: none; background: transparent;
}}
QComboBox::down-arrow {{ image: url("{ic['down']}"); width: 10px; height: 10px; }}
QComboBox::down-arrow:disabled {{ image: url("{ic['down_disabled']}"); }}
QComboBox QLineEdit {{ border: none; padding: 0px; background: transparent; min-height: 0px; }}
QComboBox QAbstractItemView {{
    background-color: {p['surface']}; color: {p['fg']};
    border: 1px solid {p['border']}; border-radius: 6px; padding: 3px; outline: none;
    selection-background-color: {p['selection']}; selection-color: {p['selection_fg']};
}}
QSpinBox::up-button, QDoubleSpinBox::up-button {{
    subcontrol-origin: border; subcontrol-position: top right; width: 18px;
    border: none; border-left: 1px solid {p['border_soft']}; background: transparent; border-top-right-radius: 6px;
}}
QSpinBox::down-button, QDoubleSpinBox::down-button {{
    subcontrol-origin: border; subcontrol-position: bottom right; width: 18px;
    border: none; border-left: 1px solid {p['border_soft']}; background: transparent; border-bottom-right-radius: 6px;
}}
QSpinBox::up-arrow, QDoubleSpinBox::up-arrow {{ image: url("{ic['up']}"); width: 9px; height: 9px; }}
QSpinBox::down-arrow, QDoubleSpinBox::down-arrow {{ image: url("{ic['down']}"); width: 9px; height: 9px; }}
QSpinBox {{ padding-right: 20px; }} QDoubleSpinBox {{ padding-right: 20px; }}

QCheckBox, QRadioButton {{ background: transparent; color: {p['fg']}; spacing: 6px; }}
QCheckBox::indicator, QTreeView::indicator, QListView::indicator, QTableView::indicator {{
    width: 13px; height: 13px; border-radius: 4px;
    border: 1px solid {p['border_strong']}; background-color: {p['surface']};
}}
QCheckBox::indicator:hover, QTreeView::indicator:hover {{ border-color: {p['focus']}; }}
QCheckBox::indicator:checked, QTreeView::indicator:checked, QListView::indicator:checked, QTableView::indicator:checked {{
    background-color: {p['accent']}; border-color: {p['accent_border']}; image: url("{ic['check']}");
}}
QCheckBox::indicator:indeterminate, QTreeView::indicator:indeterminate {{
    background-color: {p['accent']}; border-color: {p['accent_border']}; image: url("{ic['partial']}");
}}
QCheckBox::indicator:disabled {{ background-color: {p['disabled_bg']}; border-color: {p['disabled_border']}; }}

/* ---------- Views ---------- */
QTreeWidget, QTreeView, QListWidget, QListView, QTextBrowser, QTextEdit, QPlainTextEdit {{
    background-color: {p['surface']}; color: {p['fg']};
    border: 1px solid {p['border']}; border-radius: 8px;
    selection-background-color: {p['selection']}; selection-color: {p['selection_fg']};
    outline: none;
}}
QTextEdit:focus, QPlainTextEdit:focus {{ border-color: {p['focus']}; }}
QTreeView {{ alternate-background-color: {p['surface_alt']}; padding: 2px; }}
QTreeView::item {{ padding: 3px 2px; border: none; border-bottom: 1px solid {p['row_divider']}; }}
QTreeView::item:hover {{ background-color: {p['row_hover']}; }}
QTreeView::item:selected {{ background-color: {p['selection_row']}; color: {p['fg']}; }}
QTreeView::branch {{ background: transparent; border: none; image: none; }}
QHeaderView {{ background: transparent; border: none; }}
QHeaderView::section {{
    background-color: {p['strip']}; color: {p['fg_soft']};
    border: none; border-right: 1px solid {p['border_soft']}; border-bottom: 1px solid {p['border']};
    padding: 4px 6px; font-weight: normal;
}}
QHeaderView::section:first {{ border-top-left-radius: 7px; }}
QHeaderView::section:last {{ border-right: none; border-top-right-radius: 7px; }}

QMenu {{
    background-color: {p['surface']}; color: {p['fg']};
    border: 1px solid {p['border']}; border-radius: 8px; padding: 4px;
}}
QMenu::item {{ padding: 5px 18px 5px 12px; border-radius: 5px; background: transparent; }}
QMenu::item:selected {{ background-color: {p['selection']}; color: {p['selection_fg']}; }}
QMenu::separator {{ height: 1px; background: {p['border_soft']}; margin: 4px 6px; }}

/* ---------- Tabs ---------- */
QTabWidget::pane {{
    background-color: {p['surface']}; border: 1px solid {p['border']};
    border-radius: 8px; border-top-left-radius: 0px; top: -1px;
}}
QTabWidget::tab-bar {{ left: 2px; }}
QTabWidget, QTabWidget > QStackedWidget, QSplitter {{ background: transparent; }}
QTabWidget > QStackedWidget > QWidget {{ background-color: {p['surface']}; }}
QTabBar {{ background: transparent; }}
QTabBar::tab {{
    background-color: {p['tab']}; color: {p['tab_fg']};
    border: 1px solid {p['border']}; border-bottom: none;
    border-top-left-radius: 7px; border-top-right-radius: 7px;
    padding: 5px 13px; margin-right: 3px; margin-top: 2px;
}}
QTabBar::tab:hover:!selected {{ background-color: {p['tab_hover']}; color: {p['fg']}; }}
QTabBar::tab:selected {{
    background-color: {p['surface']}; color: {p['fg']}; font-weight: 600;
    border-top: 2px solid {p['accent']}; margin-top: 0px; padding-bottom: 6px;
}}

/* ---------- Group boxes (settings) ---------- */
QGroupBox {{
    background-color: {p['surface']}; color: {p['fg']}; font-weight: 600;
    border: 1px solid {p['border']}; border-radius: 8px; margin-top: 15px; padding: 12px 10px 8px;
}}
QGroupBox::title {{ subcontrol-origin: margin; left: 12px; padding: 0 6px; color: {p['fg_soft']}; background: transparent; }}
QScrollArea {{ background: transparent; border: none; }}
QScrollArea > QWidget > QWidget {{ background: transparent; }}

/* ---------- Progress ---------- */
QProgressBar {{
    background-color: {p['progress_track']}; border: 1px solid {p['border']};
    border-radius: 4px; max-height: 8px; min-height: 8px; text-align: center; color: transparent;
}}
QProgressBar::chunk {{
    border-radius: 3px;
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 {p['accent']}, stop:1 {p['progress']});
}}

/* ---------- Splitter ---------- */
QSplitter {{ background: transparent; }}
QSplitter::handle {{ background: transparent; }}
QSplitter::handle:vertical {{ height: 7px; }}
QSplitter::handle:horizontal {{ width: 7px; }}
QSplitter::handle:hover {{ background-color: {p['accent_soft']}; border-radius: 3px; }}

/* ---------- Scrollbars ---------- */
QScrollBar:vertical {{ background: {p['surface']}; width: 10px; margin: 0px; border: none; }}
QScrollBar:horizontal {{ background: {p['surface']}; height: 10px; margin: 0px; border: none; }}
QScrollBar::handle:vertical {{ background: {p['scroll_thumb']}; min-height: 24px; border-radius: 4px; margin: 2px 2px; }}
QScrollBar::handle:horizontal {{ background: {p['scroll_thumb']}; min-width: 24px; border-radius: 4px; margin: 2px 2px; }}
QScrollBar::handle:hover {{ background: {p['scroll_thumb_hover']}; }}
QScrollBar::add-line, QScrollBar::sub-line {{ width: 0px; height: 0px; border: none; background: none; }}
QScrollBar::add-page, QScrollBar::sub-page {{ background: none; }}
QAbstractScrollArea::corner {{ background: {p['surface']}; border: none; }}

/* ---------- Panel specific ---------- */
QFrame#operationCard {{
    background-color: {p['card']}; border: 1px solid {p['border']}; border-radius: 9px;
}}
QFrame#cardDivider {{ background-color: {p['border_soft']}; border: none; max-height: 1px; min-height: 1px; }}
QWidget#cardPage, QFrame#operationCard QStackedWidget {{ background-color: {p['card']}; }}
QLabel#cardKey {{ color: {p['muted']}; }}
QLabel#cardValue {{ color: {p['fg']}; font-weight: 600; }}
QLabel#cardCost {{ color: {g[2]}; font-weight: 700; }}
QLabel#cardStream {{ color: {p['link']}; font-weight: 600; }}
QLabel#cardMeta {{ color: {p['muted']}; }}
QLabel#cardError {{ color: {r[2]}; }}
QLabel#busyTitle {{ color: {p['link']}; font-weight: 700; }}

QLabel[pill="green"] {{ background-color: {g[0]}; border: 1px solid {g[1]}; color: {g[2]}; border-radius: 6px; padding: 1px 7px; font-weight: 700; }}
QLabel[pill="amber"] {{ background-color: {a[0]}; border: 1px solid {a[1]}; color: {a[2]}; border-radius: 6px; padding: 1px 7px; font-weight: 700; }}
QLabel[pill="red"] {{ background-color: {r[0]}; border: 1px solid {r[1]}; color: {r[2]}; border-radius: 6px; padding: 1px 7px; font-weight: 700; }}
QLabel[pill="blue"] {{ background-color: {b[0]}; border: 1px solid {b[1]}; color: {b[2]}; border-radius: 6px; padding: 1px 7px; font-weight: 700; }}
QLabel[pill="purple"] {{ background-color: {p['purple'][0]}; border: 1px solid {p['purple'][1]}; color: {p['purple'][2]}; border-radius: 6px; padding: 1px 7px; font-weight: 700; }}

QFrame#toolStrip {{
    background-color: {p['strip']}; border: none; border-bottom: 1px solid {p['border_soft']};
    border-top-right-radius: 8px;
}}
QLabel#stripHint {{ color: {p['fg_soft']}; }}
QWidget#paneBody {{ background-color: {p['surface_alt']}; border-bottom-left-radius: 8px; border-bottom-right-radius: 8px; }}
QFrame#inspector {{ background-color: {p['surface']}; border: 1px solid {p['border']}; border-radius: 8px; }}
QFrame#inspector QTextBrowser {{ border: none; border-radius: 0px; background: transparent; }}
QFrame#inspectorFooter {{
    background-color: {p['strip']}; border: none; border-top: 1px solid {p['border_soft']};
    border-bottom-left-radius: 8px; border-bottom-right-radius: 8px;
}}
QLabel#footerText {{ color: {p['muted']}; }}
QLabel#bottomStatus {{ color: {p['muted']}; }}
QFrame#chatBar {{
    background-color: {p['strip']}; border: none; border-top: 1px solid {p['border_soft']};
    border-bottom-left-radius: 8px; border-bottom-right-radius: 8px;
}}
QListWidget#deepFunctionList {{ padding: 2px; }}
QListWidget#deepFunctionList::item {{ border: none; background: transparent; }}
"""


# ---------------------------------------------------------------------------
# Pseudocode syntax themes (unchanged: Dark / Light / Midnight)
# ---------------------------------------------------------------------------
THEMES = {
    "Dark": {
        "bg": "#1e1e1e", "fg": "#abb2bf", "keyword": "#c678dd", "type": "#56b6c2",
        "func": "#61afef", "string": "#98c379", "number": "#d19a66", "comment": "#5c6370",
    },
    "Light": {
        "bg": "#ffffff", "fg": "#383a42", "keyword": "#a626a4", "type": "#c18401",
        "func": "#4078f2", "string": "#50a14f", "number": "#986801", "comment": "#a0a1a7",
    },
    "Midnight": {
        "bg": "#0f172a", "fg": "#e2e8f0", "keyword": "#818cf8", "type": "#38bdf8",
        "func": "#60a5fa", "string": "#34d399", "number": "#fbbf24", "comment": "#64748b",
    },
}


def theme_from_palette(palette):
    """Backward-compatible helper (no longer used by the panel)."""
    roles = QtGui.QPalette.ColorRole

    def color(role, fallback):
        value = palette.color(role)
        return value if value.isValid() else QtGui.QColor(fallback)
    return {
        "bg": color(roles.Base, "#202020").name(), "fg": color(roles.Text, "#d0d0d0").name(),
        "keyword": color(roles.Highlight, "#589df6").name(), "type": color(roles.Link, "#4aa3c7").name(),
        "func": color(roles.Link, "#4aa3c7").name(), "string": color(roles.Text, "#d0d0d0").name(),
        "number": color(roles.Highlight, "#589df6").name(),
        "comment": palette.color(QtGui.QPalette.ColorGroup.Disabled, roles.Text).name(),
        "border": color(roles.Mid, "#555555").name(), "selection": color(roles.Highlight, "#3874b8").name(),
        "selection_fg": color(roles.HighlightedText, "#ffffff").name(),
        "muted": palette.color(QtGui.QPalette.ColorGroup.Disabled, roles.Text).name(),
        "code": color(roles.AlternateBase, "#292929").name(), "assistant": color(roles.AlternateBase, "#292929").name(),
        "user": color(roles.Highlight, "#3874b8").name(),
    }


class HexRaysHighlighter(QtGui.QSyntaxHighlighter):
    def __init__(self, document, theme_name="Dark"):
        super().__init__(document)
        self.theme_name = theme_name if isinstance(theme_name, str) else "Dark"
        self.rules = []
        self.update_theme(self.theme_name)

    def update_theme(self, theme_name):
        from ..config import normalize_theme_name
        self.theme_name = normalize_theme_name(theme_name, tuple(THEMES), "Dark")
        t = THEMES[self.theme_name]
        self.rules = []

        def fmt(color, bold=False, italic=False):
            f = QtGui.QTextCharFormat()
            f.setForeground(QtGui.QColor(color))
            if bold:
                f.setFontWeight(QtGui.QFont.Weight.Bold)
            if italic:
                f.setFontItalic(True)
            return f
        self.rules.append((QtCore.QRegularExpression(r"//[^\n]*"), fmt(t["comment"], italic=True)))
        self.rules.append((QtCore.QRegularExpression(r"/\*.*?\*/"), fmt(t["comment"], italic=True)))
        self.rules.append((QtCore.QRegularExpression(r'"[^"\\]*(\\.[^"\\]*)*"'), fmt(t["string"])))
        self.rules.append((QtCore.QRegularExpression(r"\b(0x[0-9a-fA-F]+|\d+\.?\d*)\b"), fmt(t["number"])))
        keywords = ["if", "else", "return", "while", "for", "switch", "case", "break", "continue", "default", "goto", "struct", "union", "typedef", "enum", "sizeof", "const", "volatile", "static", "extern", "do"]
        self.rules.append((QtCore.QRegularExpression(r"\b(" + "|".join(keywords) + r")\b"), fmt(t["keyword"], bold=True)))
        types = ["int", "char", "bool", "void", "unsigned", "signed", "short", "long", "float", "double", "size_t", "__int8", "__int16", "__int32", "__int64", "__int128", "_BOOL1", "_BOOL2", "_BOOL4", "DWORD", "WORD", "BYTE", "QWORD", "LPSTR", "LPCSTR", "HANDLE", "NTSTATUS", "HMODULE"]
        self.rules.append((QtCore.QRegularExpression(r"\b(" + "|".join(types) + r")\b"), fmt(t["type"])))
        self.rules.append((QtCore.QRegularExpression(r"\b([A-Za-z_][A-Za-z0-9_]*)(?=\s*\()"), fmt(t["func"])))
        self.rehighlight()

    def update_palette(self, _palette=None):
        self.update_theme(self.theme_name)

    def highlightBlock(self, text):
        for pattern, fmt in self.rules:
            it = pattern.globalMatch(text)
            while it.hasNext():
                m = it.next()
                self.setFormat(m.capturedStart(), m.capturedLength(), fmt)
