# -*- coding: utf-8 -*-
"""
IDA Pro 9.4 Plugin registration, UI hooks, and entrypoint.
"""
import ida_funcs
import ida_idaapi
import ida_kernwin

from .config import ACTION_PREFIX, log_msg
from .controller import Controller
from .ida_utils import get_selected_variable_name

class _UIHooks(ida_kernwin.UI_Hooks):
    def __init__(self, ctl):
        super().__init__()
        self.ctl = ctl

    def finish_populating_widget_popup(self, widget, popup, ctx=None):
        wtype = ida_kernwin.get_widget_type(widget)
        if wtype in (ida_kernwin.BWN_DISASM, ida_kernwin.BWN_PSEUDOCODE):
            ida_kernwin.attach_action_to_popup(widget, popup, ACTION_PREFIX + "deep", "AI Assistant/")
            ida_kernwin.attach_action_to_popup(widget, popup, ACTION_PREFIX + "pseudo", "AI Assistant/")
        if wtype == ida_kernwin.BWN_PSEUDOCODE:
            ida_kernwin.attach_action_to_popup(widget, popup, ACTION_PREFIX + "struct", "AI Assistant/")

    def ready_to_run(self, *args, **kwargs):
        try:
            self.ctl.on_database_ready()
        except Exception as e:
            log_msg("DEBUG", "Init", f"Cache reload on ready_to_run failed: {e}", self.ctl.cfg)
        return 0

    def view_loc_changed(self, *args, **kwargs):
        self.ctl.check_func_switch()
        return 0


class _Handler(ida_kernwin.action_handler_t):
    def __init__(self, cb):
        super().__init__()
        self.cb = cb

    def activate(self, ctx):
        self.cb(ctx)
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class AIPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_KEEP
    comment = "Modular AI Assistant for IDA Pro 9.4 (Ollama & Cloud APIs)"
    help = "Edit -> AI Assistant"
    wanted_name = "Ollama AI Assistant"
    wanted_hotkey = "Ctrl-Alt-A"

    def init(self):
        self.ctl = Controller()
        log_msg("INFO", "Init", "Initializing modular AIPlugin...", self.ctl.cfg)
        self.hooks = _UIHooks(self.ctl)
        self.hooks.hook()
        self.actions = []

        actions_def = [
            ("deep", "AI: Глубокое сканирование", lambda ctx: self.ctl.run_section("deep")),
            ("pseudo", "AI: Анализ псевдокода", lambda ctx: self.ctl.run_section("pseudo")),
            ("struct", "Сгенерировать C++-структуру", lambda ctx: self.ctl.run_section("struct", get_selected_variable_name())),
            ("panel", "AI: Открыть панель", lambda ctx: (self.ctl.ensure_panel(), self.ctl.on_panel_ready())),
        ]

        for kind, label, cb in actions_def:
            name = ACTION_PREFIX + kind
            desc = ida_kernwin.action_desc_t(name, label, _Handler(cb), None, label, -1)
            if ida_kernwin.register_action(desc):
                ida_kernwin.attach_action_to_menu("Edit/AI Assistant/", name, ida_kernwin.SETMENU_APP)
                self.actions.append(name)

        log_msg("INFO", "Init", "AIPlugin loaded successfully.", self.ctl.cfg)
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        self.ctl.ensure_panel()
        self.ctl.on_panel_ready()

    def term(self):
        try:
            if self.ctl.displayed_func_ea is not None and self.ctl.panel:
                f = ida_funcs.get_func(self.ctl.displayed_func_ea)
                if f:
                    self.ctl.save_current_ui_state(f)
            self.hooks.unhook()
            if getattr(self.ctl, "idb_hooks", None):
                self.ctl.idb_hooks.unhook()
            for a in self.actions:
                ida_kernwin.detach_action_from_menu("Edit/AI Assistant/", a)
                ida_kernwin.unregister_action(a)
            log_msg("INFO", "Term", "AIPlugin terminated.", self.ctl.cfg)
        except Exception:
            pass


def PLUGIN_ENTRY():
    import sys

    package = sys.modules.get("ai_assistant")

    if package is None:
        raise RuntimeError("ai_assistant package is not loaded")

    plugin_class = getattr(package, "AIPlugin", None)

    if plugin_class is None:
        raise RuntimeError("AIPlugin class not found in ai_assistant package")

    return plugin_class()