# -*- coding: utf-8 -*-
"""
Application controller: coordinates UI events, background workers, netnode cache,
multi-level Deep Scan execution, and safe IDA database mutations.
"""
import copy
import concurrent.futures
import json
import re
import sys
import threading
import time
import traceback
import uuid

import ida_bytes
import ida_funcs
import ida_hexrays
import ida_idaapi
import ida_kernwin
import ida_name
import ida_idp
import ida_nalt
import ida_netnode
import ida_typeinf
from PySide6 import QtCore, QtWidgets

try:
    import ida_undo
except Exception:
    ida_undo = None

from .analysis import (
    KIND_LABEL,
    SCHEMA_DEEP_COMPACT,
    SCHEMA_DEEP_SINGLE,
    SCHEMA_DEEP_SURFACE,
    SCHEMA_PSEUDO,
    SCHEMA_SCAN,
    build_json_system_prompt,
    execute_json_request_with_retry,
    deep_node_uses_full_schema,
    deep_node_wants_reasoning,
    format_deep_node_prompt,
    get_deep_level_profile,
    log_request_metrics,
    make_proposal,
    parse_confidence,
)
from .api import APIError, chat_completion
from .ui.i18n import tr as ui_tr
from .config import (
    FORM_CAPTION,
    NETNODE,
    estimate_tokens,
    get_active_profile,
    get_language_instruction,
    load_cfg,
    log_msg,
    save_cfg,
)
from .ida_utils import (
    clip,
    clip_code,
    collect_call_graph,
    compact_pseudocode,
    compute_func_hash,
    extract_func_rich_context,
    fname,
    get_func_signature_and_args,
    get_pseudo_at,
    get_function_xrefs,
    hx_ok,
    ident,
    is_auto_generated_name,
    make_function_signature,
    fit_code,
)
from .compare import (
    compare_versions,
    format_comparison,
    history_placeholder,
    split_question_and_code,
    wants_comparison,
)
from .ui.panel import Panel
from .ui.settings import SettingsDialog


class Bridge(QtCore.QObject):
    chunk_signal = QtCore.Signal(tuple)
    progress_signal = QtCore.Signal(object)
    finished = QtCore.Signal(object)


class UserAbort(Exception):
    pass


class _FunctionRenameHooks(ida_idp.IDB_Hooks):
    """Refresh analyzed-function labels when the user renames a function in IDA."""
    def __init__(self, controller):
        super().__init__()
        self.controller = controller

    def renamed(self, ea, new_name, local_name, old_name):
        if local_name:
            return
        try:
            f = ida_funcs.get_func(ea)
            if f and f.start_ea == ea and self.controller.panel:
                panel = self.controller.panel
                QtCore.QTimer.singleShot(0, panel.refresh_function_list)
        except Exception:
            pass


_COMPARE_FOLLOWUP_RE = re.compile(
    r"(?i)сравн|предыдущ|стар\w+ верс|прошл\w+ верс|изменил|изменени|отлич|разниц|офсет|оффсет|смещени|offset|diff|compare|previous|changed|old version"
)


class AIForm(ida_kernwin.PluginForm):
    def __init__(self, ctl):
        super().__init__()
        self.ctl = ctl

    def OnCreate(self, form):
        mod = sys.modules[__name__]
        widget = None
        for conv in ("FormToPySideWidget", "FormToPyQtWidget"):
            fn = getattr(self, conv, None)
            if fn:
                try:
                    widget = fn(form, ctx=mod)
                    break
                except Exception:
                    try:
                        widget = fn(form)
                        break
                    except Exception:
                        continue
        if widget is None:
            raise RuntimeError("Не удалось получить Qt-виджет из PluginForm")
        self.ctl.panel = Panel(self.ctl)
        lay = QtWidgets.QVBoxLayout(widget)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(self.ctl.panel)
        # Re-read the cache (the IDB may have been opened after plugin init) and
        # load the function under the cursor without waiting for a cursor move.
        self.ctl.active_func_ea = None
        self.ctl.displayed_func_ea = None
        QtCore.QTimer.singleShot(0, self.ctl.on_panel_ready)
        log_msg("INFO", "UI", "AI Form successfully created.", self.ctl.cfg)

    def OnClose(self, form):
        try:
            if self.ctl.displayed_func_ea is not None:
                f = ida_funcs.get_func(self.ctl.displayed_func_ea)
                if f and self.ctl.panel:
                    self.ctl.save_current_ui_state(f)
        except Exception as e:
            log_msg("ERROR", "UI", f"Error in OnClose: {e}", self.ctl.cfg)
        self.ctl.panel = None
        self.ctl.form = None
        # Force a reload of the current function when the panel is reopened.
        self.ctl.active_func_ea = None
        self.ctl.displayed_func_ea = None


class Controller(QtCore.QObject):
    def __init__(self):
        super().__init__()
        self.cfg = load_cfg()
        self.bridge = Bridge()
        self.bridge.chunk_signal.connect(self.on_chunk_received)
        self.bridge.progress_signal.connect(self.on_progress_received)
        self.bridge.finished.connect(self.on_finished)

        self.form = None
        self.panel = None
        self.token = 0
        self.job = None
        self.cancel_event = None
        self.db = {"version": 24, "funcs": {}}
        # A new session distinguishes analyses made during this plugin run from persisted cache entries.
        self.analysis_session_id = uuid.uuid4().hex
        self.active_func_ea = None  # Function under IDA's current cursor.
        self.displayed_func_ea = None  # Function whose cached data is shown in the panel.
        self.idb_hooks = _FunctionRenameHooks(self)
        try:
            self.idb_hooks.hook()
        except Exception as e:
            log_msg("DEBUG", "UI", f"Could not hook IDB rename events: {e}", self.cfg)

        self.save_timer = QtCore.QTimer(self)
        self.save_timer.setSingleShot(True)
        self.save_timer.timeout.connect(self.save_db)
        self.load_db()

    def load_db(self):
        try:
            n = ida_netnode.netnode(NETNODE, 0, True)
            b = n.getblob(0, "A")
            if b:
                data = json.loads(bytes(b).decode("utf-8"))
                if isinstance(data, dict):
                    self.db = data
        except Exception as e:
            log_msg("DEBUG", "Cache", f"Could not load db from netnode: {e}", self.cfg)

    def on_panel_ready(self):
        if not self.db.get("funcs"):
            self.load_db()
        if self.panel:
            try:
                self.panel.refresh_function_list()
                self.check_func_switch()
            except RuntimeError:
                pass

    def on_database_ready(self):
        """Called when IDA finished opening the database (UI ready_to_run)."""
        self.load_db()
        self.on_panel_ready()

    def trigger_save(self):
        self.save_timer.start(1500)

    def save_db(self):
        try:
            n = ida_netnode.netnode(NETNODE, 0, True)
            n.setblob(json.dumps(self.db, ensure_ascii=False).encode("utf-8"), 0, "A")
        except Exception as e:
            log_msg("ERROR", "Cache", f"Cannot persist results: {e}", self.cfg)

    def get_idb_id(self):
        return ida_nalt.get_root_filename() or "default_idb"

    def get_func_key(self, f):
        mode, prof = get_active_profile(self.cfg)
        model_name = prof.get("model", "default")
        depth = max(0, min(3, int(self.cfg.get("deep_depth", 1))))
        return f"{self.get_idb_id()}_{f.start_ea:#x}_{mode}_{model_name}_d{depth}"

    def get_func_db(self, f):
        key = self.get_func_key(f)
        funcs = self.db.setdefault("funcs", {})
        ent = funcs.get(key)
        current_hash = compute_func_hash(f)
        if ent is None:
            ent = {
                "start_ea": f.start_ea,
                "hash": current_hash,
                "sections": {},
                "chat_history": [],
            }
            funcs[key] = ent
        elif ent.get("hash") != current_hash:
            ent["hash"] = current_hash
            ent["outdated"] = True
        return ent

    @staticmethod
    def _has_saved_analysis(ent):
        sections = ent.get("sections", {}) if isinstance(ent, dict) else {}
        for name in ("scan", "deep", "pseudo"):
            section = sections.get(name) or {}
            if section.get("details") or section.get("props") or section.get("code"):
                return True
        return False

    def _best_existing_func_db(self, f):
        """Load active-profile data and fill missing tabs from other saved profiles."""
        funcs = self.db.setdefault("funcs", {})
        active = funcs.get(self.get_func_key(f))
        candidates = [
            ent for ent in funcs.values()
            if int(ent.get("start_ea", -1)) == int(f.start_ea) and self._has_saved_analysis(ent)
        ]
        if active and self._has_saved_analysis(active):
            candidates = [active] + [ent for ent in candidates if ent is not active]
        else:
            candidates.sort(key=lambda ent: (
                float(ent.get("last_analyzed", 0) or 0),
                len(ent.get("sections", {})),
            ), reverse=True)
        if not candidates:
            return self.get_func_db(f)
        merged = copy.deepcopy(candidates[0])
        merged_sections = dict(merged.get("sections", {}) or {})
        for ent in candidates[1:]:
            for section, data in (ent.get("sections", {}) or {}).items():
                if section not in merged_sections:
                    merged_sections[section] = copy.deepcopy(data)
        merged["sections"] = merged_sections
        return merged

    def get_analyzed_functions(self):
        """Return only top-level functions that have saved user-requested analyses.

        DeepScan child nodes live inside a report's function_results and are not
        database roots, so they are deliberately excluded from this history.
        """
        by_ea = {}
        for ent in self.db.setdefault("funcs", {}).values():
            try:
                ea = int(ent.get("start_ea", 0))
            except (TypeError, ValueError):
                continue
            if not ea or not self._has_saved_analysis(ent):
                continue
            previous = by_ea.get(ea)
            if previous is None or (
                float(ent.get("last_analyzed", 0) or 0), len(ent.get("sections", {}))
            ) > (
                float(previous.get("last_analyzed", 0) or 0), len(previous.get("sections", {}))
            ):
                by_ea[ea] = ent
        records = []
        for ea, ent in by_ea.items():
            try:
                name = fname(ea)
            except Exception:
                name = f"sub_{ea:X}"
            records.append({
                "ea": ea,
                "name": name,
                "last_analyzed": float(ent.get("last_analyzed", 0) or 0),
                "is_current_session": ent.get("analysis_session_id") == self.analysis_session_id,
            })
        records.sort(key=lambda item: (item["last_analyzed"], item["ea"]), reverse=True)
        return records

    def select_analyzed_function(self, ea):
        """Load all saved tabs for a selected history entry without moving IDA's cursor."""
        if not self.panel:
            return
        f = ida_funcs.get_func(int(ea))
        if not f:
            return
        if self.displayed_func_ea is not None and self.displayed_func_ea != f.start_ea:
            previous = ida_funcs.get_func(self.displayed_func_ea)
            if previous:
                self.save_current_ui_state(previous)
        self.load_ui_state(f)
        self.panel.set_header_info(fname(f.start_ea), f.start_ea)

    def ensure_panel(self):
        if self.form is None or self.panel is None:
            try:
                self.form = AIForm(self)
                # Persist the dock and request the right dock area on first creation.
                dock_right = getattr(ida_kernwin.PluginForm, "WOPN_DP_RIGHT", 0)
                opts = ida_kernwin.PluginForm.WOPN_PERSIST | dock_right
                self.form.Show(FORM_CAPTION, options=opts)
            except Exception as e:
                log_msg("ERROR", "UI", f"Error creating panel: {e}\n{traceback.format_exc()}", self.cfg)
                ida_kernwin.warning(f"Не удалось открыть панель AI Assistant: {e}")
                self.form = None
                self.panel = None
        else:
            try:
                widget = ida_kernwin.find_widget(FORM_CAPTION)
                if widget:
                    ida_kernwin.activate_widget(widget, True)
            except Exception:
                pass

    def check_func_switch(self):
        if not self.panel:
            return
        ea = ida_kernwin.get_screen_ea()
        f = ida_funcs.get_func(ea)
        target_ea = f.start_ea if f else None

        if target_ea != self.active_func_ea:
            if self.displayed_func_ea is not None:
                prev_f = ida_funcs.get_func(self.displayed_func_ea)
                if prev_f:
                    self.save_current_ui_state(prev_f)
            self.active_func_ea = target_ea
            if f:
                self.load_ui_state(f)
            else:
                self.displayed_func_ea = None
                self.panel.clear_ui()

    def save_current_ui_state(self, f):
        if not self.panel or not f:
            return
        try:
            ent = self.get_func_db(f)
            sections = ent.setdefault("sections", {})
            scan_props, scan_details = self.panel.get_workspace_state("scan")
            sections["scan"] = {"props": scan_props, "details": scan_details}
            # Capture checkbox/value edits from whichever function is currently
            # displayed, while keeping the aggregate DeepScan summary intact.
            self.panel.get_workspace_state("deep")
            sections["deep"] = {
                "props": list(getattr(self.panel, "deep_summary_props", []) or []),
                "details": str(getattr(self.panel, "deep_summary_details", "") or ""),
                "function_results": list(getattr(self.panel, "function_results", []) or []),
            }
            code, pseudo_props, pseudo_details = self.panel.get_pseudocode_state()
            sections["pseudo"] = {"code": code, "props": pseudo_props, "details": pseudo_details}
            self.trigger_save()
        except Exception as e:
            log_msg("ERROR", "UI", f"Failed to save current UI state: {e}", self.cfg)

    def load_ui_state(self, f):
        if not self.panel:
            return
        self.displayed_func_ea = f.start_ea
        ent = self._best_existing_func_db(f)
        is_outdated = ent.get("outdated", False)
        sections = ent.get("sections", {})

        scan_data = sections.get("scan", {})
        self.panel.set_workspace_state("scan", scan_data.get("props", []), scan_data.get("details", ""))
        deep_data = sections.get("deep", {})
        self.panel.set_workspace_state(
            "deep", deep_data.get("props", []), deep_data.get("details", ""),
            deep_data.get("function_results", []),
        )
        pseudo_data = sections.get("pseudo", {})
        self.panel.set_pseudocode_state(
            pseudo_data.get("code", ""), pseudo_data.get("props", []), pseudo_data.get("details", "")
        )
        self.panel.set_chat_history(ent.get("chat_history", []))

        status_suffix = " [УСТАРЕЛО (код изменен)]" if is_outdated else ""
        self.panel.set_header_info(fname(f.start_ea), f.start_ea, status_suffix)

    def cur_func(self):
        ea = ida_kernwin.get_screen_ea()
        f = ida_funcs.get_func(ea)
        if not f:
            ida_kernwin.warning("AI Assistant: курсор не находится внутри функции.")
            raise UserAbort()
        return f

    def run_section(self, section_name, extra_arg=None, target_ea=None, force=False):
        if target_ea is not None:
            try:
                f = ida_funcs.get_func(int(target_ea))
            except (TypeError, ValueError):
                f = None
            if not f:
                if self.panel:
                    self.panel.show_error(section_name, "Не удалось определить функцию для анализа.")
                return
        else:
            try:
                f = self.cur_func()
            except UserAbort:
                return

        if not self.panel:
            self.ensure_panel()
            if not self.panel:
                return

        ent = self.get_func_db(f)
        if not force and not extra_arg and section_name in ("scan", "deep", "pseudo") and not ent.get("outdated", False):
            cached = ent.get("sections", {}).get(section_name)
            if cached and (cached.get("details") or cached.get("props") or cached.get("code")):
                log_msg("INFO", section_name, f"Restoring cached result for {fname(f.start_ea)}", self.cfg)
                self.panel.show_section_result(section_name, cached)
                return

        try:
            job = self.build_job(section_name, f, extra_arg)
        except Exception as e:
            self.panel.show_error(section_name, str(e))
            return

        if not job:
            return

        self.token += 1
        self.job = job
        self.cancel_event = threading.Event()
        self.panel.set_busy(True, job["title"])

        if section_name in ("chat", "struct"):
            self.panel.append_chat_streaming_placeholder()

        cfg_snapshot = copy.deepcopy(self.cfg)
        mode_snapshot, profile_snapshot = get_active_profile(cfg_snapshot)
        log_msg(
            "INFO", section_name,
            f"Starting analysis -> provider={mode_snapshot}, model={profile_snapshot.get('model', '')}",
            cfg_snapshot,
        )
        threading.Thread(
            target=self._worker,
            args=(self.token, job, cfg_snapshot, f.start_ea, section_name),
            daemon=True,
        ).start()

    def cancel(self):
        if self.cancel_event:
            self.cancel_event.set()
        self.token += 1
        if self.panel:
            self.panel.set_busy(False, "Запрос отменён")
            self.panel.remove_streaming_placeholder()

    def _worker(self, token, job, cfg, target_ea, section_name):
        t0 = time.time()
        results, err = [], None
        try:
            results = job["runner"](token, cfg)
        except (UserAbort, InterruptedError):
            err = "Запрос отменён пользователем"
        except Exception as e:
            err = str(e)
            log_msg("ERROR", section_name, f"Worker error: {e}\n{traceback.format_exc()}", cfg)

        dt = time.time() - t0
        self.bridge.finished.emit((token, results, err, dt, target_ea, section_name))

    def on_chunk_received(self, payload):
        token, chunk = payload
        if token != self.token or self.panel is None:
            return
        self.panel.update_streaming(chunk)

    def on_progress_received(self, payload):
        if not payload or payload.get("token") != self.token or self.panel is None:
            return
        self.panel.update_operation_progress(payload)

    def on_finished(self, payload):
        token, results, err, dt, target_ea, section_name = payload
        if token != self.token or self.panel is None:
            return

        job = self.job
        try:
            self.panel.set_busy(False, f"Готово ({dt:.1f}с)" if not err else "Ошибка")
        except RuntimeError:
            # Qt widget may have been destroyed while a background request was running.
            self.panel = None
            return

        try:
            f = ida_funcs.get_func(target_ea)
            if not f:
                return

            if err:
                self.panel.show_error(section_name, err)
                return

            res_data = job["handler"](results)
            ent = self.get_func_db(f)
            ent["outdated"] = False
            ent["hash"] = compute_func_hash(f)
            ent["last_analyzed"] = time.time()
            if section_name in ("scan", "deep", "pseudo"):
                ent["analysis_session_id"] = self.analysis_session_id

            if section_name not in ("chat", "struct"):
                sections = ent.setdefault("sections", {})
                sections[section_name] = res_data
                self.trigger_save()

            self.panel.refresh_function_list()
            current_f = ida_funcs.get_func(ida_kernwin.get_screen_ea())
            if ((current_f and current_f.start_ea == target_ea)
                    or self.displayed_func_ea == target_ea):
                self.displayed_func_ea = target_ea
                self.panel.show_section_result(section_name, res_data)
        except Exception as ex:
            log_msg("ERROR", section_name, f"on_finished error: {ex}\n{traceback.format_exc()}", self.cfg)
            self.panel.show_error(section_name, str(ex))

    # ------------------------------------------------------------------
    # Job Builders
    # ------------------------------------------------------------------
    def build_job(self, section, f, extra_arg):
        if section == "scan":
            return self.job_scan(f)
        if section == "deep":
            return self.job_deep(f)
        if section == "pseudo":
            return self.job_pseudo(f)
        if section == "chat":
            return self.job_chat(f, extra_arg)
        if section == "struct":
            return self.job_struct(f, extra_arg)
        return None

    def job_scan(self, f):
        cfg = self.cfg
        ctx = extract_func_rich_context(f.start_ea, depth_level=1, code_char_limit=cfg["max_code_chars"])
        cf, _ = get_pseudo_at(f.start_ea)
        _, lv = get_func_signature_and_args(f.start_ea, cf)
        cur = fname(f.start_ea)

        extra_hints = []
        if ctx["prototype"]:
            extra_hints.append(f"Prototype: {ctx['prototype']}")
        if ctx["strings"]:
            extra_hints.append(f"Strings: {ctx['strings']}")
        if ctx["callees"]:
            extra_hints.append(f"Callees: {', '.join(ctx['callees'])}")
        hints_block = "\n".join(extra_hints)

        user = (
            f"Function: {cur} @ {f.start_ea:#x} (Source: {ctx['source_type']})\n"
            f"{hints_block}\n"
            f"Locals count: {len(lv)}.\n"
            f"Code:\n{ctx['code']}"
        )
        task = (
            "Infer a meaningful function name, concise purpose, and better names only for variables "
            "whose roles are directly supported by data flow and use sites. Do not guess."
        )
        messages = [
            {"role": "system", "content": build_json_system_prompt(cfg) + "\nTask: " + task + "\nSchema:\n" + SCHEMA_SCAN},
            {"role": "user", "content": user},
        ]

        def runner(token, run_cfg):
            data, meta = execute_json_request_with_retry(
                run_cfg, messages, stage="scan", cancel_event=self.cancel_event,
                max_output_override=1000, disable_reasoning=True,
            )
            return [(data, meta)]

        def handler(res):
            d, meta = res[0]
            props = []
            nn = ident(d.get("function_name"), "")
            conf_val, _ = parse_confidence(d.get("confidence", "средняя"))
            if nn and nn != cur and is_auto_generated_name(cur):
                props.append(make_proposal("rename_func", cur, nn, cur, conf_val, checked=conf_val >= 0.6, ea=f.start_ea, func=f.start_ea))

            names = {v["name"] for v in lv}
            for v in d.get("variables", []) or []:
                old, new = v.get("old"), ident(v.get("new"), "")
                if old in names and new and new != old:
                    vc, _ = parse_confidence(v.get("confidence", "средняя"))
                    props.append(make_proposal("rename_lvar", old, new, old, vc, checked=vc >= 0.6, ea=f.start_ea, func=f.start_ea))

            desc = str(d.get("description", ""))
            if desc:
                props.append(make_proposal("func_comment", cur, desc, "", conf_val, checked=False, ea=f.start_ea, func=f.start_ea))

            return {"title": "Сканирование", "section": "scan", "desc": desc, "props": props, "details": desc, "metrics": meta}

        return {"title": "Сканирование", "section": "scan", "runner": runner, "handler": handler}

    def job_deep(self, f):
        cfg = self.cfg
        depth = max(0, min(3, int(cfg.get("deep_depth", 1))))
        max_f = int(cfg.get("max_deep_funcs", 15))
        level_prof = get_deep_level_profile(cfg, depth)

        graph_nodes = collect_call_graph(f, level_prof["graph_depth"], max_f)
        # Bottom-up order (deepest callees first -> root function last) so parent functions benefit from child names
        if level_prof["bottom_up"]:
            ordered_nodes = sorted(graph_nodes, key=lambda n: n["depth"], reverse=True)
        else:
            ordered_nodes = list(graph_nodes)

        def runner(token, run_cfg):
            deep_started = time.monotonic()
            results = []
            analysis_order = []
            resolved_names = {}
            agg_metrics = {
                "provider": get_active_profile(run_cfg)[0],
                "model": get_active_profile(run_cfg)[1].get("model", ""),
                "stage": f"deep ({level_prof['label']}, depth={depth})",
                "prompt_tokens": 0,
                "cached_prompt_tokens": 0,
                "completion_tokens": 0,
                "total_tokens": 0,
                "tokens_estimated": False,
                "cost_usd": 0.0,
                "duration": 0.0,
                "retries": 0,
            }

            if depth == 0:
                task_text = (
                    "Task: Perform a concise surface analysis of this single function. "
                    "Explain only its primary purpose, propose a PascalCase name only when justified, "
                    "and cite the strongest evidence. Do not enumerate implementation details. "
                    "Return only the compact fields shown in the schema.\nSchema:\n"
                    + SCHEMA_DEEP_SURFACE
                )
            else:
                task_text = (
                    "Task: Analyze the supplied function context (code, types, xrefs, strings, globals). "
                    "Propose a specific PascalCase name if it has an auto-generated name (sub_...), explain its purpose, "
                    "and ground your reasoning in concrete evidence.\nSchema:\n"
                )
            # The system prompt is identical for every node of the same schema,
            # so providers with prefix caching bill it at the cached rate.
            base_sys = build_json_system_prompt(run_cfg) + "\n" + task_text
            sys_prompt_full = base_sys if depth == 0 else base_sys + SCHEMA_DEEP_SINGLE
            sys_prompt_compact = base_sys if depth == 0 else base_sys + SCHEMA_DEEP_COMPACT

            resolved_purposes = {}

            def analyze_node(node, known_names, known_purposes):
                ea = node["ea"]
                name = node["name"]
                if not node["is_auto"]:
                    library = bool(node.get("is_library"))
                    return ({
                        "ea": ea, "depth": node["depth"], "current_name": name,
                        "edge_kind": node.get("edge_kind", "root"),
                        "incoming_context": node.get("incoming_context"),
                        "callback_refs": node.get("callback_refs", []),
                        "suggested_name": name, "status": "уже подходит",
                        "purpose": ("Библиотечная функция или переходник (thunk); не анализируется."
                                    if library else "Функция уже имеет осмысленное имя."),
                        "reasoning": "Переименование не требуется.", "confidence": "высокая",
                    }, None)
                if not node["has_code"] and not node["strings"]:
                    return ({
                        "ea": ea, "depth": node["depth"], "current_name": name,
                        "edge_kind": node.get("edge_kind", "root"),
                        "incoming_context": node.get("incoming_context"),
                        "callback_refs": node.get("callback_refs", []),
                        "suggested_name": name, "status": "недостаточно данных",
                        "purpose": "Отсутствует код и строковые ссылки.",
                        "reasoning": "Недостаточно данных для анализа.", "confidence": "низкая",
                    }, None)

                try:
                    full_schema = deep_node_uses_full_schema(node, depth)
                    want_reasoning = deep_node_wants_reasoning(node, depth)
                    user_prompt = format_deep_node_prompt(
                        node, level_prof, known_names, known_purposes, full_schema=full_schema,
                    )
                    # Larger per-node evidence sets receive a modestly larger
                    # answer budget, bounded by the selected depth's ceiling.
                    input_complexity = estimate_tokens(user_prompt)
                    complexity_bonus = min(
                        max(0, level_prof["max_tokens_cap"] - level_prof["max_tokens"]),
                        max(0, int((input_complexity - 3000) * 0.20)),
                    )
                    node_output_budget = level_prof["max_tokens"] + complexity_bonus
                    if not want_reasoning:
                        # Without hidden reasoning a compact JSON answer needs far
                        # fewer tokens; keep a safe floor for retries.
                        node_output_budget = min(node_output_budget, max(1500, level_prof["max_tokens"] // 3))
                    msgs = [
                        {"role": "system", "content": sys_prompt_full if full_schema else sys_prompt_compact},
                        {"role": "user", "content": user_prompt},
                    ]
                    res_json, meta = execute_json_request_with_retry(
                        run_cfg, msgs, stage=f"deep_{ea:#x}",
                        cancel_event=self.cancel_event,
                        max_output_override=node_output_budget, max_retries=1,
                        disable_reasoning=not want_reasoning,
                        enable_reasoning=want_reasoning,
                        max_output_cap=level_prof["max_tokens_cap"],
                    )
                    if not isinstance(res_json, dict):
                        raise ValueError(f"Ожидался JSON-объект, получен {type(res_json).__name__}")
                    sugg = ident(res_json.get("suggested_name"), name)
                    return ({
                        "ea": ea, "depth": node["depth"], "current_name": name,
                        "edge_kind": node.get("edge_kind", "root"),
                        "incoming_context": node.get("incoming_context"),
                        "callback_refs": node.get("callback_refs", []),
                        "suggested_name": sugg, "status": "предложено",
                        "purpose": res_json.get("purpose", "Назначение определено."),
                        "reasoning": res_json.get("reasoning", "Анализ контекста."),
                        "facts": res_json.get("facts", []) or [],
                        "hypotheses": res_json.get("hypotheses", []) or [],
                        "field_layout": res_json.get("field_layout", []) or [],
                        "control_flow": res_json.get("control_flow", []) or [],
                        "loops_and_containers": res_json.get("loops_and_containers", []) or [],
                        "helper_calls": res_json.get("helper_calls", []) or [],
                        "confidence": res_json.get("confidence", "средняя"),
                    }, meta)
                except Exception as e:
                    log_msg("ERROR", "DeepScan", f"Error analyzing {name} @ {ea:#x}: {e}", run_cfg)
                    return ({
                        "ea": ea, "depth": node["depth"], "current_name": name,
                        "edge_kind": node.get("edge_kind", "root"),
                        "incoming_context": node.get("incoming_context"),
                        "callback_refs": node.get("callback_refs", []),
                        "suggested_name": name, "status": "ошибка анализа",
                        "purpose": f"Ошибка: {e}", "reasoning": str(e), "confidence": "низкая",
                    }, None)

            # Calls at the same graph depth are independent. Run them concurrently
            # (bounded to 3 requests); deeper levels still finish before their parents
            # so inferred child names remain available to parent prompts.
            # Every mode with child nodes is processed level by level (deepest
            # first) so that parents, including the root in Basic mode, receive
            # the names and purposes inferred for their callees.
            if not level_prof["bottom_up"]:
                batches = [ordered_nodes]
            else:
                by_depth = {}
                for node in ordered_nodes:
                    by_depth.setdefault(node["depth"], []).append(node)
                batches = [by_depth[d] for d in sorted(by_depth, reverse=True)]

            for batch in batches:
                if self.cancel_event and self.cancel_event.is_set():
                    raise UserAbort()
                known_names = dict(resolved_names)
                known_purposes = dict(resolved_purposes)
                workers = min(3, max(1, len(batch)))
                with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
                    futures = [pool.submit(analyze_node, node, known_names, known_purposes) for node in batch]
                    for future in concurrent.futures.as_completed(futures):
                        if self.cancel_event and self.cancel_event.is_set():
                            raise UserAbort()
                        item, meta = future.result()
                        results.append(item)
                        analysis_order.append(item.get("ea"))
                        if meta:
                            for key in ("prompt_tokens", "cached_prompt_tokens", "completion_tokens", "total_tokens", "cost_usd", "duration", "retries"):
                                agg_metrics[key] += meta.get(key, 0) or 0
                            agg_metrics["tokens_estimated"] = agg_metrics["tokens_estimated"] or bool(meta.get("tokens_estimated"))
                        if item.get("status") == "предложено":
                            old_name, new_name = item.get("current_name"), item.get("suggested_name")
                            if new_name and new_name != old_name:
                                resolved_names[old_name] = new_name
                                resolved_purposes[old_name] = str(item.get("purpose") or "")
                        done_count = len(results)
                        self.bridge.progress_signal.emit({
                            "token": token, "done": done_count, "total": len(ordered_nodes),
                            "elapsed": time.monotonic() - deep_started, "metrics": dict(agg_metrics),
                        })

            # Restore top-down display order (root function first)
            results.sort(key=lambda r: (r["depth"], r["ea"] != f.start_ea))
            # Parallel requests overlap; report real wall-clock scan time rather
            # than the sum of individual request durations.
            agg_metrics["duration"] = time.monotonic() - deep_started
            last_analyzed_ea = analysis_order[-1] if analysis_order else None
            return [results, agg_metrics, last_analyzed_ea]

        def handler(res):
            items, agg_metrics, last_analyzed_ea = res
            props = []
            analyzed_count = 0
            meaningful_proposals = 0
            already_matching = 0
            insufficient_data = 0
            errors_count = 0

            md = [
                f"### Глубокий анализ: {level_prof['label']}",
                f"- Обнаружено узлов в графе: **{len(graph_nodes)}** (лимит: {max_f})",
                f"- Режим обхода: **{level_prof['label']}**, глубина прямых вызовов: **{level_prof['graph_depth']}**",
            ]

            function_results = []
            for item in items:
                item_md = []
                item_props = []
                status = item.get("status", "предложено")
                if status == "уже подходит":
                    already_matching += 1
                elif status == "недостаточно данных":
                    insufficient_data += 1
                elif status == "ошибка анализа":
                    errors_count += 1
                else:
                    analyzed_count += 1
                    if item.get("suggested_name") != item.get("current_name"):
                        meaningful_proposals += 1

                curr_name = item["current_name"]
                sugg_name = item["suggested_name"]
                ea = item["ea"]
                purpose = item["purpose"]
                reasoning = item["reasoning"]
                conf_val, conf_cat = parse_confidence(item.get("confidence", "средняя"))

                item_md.append(
                    f"### {curr_name} (`@{ea:#x}`)\n"
                    f"- **Глубина:** {item['depth']} · **Статус:** *{status}*\n"
                    f"- **Предложение:** `{sugg_name if sugg_name != curr_name else '(без изменений)'}` · Уверенность: {conf_cat}\n"
                    f"- **Назначение:** {purpose}\n"
                    f"- **Обоснование:** {reasoning}"
                )
                md.append(
                    f"- **[Depth {item['depth']}] {curr_name}** (`@{ea:#x}`) | Статус: *{status}*\n"
                    f"  - **Предложение:** `{sugg_name if sugg_name != curr_name else '(без изменений)'}` (Уверенность: {conf_cat})\n"
                    f"  - **Назначение:** {purpose}\n"
                    f"  - **Обоснование:** {reasoning}"
                )
                if item.get("incoming_context"):
                    edge = item["incoming_context"]
                    edge_text = f"- **Связь:** {edge.get('kind')} от `{edge.get('from')}`; контекст: `{edge.get('call_site') or 'не восстановлен'}`"
                    md.append("  " + edge_text)
                    item_md.append(edge_text)
                elif item.get("edge_kind") == "function_pointer_candidate":
                    md.append("  - **Связь:** кандидат на callback/function pointer")
                    item_md.append("- **Связь:** кандидат на callback/function pointer")
                if item.get("callback_refs"):
                    refs_text = "- **Ссылки на функции:** " + "; ".join(item["callback_refs"][:8])
                    md.append("  " + refs_text)
                    item_md.append(refs_text)

                for key, label in (("facts", "Подтверждённые факты"), ("hypotheses", "Гипотезы"),
                                   ("field_layout", "Поля/смещения"), ("control_flow", "Условия и ветвления"),
                                   ("loops_and_containers", "Циклы и контейнеры"), ("helper_calls", "Вспомогательные вызовы")):
                    values = item.get(key) or []
                    if values:
                        value_text = f"- **{label}:** {json.dumps(values, ensure_ascii=False)}"
                        md.append("  " + value_text)
                        item_md.append(value_text)

                if ea and sugg_name and sugg_name != curr_name and is_auto_generated_name(curr_name):
                    proposal = make_proposal("rename_func", curr_name, sugg_name, curr_name, conf_val, checked=conf_val >= 0.6, ea=ea, func=ea)
                    props.append(proposal)
                    item_props.append(proposal)
                if ea and purpose and status == "предложено":
                    proposal = make_proposal("func_comment", curr_name, purpose, "", conf_val, checked=False, ea=ea, func=ea)
                    props.append(proposal)
                    item_props.append(proposal)

                function_results.append({
                    "ea": ea, "name": curr_name, "current_name": curr_name,
                    "depth": item.get("depth", 0), "status": status,
                    "props": item_props, "details": "\n\n".join(item_md),
                })

            # Keep the actually last completed function at the end of the list;
            # the panel pins it directly below the current IDA function.
            if last_analyzed_ea is not None:
                function_results.sort(key=lambda record: record.get("ea") == last_analyzed_ea)

            # Translate only UI-authored headings; model-generated purpose/reasoning stays in its configured response language.
            ui_lang = cfg.get("interface_language", "Russian")
            ui_labels = ("Глубокий анализ", "Обнаружено узлов в графе", "Режим обхода", "Глубина", "Статус",
                         "Предложение", "Уверенность", "Назначение", "Обоснование", "Связь",
                         "кандидат на callback/function pointer", "Ссылки на функции", "Подтверждённые факты",
                         "Гипотезы", "Поля/смещения", "Условия и ветвления", "Циклы и контейнеры",
                         "Вспомогательные вызовы", "Итоги", "проанализировано", "предложено имён",
                         "уже именованы", "недостаточно данных", "ошибок", "уже подходит", "предложено", "ошибка анализа", "высокая", "средняя", "низкая")
            if ui_lang != "Russian":
                md = [line for line in md]
                for label in ui_labels:
                    translated = ui_tr(label, ui_lang)
                    md = [line.replace(label, translated) for line in md]
                for record in function_results:
                    details = record.get("details", "")
                    for label in ui_labels:
                        details = details.replace(label, ui_tr(label, ui_lang))
                    record["details"] = details
            md.append(
                f"\n---\n**{ui_tr('Итоги', ui_lang)}:** {ui_tr('проанализировано', ui_lang)} {analyzed_count}, {ui_tr('предложено имён', ui_lang)} {meaningful_proposals}, "
                f"{ui_tr('уже именованы', ui_lang)} {already_matching}, {ui_tr('недостаточно данных', ui_lang)} {insufficient_data}, {ui_tr('ошибок', ui_lang)} {errors_count}."
            )
            return {
                "title": ui_tr("Глубокое сканирование", ui_lang),
                "section": "deep",
                "desc": ui_tr(level_prof["label"], ui_lang),
                "props": props,
                "details": "\n".join(md),
                "function_results": function_results,
                "metrics": agg_metrics,
            }

        return {"title": f"{ui_tr('Глубокое сканирование', cfg.get('interface_language', 'Russian'))} ({ui_tr(level_prof['label'], cfg.get('interface_language', 'Russian'))})", "section": "deep", "runner": runner, "handler": handler}

    def job_pseudo(self, f):
        cfg = self.cfg
        cf, code = get_pseudo_at(f.start_ea)
        if not cf or not code:
            raise RuntimeError("Декомпилятор Hex-Rays недоступен или функция не декомпилируется.")
        _, lv = get_func_signature_and_args(f.start_ea, cf)
        cur = fname(f.start_ea)

        # The editor still shows the original pseudocode; the model receives a
        # compacted copy (no location comments/blank lines) clipped head+tail.
        user = f"Function: {cur} @ {f.start_ea:#x}\nPseudocode:\n{clip_code(compact_pseudocode(code), cfg['max_code_chars'])}"
        messages = [
            {"role": "system", "content": (
                build_json_system_prompt(cfg)
                + "\nTask: Explain the actual control flow and data transformations. "
                  "Return concise Russian output: 3-6 short points, maximum 180 words. "
                  "Suggest local-variable names only when their role is clear from usage. "
                  "Do not reproduce the pseudocode or add unsupported assumptions.\nSchema:\n"
                + SCHEMA_PSEUDO
            )},
            {"role": "user", "content": user},
        ]

        def runner(token, run_cfg):
            data, meta = execute_json_request_with_retry(
                run_cfg, messages, stage="pseudo", cancel_event=self.cancel_event,
                max_output_override=4096, disable_reasoning=True,
            )
            return [(data, meta)]

        def handler(res):
            d, meta = res[0]
            props = []
            names = {v["name"] for v in lv}
            for s in d.get("suggestions", []) or []:
                old, new = s.get("target"), ident(s.get("new"), "")
                if old in names and new and new != old:
                    sc, _ = parse_confidence(s.get("confidence", "средняя"))
                    props.append(make_proposal("rename_lvar", old, new, old, sc, checked=sc >= 0.6, ea=f.start_ea, func=f.start_ea))
            return {
                "title": "Псевдокод",
                "section": "pseudo",
                "desc": "Анализ псевдокода",
                "props": props,
                "details": str(d.get("explanation", "")),
                "code": code,
                "metrics": meta,
            }

        return {"title": "Анализ псевдокода", "section": "pseudo", "runner": runner, "handler": handler}

    def job_chat(self, f, user_query):
        cfg = self.cfg

        # Pasted code (e.g. the previous build of this function) is separated from
        # the question: names inside pasted code must not retarget the chat.
        question_text, pasted_blocks = split_question_and_code(user_query)

        # If the question explicitly names another IDA function, resolve it from the database.
        # Otherwise keep the currently selected function as the chat target.
        named_funcs = []
        for candidate in re.findall(r"[A-Za-z_$?@][A-Za-z0-9_$?@:.]*", question_text or ""):
            try:
                ea = ida_name.get_name_ea(ida_idaapi.BADADDR, candidate)
                resolved = ida_funcs.get_func(ea) if ea != ida_idaapi.BADADDR else None
                if resolved and all(r.start_ea != resolved.start_ea for r in named_funcs):
                    named_funcs.append(resolved)
            except Exception:
                continue

        compare_mode = wants_comparison(question_text, pasted_blocks)
        target_f = f
        old_code = old_label = ""
        if compare_mode:
            if pasted_blocks:
                old_code = compact_pseudocode(max(pasted_blocks, key=len))
                old_label = "pasted by the user"
                if named_funcs:
                    target_f = named_funcs[-1]
            elif len(named_funcs) >= 2:
                old_f, target_f = named_funcs[0], named_funcs[-1]
                old_code = compact_pseudocode(get_pseudo_at(old_f.start_ea)[1] or "")
                old_label = f"{fname(old_f.start_ea)} @ {old_f.start_ea:#x} from this database"
            elif len(named_funcs) == 1 and named_funcs[0].start_ea != f.start_ea:
                old_f = named_funcs[0]
                old_code = compact_pseudocode(get_pseudo_at(old_f.start_ea)[1] or "")
                old_label = f"{fname(old_f.start_ea)} @ {old_f.start_ea:#x} from this database"
            else:
                # Follow-up question about the previously pasted version.
                stored = self.get_func_db(f).get("compare_old_code") or ""
                if stored and _COMPARE_FOLLOWUP_RE.search(question_text or ""):
                    old_code, old_label = stored, "pasted earlier in this chat"
            if not old_code:
                compare_mode = False
        elif named_funcs:
            target_f = named_funcs[-1]

        ctx = extract_func_rich_context(target_f.start_ea, depth_level=1, code_char_limit=cfg["max_code_chars"])
        cur = fname(target_f.start_ea)
        xrefs = get_function_xrefs(target_f)
        # The full xref list is sent only when the question is about references;
        # otherwise exact counts plus the first entries are enough.
        wants_xrefs = bool(re.search(
            r"(?i)xref|ссылк|вызыва|вызов|caller|callers|кто\s+вызы|откуда|references?|引用|调用",
            user_query or "",
        ))
        xref_cap = 400 if wants_xrefs else 25
        xref_lines = [
            f"Total incoming xrefs to function entry: {xrefs['count']} "
            f"(code: {xrefs['code_count']}, data: {xrefs['data_count']})."
        ]
        for xr in xrefs["items"][:xref_cap]:
            source_name = xr["from_name"] or "unknown"
            kind = "code" if xr["is_code"] else "data"
            xref_lines.append(f"- {xr['from']:#x} | {source_name} | {kind} | type={xr['type']}")
        if len(xrefs["items"]) > xref_cap:
            xref_lines.append(f"- ... ещё {len(xrefs['items']) - xref_cap} (список сокращён; полный список выдаётся на вопрос про xref)")
        xref_context = "\n".join(xref_lines)

        # Byte signatures cannot be reconstructed from pseudocode: the model would
        # burn its whole output budget trying. The plugin builds the signature
        # from real instruction bytes and checks uniqueness in the database.
        wants_signature = bool(re.search(
            r"(?i)пат+ерн|сигнатур|patt?ern|signature|\bsig\b|sigmaker|\baob\b|байт|\bbytes?\b|опкод|opcode|特征码|签名",
            user_query or "",
        ))
        signature_block = ""
        if wants_signature:
            try:
                sig = make_function_signature(target_f)
            except Exception as e:
                sig = {}
                log_msg("WARNING", "chat", f"Не удалось построить сигнатуру: {e}", cfg)
            if sig.get("pattern"):
                if sig["unique"]:
                    status = f"unique in the database ({sig['length']} bytes, first {sig['insns']} instructions)"
                else:
                    status = (f"NOT unique within the first {sig['insns']} instructions "
                              f"({sig['matches']}+ matches); say so and suggest a call-site/xref signature")
                signature_block = (
                    "\n\nByte signature computed by the plugin from the IDA database "
                    "(IDA style, '?' = wildcard byte; branch targets, RIP-relative/absolute addresses "
                    f"and relocations are wildcarded):\n{sig['pattern']}\nStatus: {status}\n"
                    f"Instruction bytes (wildcards applied):\n{sig['listing']}\n"
                    "Use this signature verbatim; do not recompute bytes from pseudocode."
                )

        compare_block = ""
        if compare_mode:
            cmp_limit = max(int(cfg.get("max_code_chars", 6000)), int(cfg.get("compare_max_code_chars", 40000)))
            new_full = compact_pseudocode(get_pseudo_at(target_f.start_ea)[1] or "") or ctx["code"]
            cmp = compare_versions(old_code, new_full)
            compare_block = (
                f"\n\nVERSION COMPARISON. NEW = {cur} @ {target_f.start_ea:#x} (current database); "
                f"OLD = {old_label}.\n" + format_comparison(cmp)
            )
            if cmp["similarity"] < 0.5 and not cmp["identical"]:
                # Heavily rewritten: a diff is not readable, give both bodies.
                compare_block += (
                    "\n\nThe versions differ a lot; full OLD code:\n" + fit_code(old_code, cmp_limit // 2)
                    + "\n\nFull NEW code:\n" + fit_code(new_full, cmp_limit // 2)
                )
            compare_block += (
                "\n\nAnswer format: 1) start with a Markdown table using the columns "
                "'old -> new | delta | what it is (field/vtable slot/array index/constant/property id) | "
                "evidence line'. Put every table row on its own physical line so the table renders "
                "correctly; do not combine the table into one line. For a1[N], give the byte offset "
                "(N * element size) only when the element size is known; otherwise mark it unknown. "
                "Do not guess what an offset represents: write 'unknown' when evidence is insufficient. "
                "2) If many offsets shift by the same delta, describe the possible struct change "
                "(e.g. 8 bytes inserted before offset X), and clearly label it as an inference/hypothesis "
                "unless directly confirmed by the diff or other supplied facts. Separate confirmed facts "
                "from hypotheses. 3) List added/removed calls and logic changes in a few concise bullets. "
                "Use only the precomputed facts and diff; do not restate unchanged code."
            )
            log_msg(
                "INFO", "chat",
                f"Сравнение версий: похожесть {cmp['similarity']:.2f}, изменённых чисел {len(cmp['changed_numbers'])}, "
                f"diff {len(cmp['diff'])} симв. (исходники: старая {len(old_code)}, новая {len(new_full)} симв.)", cfg,
            )

        ent = self.get_func_db(f)
        history = ent.setdefault("chat_history", [])
        if compare_mode and pasted_blocks:
            ent["compare_old_code"] = old_code[:60000]

        # Stable prefix first (instructions + function code + xrefs), then the
        # conversation, then the new question: providers with prefix caching
        # reuse the code block across questions about the same function.
        system_prompt = (
            "You are an expert reverse-engineering assistant operating inside IDA Pro. "
            "Answer in Russian. Give only the final answer: never reveal internal reasoning, hidden thoughts, "
            "or analysis traces. Be concise and distinguish database facts from inference. "
            "When xref data is supplied, use its exact count and entries; never guess missing xrefs. "
            "The xref count refers to references to the function entry point, not necessarily every byte "
            "inside all function chunks.\n"
            f"{get_language_instruction(cfg)}\n\n"
            f"Target Function: {cur} @ {target_f.start_ea:#x}\n"
            f"Code ({ctx['source_type']}):\n{ctx['code']}\n\n"
            f"Incoming xrefs from IDA database:\n{xref_context}"
        )
        messages = (
            [{"role": "system", "content": system_prompt}]
            + [
                {**item, "content": history_placeholder(item.get("content", ""))}
                if item.get("role") == "user" else item
                for item in history[-6:]
            ]
            + [{"role": "user", "content": (
                f"Question: {question_text or 'Compare the two versions.'}{compare_block}{signature_block}"
                if compare_mode else f"Question: {user_query}{signature_block}"
            )}]
        )

        def runner(token, run_cfg):
            # Do not stream intermediate model output into the chat: only the completed
            # final content is displayed, so reasoning metadata cannot flash in the UI.
            reasoning_on = bool(run_cfg.get("chat_reasoning", False))
            mode, prof = get_active_profile(run_cfg)
            profile_max = int(prof.get("max_output_tokens" if mode == "cloud" else "num_predict", 2000) or 2000)
            chat_cap = max(512, int(run_cfg.get("chat_max_output_tokens", 8192) or 8192))
            out_limit = min(profile_max, chat_cap)
            txt = meta = None
            total_cost = 0.0
            total_in = total_out = 0
            total_time = 0.0
            attempts = 0
            transport_retry_used = False
            while True:
                stage = "chat" if attempts == 0 else f"chat (Retry #{attempts})"
                try:
                    txt, meta = chat_completion(
                        run_cfg, messages,
                        stage=stage,
                        chunk_callback=None, json_mode=False,
                        cancel_event=self.cancel_event,
                        max_output_override=out_limit,
                        disable_reasoning=not reasoning_on,
                        enable_reasoning=reasoning_on,
                    )
                except APIError as err:
                    if (not err.retryable or transport_retry_used
                            or (self.cancel_event and self.cancel_event.is_set())):
                        raise
                    transport_retry_used = True
                    attempts += 1
                    log_msg(
                        "WARNING", "chat",
                        f"Поток ответа оборвался ({err}); повторяю запрос целиком. "
                        "Частичный ответ не будет сохранён.", run_cfg,
                    )
                    time.sleep(1.0)
                    continue
                txt = re.sub(r"(?is)<think\b[^>]*>.*?(?:</think\s*>|$)", "", str(txt or "")).strip()
                total_cost += float(meta.get("cost_usd", 0) or 0)
                total_in += int(meta.get("prompt_tokens", 0) or 0)
                total_out += int(meta.get("completion_tokens", 0) or 0)
                total_time += float(meta.get("duration", 0) or 0)
                if txt or meta.get("finish_reason") != "length" or not reasoning_on:
                    break
                if self.cancel_event and self.cancel_event.is_set():
                    break
                # The whole budget went into reasoning: one more try without it.
                attempts += 1
                reasoning_on = False
                log_msg(
                    "WARNING", "chat",
                    f"Модель израсходовала лимит {out_limit} токенов на рассуждения без ответа; "
                    "повторяю запрос без рассуждений.", run_cfg,
                )
            meta = dict(meta or {})
            if attempts:
                meta.update({"cost_usd": total_cost, "prompt_tokens": total_in,
                             "completion_tokens": total_out, "total_tokens": total_in + total_out,
                             "duration": total_time})
            meta["retries"] = attempts
            log_request_metrics(run_cfg, meta)
            if not txt:
                raise APIError(
                    f"Модель не дала ответа: лимит вывода ({out_limit} токенов) исчерпан"
                    + (" на рассуждениях." if meta.get("finish_reason") == "length" else "."),
                    retryable=False, duration=total_time,
                )
            return [(txt, meta)]

        def handler(res):
            answer, meta = res[0]
            history.append({"role": "user", "content": user_query})
            history.append({"role": "assistant", "content": answer})
            self.trigger_save()
            return {"title": "Чат с ИИ", "section": "chat", "desc": user_query, "props": [], "details": history, "metrics": meta}

        return {"title": "Чат с ИИ", "section": "chat", "runner": runner, "handler": handler}

    def job_struct(self, f, var_name):
        cfg = self.cfg
        ctx = extract_func_rich_context(f.start_ea, depth_level=2, code_char_limit=cfg["max_code_chars"])
        cur = fname(f.start_ea)
        ent = self.get_func_db(f)
        history = ent.setdefault("chat_history", [])

        system_prompt = (
            f"Reconstruct a clean C/C++ struct definition for variable '{var_name}' based on memory offsets and types. "
            f"\n{get_language_instruction(cfg)}"
        )
        user_msg = f"Сгенерировать C++-структуру для переменной {var_name}"
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"Function: {cur} @ {f.start_ea:#x}\nVariable: {var_name}\nCode:\n{ctx['code']}"},
        ]

        def runner(token, run_cfg):
            txt = meta = None
            for attempt in range(2):
                streamed_any = [False]

                def chunk_cb(piece):
                    streamed_any[0] = True
                    self.bridge.chunk_signal.emit((token, piece))

                try:
                    txt, meta = chat_completion(
                        run_cfg, messages,
                        stage="struct" if attempt == 0 else "struct (Retry #1)",
                        chunk_callback=chunk_cb, json_mode=False,
                        cancel_event=self.cancel_event,
                        disable_reasoning=False, enable_reasoning=True,
                    )
                    break
                except APIError as err:
                    # Once visible text has been streamed, replaying could duplicate
                    # it in the UI. Retry only failures that happened before first data.
                    if (not err.retryable or streamed_any[0] or attempt >= 1
                            or (self.cancel_event and self.cancel_event.is_set())):
                        raise
                    log_msg(
                        "WARNING", "struct",
                        f"Сетевой сбой до первого фрагмента ({err}); повторяю запрос (2/2).",
                        run_cfg,
                    )
                    time.sleep(1.0)
            meta["retries"] = attempt
            log_request_metrics(run_cfg, meta)
            return [(txt, meta)]

        def handler(res):
            answer, meta = res[0]
            history.append({"role": "user", "content": user_msg})
            history.append({"role": "assistant", "content": answer})
            self.trigger_save()
            return {"title": "Чат с ИИ", "section": "struct", "desc": user_msg, "props": [], "details": history, "metrics": meta}

        return {"title": "Реконструкция структуры", "section": "struct", "runner": runner, "handler": handler}

    # ------------------------------------------------------------------
    # Applying IDB Changes
    # ------------------------------------------------------------------
    def apply(self, items):
        order = {"proto": 0, "lvar_type": 1, "rename_func": 2, "rename_lvar": 3, "comment": 4, "func_comment": 5}
        items = sorted(items, key=lambda it: order.get(it[0]["kind"], 6))
        if ida_undo:
            try:
                ida_undo.create_undo_point(b"AI Assistant", b"AI Assistant: apply")
            except Exception:
                pass
        log, ok = [], 0
        cf_cache = {}
        for p, val in items:
            k, val = p["kind"], str(val).strip()
            try:
                res = self._apply_one(p, k, val, cf_cache)
            except Exception as e:
                res = f"ошибка: {e}"
            good = res is True
            ok += good
            log.append(f"{'OK ' if good else 'ERR'} {KIND_LABEL.get(k, k)} {p['target']} -> {val[:50] if good else res}")
        try:
            ida_kernwin.refresh_idaview_anyway()
        except Exception:
            pass
        if self.displayed_func_ea:
            f = ida_funcs.get_func(self.displayed_func_ea)
            if f:
                ent = self.get_func_db(f)
                ent["hash"] = compute_func_hash(f)
                self.trigger_save()
        return ok, log

    def _apply_one(self, p, k, val, cf_cache):
        if k == "rename_func":
            ea, nm = p["func"], ident(val, "")
            if not nm:
                return "пустое имя"
            existing_ea = ida_name.get_name_ea(ida_idaapi.BADADDR, nm)
            if existing_ea != ida_idaapi.BADADDR and existing_ea != ea:
                nm = f"{nm}_{ea:X}"
            return True if ida_name.set_name(ea, nm, ida_name.SN_CHECK | ida_name.SN_NOWARN) else "отклонено"
        if k == "rename_lvar":
            if not hx_ok():
                return "Hex-Rays недоступен"
            return True if ida_hexrays.rename_lvar(p["func"], p["target"], ident(val)) else "отклонено"
        if k in ("comment", "func_comment"):
            ea = p.get("ea", p.get("func"))
            old = ida_bytes.get_cmt(ea, False) or ""
            return True if ida_bytes.set_cmt(ea, (old + " | " if old else "") + "[AI] " + val, False) else "отклонено"
        if k == "lvar_type":
            if not hx_ok():
                return "Hex-Rays недоступен"
            tif = ida_typeinf.tinfo_t()
            if not ida_typeinf.parse_decl(tif, None, val.rstrip(";") + " x;", ida_typeinf.PT_SIL):
                return "тип не разобран"
            cf = cf_cache.get(p["func"]) or ida_hexrays.decompile(p["func"])
            cf_cache[p["func"]] = cf
            for lv in cf.get_lvars():
                if lv.name == p["target"]:
                    lsi = ida_hexrays.lvar_saved_info_t()
                    lsi.ll = lv
                    lsi.type = tif
                    return True if ida_hexrays.modify_user_lvar_info(p["func"], ida_hexrays.MLI_TYPE, lsi) else "отклонено"
            return "переменная не найдена"
        return "не поддерживается"

    def settings(self):
        dlg = SettingsDialog(self.cfg, self.panel)
        if dlg.exec():
            self.cfg = dlg.get_updated_cfg()
            save_cfg(self.cfg)
            if self.panel:
                self.panel.refresh_models()
                self.panel.apply_theme(self.cfg.get("theme", "Dark"))
                self.panel.apply_language()
