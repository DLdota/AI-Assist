# -*- coding: utf-8 -*-
"""
Prompt engineering, JSON schemas, multi-level Deep Scan strategy, and proposal builders.
"""
import time

from .api import APIError, chat_completion
from .config import (
    get_active_profile,
    get_custom_prompt_instruction,
    get_language_instruction,
    log_msg,
)
from .ida_utils import (
    clip,
    collect_call_graph,
    extract_func_rich_context,
    fname,
    get_pseudo_at,
    is_auto_generated_name,
    ident,
)
from .parser import AIResponseError, parse_json_response

SYS_JSON = (
    "You are an expert reverse engineer inside IDA Pro. Rules:\n"
    "- Output ONLY a valid JSON object matching the requested schema.\n"
    "- Use double quotes for keys and string values. NO trailing commas.\n"
    "- NO markdown fences (no ```json), NO extra text.\n"
    "- Ground every conclusion strictly in the supplied code, strings, xrefs, and types; do not hallucinate APIs or behavior.\n"
    "- Prefer conservative, specific names; if evidence is weak, keep the existing name and lower confidence.\n"
    "{lang_rule}"
)

SCHEMA_SCAN = (
    '{\n'
    '  "function_name": "PascalCaseName",\n'
    '  "description": "Short description (max 140 chars)",\n'
    '  "confidence": "высокая",\n'
    '  "variables": [{"old": "v4", "new": "buffer", "confidence": "высокая"}]\n'
    '}'
)

SCHEMA_DEEP_SINGLE = (
    '{\n'
    '  "suggested_name": "CalculateMovementSpeed",\n'
    '  "status": "предложено",\n'
    '  "purpose": "Краткое назначение функции",\n'
    '  "facts": ["Подтверждённые факты из кода/типов/строк"],\n'
    '  "hypotheses": ["Предположения с явной пометкой и основанием"],\n'
    '  "field_layout": [{"expression": "base + 0x10", "offset": "0x10", "size": "неизвестен", "meaning": "назначение только если подтверждается"}],\n'
    '  "control_flow": ["Условие ветви и конкретное последствие"],\n'
    '  "loops_and_containers": ["Циклы, индексация, границы, тип контейнера и признаки"],\n'
    '  "helper_calls": [{"callee": "FunctionName", "role": "роль вызова", "evidence": "аргументы/результат/эффект"}],\n'
    '  "reasoning": "Краткое обоснование и ограничения вывода",\n'
    '  "confidence": "высокая"\n'
    '}'
)

# Basic mode for non-root nodes: the fields that drive naming, without the
# heavy layout/control-flow/loop lists that are usually empty for helpers.
SCHEMA_DEEP_COMPACT = (
    '{\n'
    '  "suggested_name": "CalculateMovementSpeed",\n'
    '  "status": "предложено",\n'
    '  "purpose": "Краткое назначение функции",\n'
    '  "facts": ["Подтверждённые факты из кода/типов/строк"],\n'
    '  "hypotheses": ["Предположения с явной пометкой и основанием"],\n'
    '  "helper_calls": [{"callee": "FunctionName", "role": "роль вызова", "evidence": "аргументы/результат/эффект"}],\n'
    '  "reasoning": "Краткое обоснование и ограничения вывода",\n'
    '  "confidence": "высокая"\n'
    '}'
)

# Functions at least this large (non-empty code lines) get model reasoning in
# Deep Scan; smaller helpers are answered directly, which saves most output tokens.
REASONING_MIN_LINES = 40


def deep_node_wants_reasoning(node, depth):
    if depth < 1:
        return False
    if node.get("depth", 0) == 0:
        return True
    return int(node.get("code_lines", 0) or 0) >= REASONING_MIN_LINES


def deep_node_uses_full_schema(node, depth):
    return depth >= 2 or node.get("depth", 0) == 0


SCHEMA_DEEP_SURFACE = (
    '{\n'
    '  "suggested_name": "PascalCaseName",\n'
    '  "status": "предложено",\n'
    '  "purpose": "Одно-два коротких предложения о назначении функции",\n'
    '  "reasoning": "Краткое обоснование по конкретным признакам кода",\n'
    '  "confidence": "высокая"\n'
    '}'
)

SCHEMA_PSEUDO = (
    '{\n'
    '  "explanation": "Краткое объяснение логики: 3-6 пунктов, без пересказа каждой строки",\n'
    '  "suggestions": [{"target": "v2", "new": "counter", "confidence": "высокая"}]\n'
    '}'
)

KIND_LABEL = {
    "rename_func": "Имя функции",
    "rename_lvar": "Переменная",
    "comment": "Комментарий",
    "func_comment": "Комментарий функции",
    "lvar_type": "Тип переменной",
    "proto": "Прототип",
}

def clip_line(text, limit):
    text = " ".join(str(text or "").split())
    return text if len(text) <= limit else text[:limit - 1].rstrip() + "…"


def make_proposal(kind, target, value, current="", conf=None, checked=True, ea=None, **extra):
    return {
        "kind": kind,
        "target": target,
        "value": value,
        "current": current,
        "conf": conf,
        "checked": checked,
        "ea": ea,
        **extra,
    }

def build_json_system_prompt(cfg):
    base = SYS_JSON.replace("{lang_rule}", get_language_instruction(cfg))
    custom = get_custom_prompt_instruction(cfg)
    if custom:
        base += "\n\nADDITIONAL USER INSTRUCTIONS:\n" + custom
    return base

def parse_confidence(val):
    if isinstance(val, (int, float)):
        if val >= 0.75:
            return 0.85, "высокая"
        if val >= 0.4:
            return 0.60, "средняя"
        return 0.30, "низкая"
    s = str(val).lower().strip()
    if "высок" in s or "high" in s:
        return 0.85, "высокая"
    if "сред" in s or "med" in s:
        return 0.60, "средняя"
    return 0.30, "низкая"

def get_deep_level_profile(cfg, depth):
    """Four explicit analysis modes: surface, basic, deep, and very deep."""
    _, prof = get_active_profile(cfg)
    base_max = int(prof.get("max_output_tokens") or prof.get("num_predict") or 1500)
    depth = max(0, min(3, int(depth)))
    configured_limits = cfg.get("deep_output_limits") or {}

    # Defaults preserve the previous depth scaling; user limits below override
    # the output budget and are enforced as hard ceilings, including retries.
    profiles = {
        0: {
            "label": "Поверхностный",
            # The surface schema is deliberately compact; a smaller output cap
            # avoids spending time generating details this mode does not display.
            "max_tokens": min(max(int(base_max * 1.0), 1200), 1800),
            "max_tokens_cap": 2700,
            "graph_depth": 0,
            "include_xrefs": False,
            "include_types": False,
            "include_disasm": False,
            "include_callbacks": False,
            "include_struct_hints": False,
            "bottom_up": False,
        },
        1: {
            "label": "Базовый",
            "max_tokens": min(max(int(base_max * 4.0), 6000), 10000),
            "max_tokens_cap": 10000,
            "graph_depth": 1,
            "include_xrefs": True,
            "include_types": True,
            "include_disasm": False,
            "include_callbacks": False,
            "include_struct_hints": False,
            "bottom_up": True,
        },
        2: {
            "label": "Глубокий",
            "max_tokens": min(max(int(base_max * 6.5), 10000), 16000),
            "max_tokens_cap": 16000,
            "graph_depth": 2,
            "include_xrefs": True,
            "include_types": True,
            "include_disasm": True,
            "include_callbacks": False,
            "include_struct_hints": True,
            "bottom_up": True,
        },
        3: {
            "label": "Очень глубокий",
            "max_tokens": min(max(int(base_max * 9.0), 14000), 24000),
            "max_tokens_cap": 24000,
            "graph_depth": 3,
            "include_xrefs": True,
            "include_types": True,
            "include_disasm": True,
            "include_callbacks": True,
            "include_struct_hints": True,
            "bottom_up": True,
        },
    }
    result = dict(profiles[depth])
    try:
        user_limit = int(configured_limits.get(str(depth), result["max_tokens"]))
    except (TypeError, ValueError):
        user_limit = result["max_tokens"]
    user_limit = max(256, min(65536, user_limit))
    result["max_tokens"] = user_limit
    result["max_tokens_cap"] = user_limit
    result["depth"] = depth
    log_msg(
        "DEBUG", "DeepScanProfile",
        f"mode={result['label']}, graph_depth={result['graph_depth']}, "
        f"max_output={result['max_tokens']}, callbacks={result['include_callbacks']}", cfg,
    )
    return result

def execute_json_request_with_retry(
    cfg, messages, stage, cancel_event=None, max_output_override=None,
    max_retries=1, disable_reasoning=False, enable_reasoning=False,
    max_output_cap=None,
):
    """Run a JSON request with bounded retries and aggregate metrics across attempts."""
    total_prompt_tokens = 0
    total_cached_tokens = 0
    total_completion_tokens = 0
    total_cost = 0.0
    total_duration = 0.0
    retries_used = 0
    estimated_any = False
    current_messages = list(messages)
    current_max_tokens = max_output_override
    if max_output_cap is not None:
        max_output_cap = max(256, min(65536, int(max_output_cap)))
        current_max_tokens = min(int(current_max_tokens or max_output_cap), max_output_cap)
    current_disable_reasoning = bool(disable_reasoning)
    current_enable_reasoning = bool(enable_reasoning)
    last_raw = ""
    last_meta = {}

    for attempt in range(max_retries + 1):
        if cancel_event and cancel_event.is_set():
            raise InterruptedError("Запрос отменён пользователем")

        try:
            raw_text, meta = chat_completion(
                cfg, current_messages,
                stage=stage if attempt == 0 else f"{stage} (Retry #{attempt})",
                json_mode=True, cancel_event=cancel_event,
                max_output_override=current_max_tokens, stream=True,
                disable_reasoning=current_disable_reasoning,
                enable_reasoning=current_enable_reasoning,
            )
            last_raw, last_meta = raw_text, meta
            total_prompt_tokens += int(meta.get("prompt_tokens", 0) or 0)
            total_cached_tokens += int(meta.get("cached_prompt_tokens", 0) or 0)
            total_completion_tokens += int(meta.get("completion_tokens", 0) or 0)
            total_cost += float(meta.get("cost_usd", 0.0) or 0.0)
            total_duration += float(meta.get("duration", 0.0) or 0.0)
            estimated_any = estimated_any or bool(meta.get("tokens_estimated"))

            parsed = parse_json_response(raw_text, stage=stage, completion_info=meta, cfg=cfg)
            agg_meta = {
                "provider": meta.get("provider", get_active_profile(cfg)[0]),
                "model": meta.get("model", get_active_profile(cfg)[1].get("model", "")),
                "stage": stage,
                "prompt_tokens": total_prompt_tokens,
                "cached_prompt_tokens": total_cached_tokens,
                "completion_tokens": total_completion_tokens,
                "total_tokens": total_prompt_tokens + total_completion_tokens,
                "tokens_estimated": estimated_any,
                "cost_usd": total_cost,
                "duration": total_duration,
                "retries": retries_used,
                "finish_reason": meta.get("finish_reason", "unknown"),
            }
            log_request_metrics(cfg, agg_meta)
            return parsed, agg_meta

        except (AIResponseError, APIError) as err:
            # Preserve elapsed time even when the transport itself fails before returning metadata.
            total_duration += float(getattr(err, "duration", 0.0) or 0.0)
            if isinstance(err, APIError) and err.status_code in (401, 403, 404):
                raise
            if isinstance(err, APIError) and not err.retryable:
                raise
            if attempt >= max_retries:
                if total_duration:
                    mode, prof = get_active_profile(cfg)
                    failure_meta = {
                        "provider": mode, "model": prof.get("model", ""), "stage": stage,
                        "prompt_tokens": total_prompt_tokens,
                        "completion_tokens": total_completion_tokens,
                        "total_tokens": total_prompt_tokens + total_completion_tokens,
                        "tokens_estimated": estimated_any, "cost_usd": total_cost,
                        "duration": total_duration, "retries": retries_used,
                    }
                    log_request_metrics(cfg, failure_meta)
                raise

            retries_used += 1
            log_msg("INFO", stage, f"Attempt {attempt + 1} failed ({err}). Retrying ({retries_used}/{max_retries})...", cfg)
            if isinstance(err, APIError) and err.retryable:
                time.sleep(min(1.0 + attempt, 2.0))

            if isinstance(err, AIResponseError):
                # If no explicit override was supplied, grow the active profile's configured limit.
                if last_meta.get("finish_reason") == "length":
                    if not current_max_tokens:
                        _, active_prof = get_active_profile(cfg)
                        current_max_tokens = int(active_prof.get("max_output_tokens") or active_prof.get("num_predict") or 1500)
                    no_final_content = not bool(last_raw.strip())
                    reasoning_was_emitted = int(last_meta.get("reasoning_chars", 0) or 0) > 0
                    if no_final_content and reasoning_was_emitted and not current_disable_reasoning:
                        current_disable_reasoning = True
                        current_enable_reasoning = False
                        log_msg(
                            "WARNING", stage,
                            "Output limit was exhausted in reasoning before final JSON appeared; "
                            "retrying once with reasoning disabled.", cfg,
                        )
                    grown_limit = max(int(current_max_tokens) + 1, int(current_max_tokens * 1.5))
                    current_max_tokens = min(grown_limit, int(max_output_cap)) if max_output_cap else grown_limit

                current_messages = list(messages)
                # Re-sending a truncated assistant completion wastes context and often repeats the same cut-off.
                if last_raw and last_meta.get("finish_reason") != "length":
                    current_messages.append({"role": "assistant", "content": clip(last_raw, 900)})
                current_messages.append({
                    "role": "user",
                    "content": (
                        "Предыдущая попытка не прошла проверку JSON. Верни один полный JSON-объект "
                        "строго по схеме, без Markdown и текста вне JSON. Сократи пояснения, "
                        "не выдумывай отсутствующие данные; неизвестное обозначай явно. "
                        f"Причина проверки: {str(err)[:500]}"
                    ),
                })

    raise AIResponseError(f"Не удалось получить валидный JSON в разделе '{stage}'.")

def log_request_metrics(cfg, meta):
    est_tag = " (approx)" if meta.get("tokens_estimated") else ""
    cost_str = f"${meta['cost_usd']:.6f}" if meta.get("provider") == "cloud" else "$0.000000 (local)"
    log_msg(
        "INFO",
        "Metrics",
        f"stage={meta['stage']} | provider={meta['provider']} | model={meta['model']} | "
        f"in_tokens={meta['prompt_tokens']}{est_tag} (cached={meta.get('cached_prompt_tokens', 0)}) | out_tokens={meta['completion_tokens']}{est_tag} | "
        f"cost={cost_str} | time={meta['duration']:.2f}s | retries={meta['retries']}",
        cfg,
    )

def format_deep_node_prompt(node, level_prof, resolved_names_map, resolved_purposes=None, full_schema=True):
    """Build a mode-aware prompt with explicit evidence boundaries."""
    lines = [
        f"Target Function: {node['name']} @ {node['ea']:#x} (Call Depth: {node['depth']}, Source: {node['source_type']})",
        f"Analysis mode: {level_prof['label']}.",
    ]
    if level_prof.get("graph_depth", 0) == 0:
        lines.extend([
            "Requirements:",
            "1) Analyze only this function and the supplied code; do not infer behavior from unavailable callees.",
            "2) State its main purpose in 1-2 short sentences and give only the strongest code evidence.",
            "3) Suggest a PascalCase name only when the current name is auto-generated and evidence supports it.",
            "4) If evidence is insufficient, preserve the current name and say what is unknown.",
            "5) Be concise. Do not produce facts/hypotheses/field-layout/control-flow/helper-call lists.",
        ])
    else:
        lines.extend([
            "Requirements:",
            "1) Ground every statement in supplied code, references, types, strings, or concrete call effects.",
            "2) For pointer arguments, trace how the caller initializes the pointed-to memory and how the callee reads/writes offsets; distinguish proven fields from guesses.",
            "3) Identify callback/function-pointer references separately from ordinary direct calls. Do not claim a callback role unless the registration/call context supports it.",
        ])
        if full_schema:
            lines.append("4) Explain branch predicates and consequences; report loop bounds and indexing only when visible.")
        lines.extend([
            "5) Separate confirmed facts from hypotheses. Preserve generic names when evidence is insufficient.",
            "6) Keep purpose <= 2 sentences, reasoning <= 100 words, and each array <= 5 concise items; omit empty details.",
        ])

    if level_prof["include_types"]:
        if node.get("prototype"):
            lines.append(f"Prototype: {node['prototype']}")
        if node.get("args"):
            lines.append(f"Arguments: {node['args']}")
        if node.get("struct_types"):
            lines.append(f"Pointer/Struct Types: {', '.join(node['struct_types'])}")
        if level_prof.get("include_struct_hints") and node.get("address_escaped_locals"):
            lines.append(f"Address-escaped locals (possible stack aggregates; verify against callee accesses): {node['address_escaped_locals']}")

    if level_prof["include_xrefs"]:
        xrefs = node.get("xref_summary") or {}
        lines.append(
            f"Function Xrefs: total={xrefs.get('count', 0)}, code={xrefs.get('code_count', 0)}, "
            f"data={xrefs.get('data_count', 0)}"
        )
        callers = list(node.get("callers") or [])
        if callers:
            lines.append(f"Callers (XrefsTo): {', '.join(callers)}")
        # Only xrefs not already represented by the callers list (data refs,
        # vtables, references from code outside functions).
        caller_set = set(callers)
        extra_refs = [
            item for item in xrefs.get("items", [])
            if not (item.get("is_code") and item.get("from_name") in caller_set)
        ]
        if extra_refs:
            refs_text = [
                f"{item.get('from_name') or hex(item.get('from', 0))} @ {item.get('from', 0):#x} ({'code' if item.get('is_code') else 'data'})"
                for item in extra_refs[:8]
            ]
            more = len(extra_refs) - len(refs_text)
            lines.append("Other xref sources: " + "; ".join(refs_text) + (f"; +{more} more" if more > 0 else ""))
        if node.get("callees"):
            resolved_purposes = resolved_purposes or {}
            plain = [c for c in node["callees"] if c not in resolved_names_map]
            inferred = [c for c in node["callees"] if c in resolved_names_map]
            if plain:
                lines.append(f"Direct callees: {', '.join(plain)}")
            if inferred:
                lines.append("Callees already analysed (inferred name: purpose):")
                for c in inferred:
                    purpose = clip_line(resolved_purposes.get(c, ""), 140)
                    lines.append(f"- {c} -> {resolved_names_map[c]}" + (f": {purpose}" if purpose else ""))

    if node.get("incoming_context"):
        incoming = node["incoming_context"]
        lines.append(
            f"Incoming graph edge: {incoming.get('kind')} from {incoming.get('from')}; "
            f"caller-side evidence (call with argument setup; ' | ' joins lines, ' … ' joins call sites): {incoming.get('call_site') or 'not recovered'}"
        )
        if incoming.get("caller_address_escaped_locals"):
            lines.append(f"Caller locals passed by address (verify callee field accesses): {incoming['caller_address_escaped_locals']}")
    if level_prof.get("include_callbacks") and node.get("callback_refs"):
        lines.append("Possible function-pointer/callback targets (verify call-site semantics): " + "; ".join(node["callback_refs"]))
    if node.get("strings"):
        lines.append(f"Strings: {node['strings']}")
    if node.get("globals"):
        lines.append(f"Globals: {', '.join(node['globals'])}")
    lines.append(f"Code:\n{node['code']}")
    if level_prof["include_disasm"] and node.get("disasm_hint"):
        lines.append(f"Key Disassembly:\n{node['disasm_hint']}")
    return "\n".join(lines)

