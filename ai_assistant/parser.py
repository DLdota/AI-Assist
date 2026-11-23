# -*- coding: utf-8 -*-
"""
JSON extraction, Markdown unwrapping, and conservative malformed-response repair.
"""
import json
import re
from .config import log_msg

class AIResponseError(Exception):
    pass

def strip_thinking_blocks(text):
    if not text:
        return ""
    # Remove <think>...</think> or unclosed <think>... blocks from reasoning models
    cleaned = re.sub(r"<think>.*?</think>", "", text, flags=re.S)
    cleaned = re.sub(r"<think>.*$", "", cleaned, flags=re.S)
    return cleaned.strip()

def _balanced_candidate(s, start):
    stack = []
    in_string = False
    escaped = False
    for i in range(start, len(s)):
        ch = s[i]
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch == "{":
            stack.append("}")
        elif ch == "[":
            stack.append("]")
        elif ch in "}]":
            if not stack or stack[-1] != ch:
                return s[start:i + 1].strip(), True
            stack.pop()
            if not stack:
                return s[start:i + 1].strip(), True
    return s[start:].strip(), False

def extract_json_candidate(text):
    """Find a complete JSON object despite surrounding prose or bracket-like code fragments."""
    s = strip_thinking_blocks(text)
    if not s:
        return ""

    fence_match = re.search(r"```(?:json)?\s*(.*?)\s*```", s, flags=re.S | re.I)
    if fence_match:
        fenced = fence_match.group(1).strip()
        if fenced.startswith(("{", "[")):
            s = fenced
    s = re.sub(r"^```(?:json)?\s*", "", s.strip(), flags=re.I)

    first_candidate = ""
    first_valid_non_object = ""
    for start, ch in enumerate(s):
        if ch not in "{[":
            continue
        candidate, complete = _balanced_candidate(s, start)
        if not candidate:
            continue
        if not first_candidate:
            first_candidate = candidate
        if not complete:
            continue
        try:
            parsed = json.loads(candidate)
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(parsed, dict):
            return candidate
        if not first_valid_non_object:
            first_valid_non_object = candidate

    return first_valid_non_object or first_candidate or s.strip()

def _repair_truncated_json(raw):
    """Attempts to balance unclosed quotes, brackets, and braces on truncated JSON."""
    s = re.sub(r",\s*([\]}])", r"\1", raw.strip())
    # Remove trailing incomplete key-value fragments like `, "key": "unterminated`
    s = re.sub(r',\s*"[^"]*"\s*:\s*"[^"]*$', "", s)
    s = re.sub(r',\s*"[^"]*"\s*:\s*$', "", s)
    s = re.sub(r',\s*"[^"]*$', "", s)
    s = s.rstrip(",")

    in_str = False
    escape = False
    stack = []
    for ch in s:
        if escape:
            escape = False
            continue
        if ch == "\\":
            escape = True
            continue
        if ch == '"':
            in_str = not in_str
            continue
        if not in_str:
            if ch in "{[":
                stack.append("}" if ch == "{" else "]")
            elif ch in "}]":
                if stack and stack[-1] == ch:
                    stack.pop()

    repaired = s
    if in_str:
        repaired += '"'
    while stack:
        repaired += stack.pop()
    return repaired

def parse_json_response(text, stage="unknown", completion_info=None, cfg=None):
    completion_info = completion_info or {}
    finish_reason = str(completion_info.get("finish_reason", "unknown") or "unknown").lower()

    if not text or not str(text).strip():
        raise AIResponseError(
            f"Пустой ответ от модели в разделе '{stage}' (finish_reason={finish_reason}). "
            "Проверьте лимит токенов и формат ответа API."
        )

    # A length finish means the provider cut generation off. Balancing brackets and
    # accepting the partial object can silently discard important analysis fields.
    if finish_reason in ("length", "max_tokens", "token_limit"):
        preview = str(text)[:180].replace("\n", " ")
        raise AIResponseError(
            f"Ответ модели обрезан лимитом токенов в разделе '{stage}' "
            f"(finish_reason={finish_reason}); неполный JSON отклонён. Фрагмент: {preview!r}"
        )

    candidate = extract_json_candidate(text)
    if not candidate:
        raise AIResponseError(
            f"Ответ модели не содержит JSON в разделе '{stage}' (finish_reason={finish_reason})."
        )

    try:
        data = json.loads(candidate)
    except json.JSONDecodeError as first_err:
        no_trailing = re.sub(r",\s*([\]}])", r"\1", candidate)
        try:
            data = json.loads(no_trailing)
            log_msg("INFO", "JSON", f"Removed trailing comma in stage '{stage}'.", cfg)
        except json.JSONDecodeError:
            repaired = _repair_truncated_json(candidate)
            try:
                data = json.loads(repaired)
                log_msg("INFO", "JSON", f"Recovered malformed JSON in stage '{stage}'.", cfg)
            except json.JSONDecodeError:
                preview = candidate[:180].replace("\n", " ")
                raise AIResponseError(
                    f"Ошибка невалидного JSON в разделе '{stage}' (finish_reason={finish_reason}): "
                    f"строка {first_err.lineno}, столбец {first_err.colno}: {first_err.msg}. "
                    f"Фрагмент: {preview!r}"
                )

    if not isinstance(data, dict):
        raise AIResponseError(
            f"Неверный тип JSON в разделе '{stage}': ожидался объект {{...}}, "
            f"получен {type(data).__name__}."
        )
    return data

