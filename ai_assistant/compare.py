# -*- coding: utf-8 -*-
"""
Version comparison helpers for the chat (pure Python, no IDA imports).

The user usually pastes the previous build's pseudocode of a function and asks
what changed (offsets, structures, constants, calls). Sending both full bodies
is expensive and the model tends to miss or invent offset changes, so the
plugin computes the facts locally:

- splits the chat message into the question text and pasted code;
- normalises auto-generated names that always differ between builds
  (sub_XXXX, qword_XXXX, LABEL_N, ...);
- builds a compact unified diff of the normalised code;
- pairs changed lines and extracts numeric changes (old -> new, delta);
- lists base+offset accesses that exist only in one version.
"""
import difflib
import re

_CODE_LINE_RE = re.compile(
    r"(;\s*(//.*)?$)|(^\s*[{}]\s*$)|(^\s*(if|while|for|switch|else|do|return|goto)\b)|(__fastcall|__cdecl|__stdcall|__thiscall)|(^\s*LABEL_\d+:)"
)
_COMPARE_INTENT_RE = re.compile(
    r"(?i)сравн|сопостав|предыдущ|прошл\w+ верс|стар\w+ верс|нов\w+ верс|верси\w+ (?:до|после)|"
    r"что изменил|изменени|отлич|разниц|diff|compare|comparison|previous|old(?:er)? version|"
    r"new version|what changed|changed|对比|比较|旧版|新版|变化"
)

_NORMALIZE_RULES = [
    (re.compile(r"\b(sub|loc|nullsub|j_sub|locret)_[0-9A-Fa-f]{4,}\b"), r"\1_?"),
    (re.compile(r"\b(qword|dword|word|byte|unk|off|stru|xmmword|ymmword|flt|dbl|asc|algn|jpt|def)_[0-9A-Fa-f]{4,}\b"), r"\1_?"),
    (re.compile(r"\bLABEL_\d+\b"), "LABEL_?"),
    (re.compile(r"//.*$"), ""),
]
_NUM_RE = re.compile(r"(?<![\w.])(0x[0-9A-Fa-f]+|\d+)(?:u?i64|i64|LL|ull|ULL|LLU|u|U|L|ll)?(?![\w.])")
_BASE_OFF_RE = re.compile(
    r"\b([A-Za-z_]\w*)\s*\+\s*(0x[0-9A-Fa-f]+|\d+)(?:u?i64|LL|ull|ULL|i64)?\b"
)
_INDEX_OFF_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\[\s*(0x[0-9A-Fa-f]+|\d+)\s*\]")


def looks_like_code(text):
    lines = [ln for ln in str(text or "").splitlines() if ln.strip()]
    if len(lines) < 4:
        return False
    hits = sum(1 for ln in lines if _CODE_LINE_RE.search(ln))
    return hits >= max(3, int(len(lines) * 0.5))


_STR_LIT_RE = re.compile(r'"(?:[^"\\\\]|\\\\.)*"')


def _is_prose(line):
    """True for natural-language lines (question text), false for code."""
    body = _STR_LIT_RE.sub('""', str(line or ""))
    if re.search(r"[А-Яа-яЁё]{3,}", body):
        return True
    words = re.findall(r"[A-Za-z]{2,}", body)
    return len(words) >= 4 and not re.search(r"[;{}()=*&\[\]]", body)


def split_question_and_code(message):
    """Return (question_text, [code_blocks]).

    Fenced ``` blocks are taken as code. Without fences, the longest run of
    code-like lines (>= 6 lines) is treated as pasted code.
    """
    text = str(message or "")
    blocks = []
    def take_fence(m):
        blocks.append(m.group(1).strip("\n"))
        return "\n"
    question = re.sub(r"```[\w+-]*\n(.*?)```", take_fence, text, flags=re.S)
    if blocks:
        return question.strip(), blocks

    lines = text.splitlines()
    code_idx = [i for i, ln in enumerate(lines) if ln.strip() and _CODE_LINE_RE.search(ln)]
    if len(code_idx) >= 5:
        start, end = code_idx[0], code_idx[-1] + 1
        # Hex-Rays signature line right before the first code line has no ';'.
        if start > 0 and not _is_prose(lines[start - 1]) and re.search(r"\w+\s*\(.*\)\s*$", lines[start - 1]):
            start -= 1
        if end - start >= 6:
            code = "\n".join(lines[start:end]).strip("\n")
            question = "\n".join(lines[:start] + lines[end:]).strip()
            return question, [code]
    return text.strip(), []


def looks_like_function(code):
    """A pasted Hex-Rays function (not just a snippet)."""
    lines = [ln for ln in str(code or "").splitlines() if ln.strip()]
    if len(lines) < 12:
        return False
    head = "\n".join(lines[:4])
    return "{" in head and lines[-1].strip() == "}"


def wants_comparison(question, pasted_blocks):
    if _COMPARE_INTENT_RE.search(question or ""):
        return True
    # A whole pasted Hex-Rays function with a short/no question is almost always
    # a "compare with this version" request; small snippets are not.
    blocks = pasted_blocks if isinstance(pasted_blocks, (list, tuple)) else []
    return any(looks_like_function(b) for b in blocks) and len((question or "").strip()) < 120


def normalize_line(line):
    s = str(line)
    for rx, rep in _NORMALIZE_RULES:
        s = rx.sub(rep, s)
    return re.sub(r"\s+", " ", s).strip()


def _num_value(tok):
    try:
        return int(tok, 16) if tok.lower().startswith("0x") else int(tok)
    except ValueError:
        return None


def _fmt(n):
    return f"{n} ({n:#x})" if abs(n) >= 10 else str(n)


def _mask_numbers(s):
    return _NUM_RE.sub("#", s)


def _numeric_changes(old_line, new_line):
    """Positional numeric differences between two structurally equal lines."""
    if _mask_numbers(old_line) != _mask_numbers(new_line):
        return []
    a = [_num_value(m.group(1)) for m in _NUM_RE.finditer(old_line)]
    b = [_num_value(m.group(1)) for m in _NUM_RE.finditer(new_line)]
    return [(x, y) for x, y in zip(a, b) if x is not None and y is not None and x != y]


def _offset_set(lines):
    out = {}
    for ln in lines:
        for rx in (_BASE_OFF_RE, _INDEX_OFF_RE):
            for m in rx.finditer(ln):
                val = _num_value(m.group(2))
                if val is None or val == 0:
                    continue
                out.setdefault(val, ln.strip())
    return out


def compare_versions(old_code, new_code, diff_context=2, max_diff_chars=9000, max_rows=40):
    """Compute a compact, model-friendly description of the changes."""
    old_lines = [ln for ln in str(old_code or "").splitlines() if ln.strip()]
    new_lines = [ln for ln in str(new_code or "").splitlines() if ln.strip()]
    old_norm = [normalize_line(ln) for ln in old_lines]
    strip_str = lambda ln: _STR_LIT_RE.sub('""', ln)
    new_norm = [normalize_line(ln) for ln in new_lines]

    sm = difflib.SequenceMatcher(a=old_norm, b=new_norm, autojunk=False)
    similarity = sm.ratio()

    # 1. numeric changes in paired lines (offsets / constants / sizes)
    changes = {}
    added_calls, removed_calls = set(), set()
    call_rx = re.compile(r"\b([A-Za-z_]\w*(?:::~?\w+)*)\s*\(")
    skip_calls = {"if", "while", "for", "switch", "return", "sizeof", "LODWORD", "HIDWORD", "LOBYTE",
                  "HIBYTE", "LOWORD", "HIWORD", "BYTE1", "BYTE2", "WORD1", "WORD2", "COERCE_FLOAT",
                  "COERCE_DOUBLE", "__ROL4__", "__ROR4__", "_mm_cvtsi32_si128"}
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            continue
        olds, news = old_norm[i1:i2], new_norm[j1:j2]
        used = set()
        for o in olds:
            best_j, best_r = None, 0.0
            mo = _mask_numbers(o)
            for jj, n in enumerate(news):
                if jj in used:
                    continue
                if _mask_numbers(n) == mo:
                    best_j, best_r = jj, 1.0
                    break
            if best_j is not None:
                used.add(best_j)
                for x, y in _numeric_changes(o, news[best_j]):
                    key = (x, y)
                    entry = changes.setdefault(key, {"count": 0, "example": news[best_j]})
                    entry["count"] += 1
        for o in olds:
            removed_calls.update(c for c in call_rx.findall(strip_str(o)) if c not in skip_calls)
        for n in news:
            added_calls.update(c for c in call_rx.findall(strip_str(n)) if c not in skip_calls)
    common_calls = added_calls & removed_calls
    added_calls -= common_calls
    removed_calls -= common_calls
    # Calls that exist in the unchanged part of the other version are not "new".
    all_old_calls = {c for ln in old_norm for c in call_rx.findall(strip_str(ln))}
    all_new_calls = {c for ln in new_norm for c in call_rx.findall(strip_str(ln))}
    added_calls = {c for c in added_calls if c not in all_old_calls}
    removed_calls = {c for c in removed_calls if c not in all_new_calls}

    # 2. offsets present only in one version
    off_old, off_new = _offset_set(old_norm), _offset_set(new_norm)
    only_old = sorted(set(off_old) - set(off_new))
    only_new = sorted(set(off_new) - set(off_old))

    # 3. compact unified diff of normalised code
    diff_lines = list(difflib.unified_diff(old_norm, new_norm, "old", "new", n=diff_context, lineterm=""))[2:]
    diff_text = "\n".join(diff_lines)
    diff_truncated = False
    if len(diff_text) > max_diff_chars:
        diff_text = diff_text[:max_diff_chars].rsplit("\n", 1)[0] + "\n... (diff truncated)"
        diff_truncated = True

    rows = sorted(changes.items(), key=lambda kv: (-kv[1]["count"], kv[0][0]))[:max_rows]
    num_table = [
        f"{_fmt(x)} -> {_fmt(y)} (delta {'+' if y - x >= 0 else '-'}{_fmt(abs(y - x))}, x{v['count']}): {v['example'][:110]}"
        for (x, y), v in rows
    ]
    return {
        "similarity": similarity,
        "old_lines": len(old_lines),
        "new_lines": len(new_lines),
        "changed_numbers": num_table,
        "offsets_only_old": [f"{_fmt(o)}: {off_old[o][:90]}" for o in only_old[:max_rows]],
        "offsets_only_new": [f"{_fmt(o)}: {off_new[o][:90]}" for o in only_new[:max_rows]],
        "calls_added": sorted(added_calls)[:30],
        "calls_removed": sorted(removed_calls)[:30],
        "diff": diff_text,
        "diff_truncated": diff_truncated,
        "identical": similarity == 1.0,
    }


def format_comparison(result):
    """Render compare_versions() output for the prompt."""
    if not result:
        return ""
    parts = [
        f"Precomputed comparison (auto names sub_/qword_/LABEL_ normalised): similarity {result['similarity']:.2f}, "
        f"old {result['old_lines']} lines, new {result['new_lines']} lines."
    ]
    if result["identical"]:
        parts.append("The normalised code is identical: only auto-generated names/addresses differ.")
        return "\n".join(parts)
    if result["changed_numbers"]:
        parts.append("Changed numeric literals in matching lines (old -> new):")
        parts += [f"- {row}" for row in result["changed_numbers"]]
    if result["offsets_only_old"]:
        parts.append("base+offset / index accesses only in OLD:")
        parts += [f"- {row}" for row in result["offsets_only_old"]]
    if result["offsets_only_new"]:
        parts.append("base+offset / index accesses only in NEW:")
        parts += [f"- {row}" for row in result["offsets_only_new"]]
    if result["calls_added"]:
        parts.append("Calls only in NEW: " + ", ".join(result["calls_added"]))
    if result["calls_removed"]:
        parts.append("Calls only in OLD: " + ", ".join(result["calls_removed"]))
    parts.append("Unified diff (old -> new, normalised):")
    parts.append(result["diff"] or "(no line differences)")
    return "\n".join(parts)


def history_placeholder(message, max_question=400):
    """Shorten a stored chat message that contains pasted code."""
    question, blocks = split_question_and_code(message)
    if not blocks:
        return message
    n_lines = sum(len(b.splitlines()) for b in blocks)
    q = question[:max_question]
    return f"{q}\n[пользователь вставил код другой версии функции: {n_lines} строк; код в историю не включён]".strip()
