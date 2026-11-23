# -*- coding: utf-8 -*-
"""
IDA Pro 9.4 context extraction: pseudocode, disassembly fallback, arguments/types,
callees, callers (xrefs), strings, global variables, and data structures.
"""
import hashlib
import re

import ida_bytes
import ida_funcs
import ida_hexrays
import ida_idaapi
import ida_kernwin
import ida_lines
import ida_name
import ida_typeinf
import idautils
import idc

from .config import log_msg

def hx_ok():
    try:
        return bool(ida_hexrays.init_hexrays_plugin())
    except Exception:
        return False

def fname(ea):
    return ida_funcs.get_func_name(ea) or ida_name.get_name(ea) or ("%#x" % ea)

def is_auto_generated_name(name):
    if not name:
        return True
    n = name.lower()
    return (
        n.startswith("sub_")
        or n.startswith("loc_")
        or n.startswith("nullsub_")
        or n.startswith("j_sub_")
        or n.startswith("locret_")
    )

def clip(s, n):
    if not s:
        return ""
    return s if len(s) <= n else s[:n] + "\n/* ...обрезано... */"

_HX_DECL_COMMENT_RE = re.compile(
    r"^(\s*[^\s/][^;]*;)\s*//\s*(?:(?:\[[^\]]*\]\s*)+(BYREF)?|[a-z][a-z0-9_]{1,10}(?:\s+BYREF)?|(BYREF))\s*$"
)


def compact_pseudocode(text):
    """Remove token-heavy noise from Hex-Rays output without losing semantics.

    - register/stack location comments of local declarations are dropped
      (``__int64 v4; // rax``, ``_BYTE v5[16]; // [rsp+20h] [rbp-18h] BYREF``);
      the ``BYREF`` marker is kept because it shows that the address escapes;
    - blank lines are removed;
    - Hex-Rays 2-space indentation is halved (structure is preserved).
    Declarations themselves (types of locals) are kept.
    """
    if not text:
        return ""
    out = []
    for raw in str(text).splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        m = _HX_DECL_COMMENT_RE.match(line)
        if m:
            byref = "BYREF" in line[len(m.group(1)):]
            line = m.group(1) + (" // BYREF" if byref else "")
        stripped = line.lstrip(" ")
        indent = len(line) - len(stripped)
        out.append(" " * (indent // 2) + stripped)
    return "\n".join(out)


def clip_code(text, limit):
    """Clip code at line boundaries keeping both the head and the tail.

    Function epilogues (return values, cleanup, final calls) are often more
    informative than the middle of a long body, so ~35% of the budget is
    reserved for the tail.
    """
    if not text:
        return ""
    text = str(text)
    limit = max(200, int(limit))
    if len(text) <= limit:
        return text
    marker = "\n/* ...пропущено {n} строк... */\n"
    lines = text.splitlines()
    head_budget = int(limit * 0.65)
    tail_budget = limit - head_budget - 40
    head, used = [], 0
    for line in lines:
        if used + len(line) + 1 > head_budget:
            break
        head.append(line)
        used += len(line) + 1
    tail, used = [], 0
    for line in reversed(lines[len(head):]):
        if used + len(line) + 1 > tail_budget:
            break
        tail.append(line)
        used += len(line) + 1
    tail.reverse()
    skipped = len(lines) - len(head) - len(tail)
    if skipped <= 0:
        return "\n".join(lines)
    if not head:  # one enormous line
        return text[:limit] + "\n/* ...обрезано... */"
    return "\n".join(head) + marker.format(n=skipped) + "\n".join(tail)


# ---------------------------------------------------------------------------
# Local declaration handling (Hex-Rays declaration block)
# ---------------------------------------------------------------------------
_C_KEYWORDS = {
    "return", "goto", "break", "continue", "if", "else", "while", "for", "do",
    "switch", "case", "default", "delete", "throw", "sizeof",
}
_PRIMITIVE_TYPES = {
    "char", "short", "int", "long", "float", "double", "bool", "_BOOL1", "_BOOL2",
    "_BOOL4", "_BOOL8", "__int8", "__int16", "__int32", "__int64", "__int128",
    "_BYTE", "_WORD", "_DWORD", "_QWORD", "_OWORD", "_UNKNOWN", "BYTE", "WORD",
    "DWORD", "QWORD", "unsigned", "signed", "const", "volatile", "void", "size_t",
    "__m64", "__m128", "__m128i", "__m128d", "__m256", "__m256i", "__m256d",
    "HIBYTE", "LOBYTE", "wchar_t", "char16_t", "char32_t", "uint8_t", "uint16_t",
    "uint32_t", "uint64_t", "int8_t", "int16_t", "int32_t", "int64_t", "uintptr_t",
    "intptr_t", "ssize_t", "LONG", "ULONG", "UINT", "INT", "BOOL", "HANDLE",
    "LPVOID", "PVOID", "SIZE_T", "ULONG_PTR", "LONG_PTR", "DWORD64", "ULONGLONG",
    "LONGLONG", "USHORT", "UCHAR",
}
_DECL_SIMPLE_RE = re.compile(
    r"^\s*(?P<type>[A-Za-z_][\w:<>, ]*?(?:[\s\*&]+))(?P<name>[A-Za-z_]\w*)(?P<arr>(?:\s*\[[^\]]*\])*)\s*;\s*(?P<cmt>//.*)?$"
)
_DECL_FUNCPTR_RE = re.compile(r"^\s*[\w\s\*:<>,]+\(\s*(?:__\w+\s+)?\*+\s*(?P<name>[A-Za-z_]\w*)\s*\)\s*\(.*\)\s*;\s*(//.*)?$")


def parse_decl_line(line):
    """Return {name, type, kind, raw} if *line* is a local variable declaration, else None.

    kind: "trivial" (scalar / pointer to scalar) or "important"
    (BYREF, arrays, structs/classes, function pointers, non-primitive types).
    """
    s = str(line or "").strip()
    if not s or "=" in s.split("//", 1)[0] or not s.split("//", 1)[0].rstrip().endswith(";"):
        return None
    first = re.match(r"[A-Za-z_]\w*", s)
    if not first or first.group(0) in _C_KEYWORDS:
        return None
    m = _DECL_FUNCPTR_RE.match(s)
    if m:
        return {"name": m.group("name"), "type": "funcptr", "kind": "important", "raw": s}
    code_part = s.split("//", 1)[0]
    if "(" in code_part:
        return None
    m = _DECL_SIMPLE_RE.match(s)
    if not m:
        return None
    type_text = re.sub(r"\s+", " ", m.group("type")).strip()
    # "type name" needs at least one type token (rejects e.g. "LABEL_5;").
    if not type_text or not re.search(r"[A-Za-z_]", type_text):
        return None
    cmt = m.group("cmt") or ""
    tokens = re.findall(r"[A-Za-z_]\w*", type_text)
    important = (
        "BYREF" in cmt
        or bool(m.group("arr").strip())
        or any(t in ("struct", "class", "union", "enum") for t in tokens)
        or any(t not in _PRIMITIVE_TYPES for t in tokens)
    )
    return {
        "name": m.group("name"),
        "type": type_text,
        "kind": "important" if important else "trivial",
        "raw": s,
    }


def _find_decl_block(lines):
    """Indices (start, end) of the leading local-declaration block, end exclusive."""
    start = None
    for i, line in enumerate(lines[:12]):
        if line.strip() == "{":
            start = i + 1
            break
    if start is None:
        return None
    end = start
    while end < len(lines) and parse_decl_line(lines[end]):
        end += 1
    return (start, end) if end > start else None


def condense_declarations(text, limit):
    """Shrink the declaration block when the function does not fit into *limit*.

    The function body carries most of the semantics, while long Hex-Rays
    declaration blocks (100+ ``__int64 vN;`` lines) can eat the whole budget.
    Step 1: keep informative declarations (BYREF, arrays, structs, custom and
    function-pointer types) verbatim and merge trivial scalar ones by type.
    Step 2: if still too long, drop trivial ones and leave a one-line note.
    """
    if not text or len(text) <= int(limit):
        return text
    lines = str(text).splitlines()
    block = _find_decl_block(lines)
    if not block:
        return text
    start, end = block
    indent = re.match(r"\s*", lines[start]).group(0)
    important, groups, trivial_count = [], {}, 0
    for line in lines[start:end]:
        d = parse_decl_line(line)
        if d["kind"] == "important":
            important.append(indent + d["raw"])
        else:
            trivial_count += 1
            base = d["type"].rstrip("*& ").strip()
            stars = d["type"][len(d["type"].rstrip("*& ")):].replace(" ", "")
            groups.setdefault(base, []).append(stars + d["name"])
    if not trivial_count:
        return text
    grouped = [f"{indent}{t} {', '.join(names)};" for t, names in groups.items()]
    candidate = "\n".join(lines[:start] + important + grouped + lines[end:])
    if len(candidate) <= int(limit):
        return candidate
    note = f"{indent}// {trivial_count} простых скалярных локальных переменных опущено"
    return "\n".join(lines[:start] + important + [note] + lines[end:])


def fit_code(text, limit):
    """Condense declarations, then clip head+tail to *limit* characters."""
    return clip_code(condense_declarations(text, limit), limit)


# ---------------------------------------------------------------------------
# String literals
# ---------------------------------------------------------------------------
def read_string_literal(ea):
    """Return a decoded string literal at *ea* or "" (IDA 9.x API)."""
    try:
        import ida_nalt
        flags = ida_bytes.get_flags(ea)
        if not ida_bytes.is_strlit(flags):
            return ""
        strtype = ida_nalt.get_str_type(ea)
        if strtype is None or strtype == -1 or strtype == getattr(ida_nalt, "BADADDR", -1):
            strtype = getattr(ida_nalt, "STRTYPE_C", 0)
        raw = ida_bytes.get_strlit_contents(ea, -1, strtype)
    except Exception:
        return ""
    if not raw:
        return ""
    if isinstance(raw, bytes):
        try:
            raw = raw.decode("utf-8", "ignore")
        except Exception:
            return ""
    return str(raw).replace("\x00", "").strip()


_FUNC_LIKE_RE = re.compile(r"\b[A-Za-z_][\w:]{2,}\s*\(\s*\)|\b[A-Z][a-z]+[A-Z]\w+::\w+|\b\w+::\w+")


def string_priority(s):
    """Lower is better: strings that name functions/classes come first."""
    if _FUNC_LIKE_RE.search(s):
        return 0
    if re.search(r"%[-+ #0]*\d*(?:\.\d+)?[sdifuxXpc]", s) or len(s) >= 12:
        return 1
    return 2


_AUTO_DATA_PREFIXES = (
    "def_", "jpt_", "loc_", "qword_", "dword_", "word_", "byte_", "off_", "unk_",
    "stru_", "asc_", "xmmword_", "ymmword_", "flt_", "dbl_", "algn_", "a",
)


def is_auto_data_name(name):
    n = str(name or "")
    for prefix in _AUTO_DATA_PREFIXES:
        if prefix == "a":
            # IDA string literal names: aSomeText / aFormatS (lowercase a + Capital)
            if len(n) > 1 and n[0] == "a" and n[1].isupper():
                return True
            continue
        if n.startswith(prefix):
            return True
    return False


def is_library_or_thunk(ea):
    """True for FLIRT library functions and thunks: no need to analyse/traverse them."""
    try:
        f = ida_funcs.get_func(ea)
        if not f:
            return False
        flags = int(f.flags)
        return bool(flags & (ida_funcs.FUNC_LIB | ida_funcs.FUNC_THUNK))
    except Exception:
        return False


_NOTABLE_MNEMONICS = (
    "cpuid", "rdtsc", "rdtscp", "rdrand", "rdseed", "syscall", "sysenter", "int ", "int3",
    "aes", "pclmul", "sha1", "sha256", "crc32", "xgetbv", "lock ", "xchg", "cmpxchg",
    "rol", "ror", "bswap", "popcnt", "lzcnt", "tzcnt", "bt ", "bts", "btr", "pshufb",
    "vpshufb", "pxor", "vpxor", "movdqa", "vmovdqa", "in ", "out ", "cli", "sti", "hlt",
    "invlpg", "wrmsr", "rdmsr", "mov cr", "mov dr", "ud2", "fs:", "gs:",
)


def get_notable_disasm(ea, max_lines=12):
    """Return only low-level instructions that Hex-Rays tends to hide or obscure."""
    f = ida_funcs.get_func(ea)
    if not f:
        return ""
    lines = []
    try:
        for h in idautils.FuncItems(f.start_ea):
            if not ida_bytes.is_code(ida_bytes.get_flags(h)):
                continue
            dis = ida_lines.tag_remove(idc.generate_disasm_line(h, 0) or "")
            low = dis.lower().strip()
            if not low:
                continue
            if any(low.startswith(m) or (m.endswith(":") and m in low) or (m.startswith("mov ") and low.startswith(m))
                   for m in _NOTABLE_MNEMONICS):
                lines.append(f"{h:#x}: {dis.split(';')[0].rstrip()}")
                if len(lines) >= max_lines:
                    break
    except Exception:
        pass
    return "\n".join(lines)


def count_code_lines(text):
    return sum(1 for line in str(text or "").splitlines() if line.strip())


def ident(name, fallback="ai_name"):
    name = re.sub(r"[^A-Za-z0-9_]", "_", str(name or "")).strip("_")
    if not name:
        return fallback
    if name[0].isdigit():
        name = "_" + name
    return name[:120]

def compute_func_hash(f):
    if not f:
        return "empty_func"
    hasher = hashlib.sha256()
    hasher.update(str(f.start_ea).encode())
    hasher.update(str(f.end_ea).encode())
    try:
        for h in idautils.FuncItems(f.start_ea):
            if ida_bytes.is_code(ida_bytes.get_flags(h)):
                hasher.update(str(h).encode())
                disasm = idc.generate_disasm_line(h, 0)
                if disasm:
                    hasher.update(disasm.encode())
    except Exception as e:
        log_msg("DEBUG", "Hash", f"Error computing function hash: {e}")
    return hasher.hexdigest()

def get_disasm_at(ea, max_lines=120):
    f = ida_funcs.get_func(ea)
    if not f:
        return ""
    lines = []
    try:
        for h in idautils.FuncItems(f.start_ea):
            if ida_bytes.is_code(ida_bytes.get_flags(h)):
                dis = ida_lines.tag_remove(idc.generate_disasm_line(h, 0) or "")
                if dis:
                    lines.append(f"{h:#x}: {dis}")
                    if len(lines) >= max_lines:
                        lines.append("; ... (truncated)")
                        break
    except Exception:
        pass
    return "\n".join(lines)

def get_pseudo_at(ea):
    if not hx_ok():
        return None, ""
    try:
        cf = ida_hexrays.decompile(ea)
        if not cf:
            return None, ""
        lines = [ida_lines.tag_remove(sl.line) for sl in cf.get_pseudocode()]
        return cf, "\n".join(lines)
    except Exception:
        return None, ""

def get_func_signature_and_args(ea, cf=None):
    """Extracts prototype, arguments, and local variable types."""
    proto = ""
    try:
        tif = ida_typeinf.tinfo_t()
        if ida_typeinf.guess_tinfo(tif, ea) or ida_nalt_tinfo(ea, tif):
            proto = str(tif)
    except Exception:
        pass

    lvars = []
    if cf is not None:
        try:
            for lv in cf.get_lvars():
                if lv.name:
                    lvars.append({
                        "name": lv.name,
                        "is_arg": bool(lv.is_arg_var),
                        "type": str(lv.type()),
                    })
        except Exception:
            pass
    return proto, lvars

def ida_nalt_tinfo(ea, tif):
    try:
        import ida_nalt
        return ida_nalt.get_tinfo(tif, ea)
    except Exception:
        return False

def get_callees(f):
    callees = set()
    try:
        for ea in idautils.FuncItems(f.start_ea):
            if ida_bytes.is_code(ida_bytes.get_flags(ea)):
                for xref in idautils.CodeRefsFrom(ea, 0):
                    callee_f = ida_funcs.get_func(xref)
                    if callee_f and callee_f.start_ea != f.start_ea:
                        callees.add(callee_f.start_ea)
    except Exception:
        pass
    return sorted(callees)

def get_callers(f, limit=8):
    callers = set()
    try:
        for xref in idautils.CodeRefsTo(f.start_ea, 0):
            caller_f = ida_funcs.get_func(xref)
            if caller_f and caller_f.start_ea != f.start_ea:
                callers.add(caller_f.start_ea)
                if len(callers) >= limit:
                    break
    except Exception:
        pass
    return [fname(ea) for ea in sorted(callers)]


def get_function_xrefs(f):
    """Return every xref pointing to the function entry, without an arbitrary cap."""
    if not f:
        return {"count": 0, "code_count": 0, "data_count": 0, "items": []}

    refs = []
    seen = set()
    try:
        for xr in idautils.XrefsTo(f.start_ea, 0):
            frm = int(xr.frm)
            key = (frm, int(xr.type))
            if key in seen:
                continue
            seen.add(key)
            caller = ida_funcs.get_func(frm)
            is_code = bool(getattr(xr, "iscode", False))
            refs.append({
                "from": frm,
                "from_name": fname(caller.start_ea) if caller else (ida_name.get_name(frm) or ""),
                "type": int(xr.type),
                "is_code": is_code,
            })
    except Exception as e:
        log_msg("DEBUG", "Xrefs", f"Failed to enumerate xrefs for {f.start_ea:#x}: {e}")

    refs.sort(key=lambda item: (item["from"], item["type"]))
    code_count = sum(1 for item in refs if item["is_code"])
    return {
        "count": len(refs),
        "code_count": code_count,
        "data_count": len(refs) - code_count,
        "items": refs,
    }

def get_callback_refs(f, limit=16):
    """Find function addresses referenced as data from instructions in a function.

    These are candidates for callbacks/vtables/function pointers, not proof that
    the target is invoked. The caller's pseudocode/disassembly must establish role.
    """
    found = {}
    if not f:
        return []
    try:
        for insn_ea in idautils.FuncItems(f.start_ea):
            if not ida_bytes.is_code(ida_bytes.get_flags(insn_ea)):
                continue
            for target in idautils.DataRefsFrom(insn_ea):
                target_func = ida_funcs.get_func(target)
                if not target_func or target_func.start_ea == f.start_ea:
                    continue
                found.setdefault(target_func.start_ea, set()).add(insn_ea)
                if len(found) >= limit:
                    break
            if len(found) >= limit:
                break
    except Exception as e:
        log_msg("DEBUG", "Callbacks", f"Failed to inspect function-pointer refs at {f.start_ea:#x}: {e}")
    return [
        {"ea": ea, "name": fname(ea), "sites": sorted(sites)}
        for ea, sites in sorted(found.items())
    ]


def get_address_escaped_locals(cf):
    """Return locals whose addresses escape in pseudocode (possible aggregates)."""
    if not cf:
        return []
    try:
        pseudo = "\n".join(ida_lines.tag_remove(sl.line) for sl in cf.get_pseudocode())
        lvars = {lv.name: lv for lv in cf.get_lvars() if getattr(lv, "name", "")}
    except Exception:
        return []
    # Hex-Rays prints address-of as "&v5" and bitwise AND as "a & b".
    names = set(re.findall(r"(?<![&\w)\]])&([A-Za-z_]\w*)", pseudo))
    result = []
    for name in sorted(names):
        lv = lvars.get(name)
        if not lv:
            continue
        item = {"name": name, "type": str(lv.type())}
        try:
            loc = lv.location
            if loc.is_stkoff():
                item["stack_offset"] = hex(int(loc.stkoff()))
        except Exception:
            pass
        result.append(item)
    return result[:16]

def extract_func_rich_context(ea, depth_level=1, code_char_limit=2400):
    """
    Collects targeted, non-bloated reverse engineering context for a function:
    - Pseudocode (or disassembly fallback if Hex-Rays fails)
    - Function signature, arguments, and struct/pointer types
    - Referenced strings & notable global variables
    - Direct callees (with meaningful names) and callers (xrefs)
    """
    f = ida_funcs.get_func(ea)
    if not f:
        return None

    name = fname(ea)
    cf, pseudo = get_pseudo_at(ea)
    source_type = "Hex-Rays" if (cf and pseudo) else "Disassembly"
    if pseudo:
        code_text = compact_pseudocode(pseudo)
    else:
        code_text = get_disasm_at(ea, max_lines=100 if depth_level >= 2 else 70)

    proto, lvars = get_func_signature_and_args(ea, cf)
    address_escaped_locals = get_address_escaped_locals(cf)
    args_str = ", ".join(f"{v['type']} {v['name']}" for v in lvars if v["is_arg"])
    struct_types = sorted({
        v["type"] for v in lvars
        if any(tok in v["type"] for tok in ("struct", "*", "_t", "class")) and "void *" not in v["type"]
    })[:8]

    strings = []
    globals_refs = []
    seen_drefs = set()
    try:
        items = list(idautils.FuncItems(f.start_ea))
    except Exception:
        items = []
    for h in items:
        try:
            drefs = list(idautils.DataRefsFrom(h))
        except Exception:
            continue
        for dref in drefs:
            if dref in seen_drefs:
                continue
            seen_drefs.add(dref)
            try:
                decoded = read_string_literal(dref)
                if decoded:
                    decoded = decoded[:120]
                    if decoded not in strings:
                        strings.append(decoded)
                    continue
                gname = ida_name.get_name(dref)
                if gname and gname not in globals_refs and not is_auto_data_name(gname):
                    globals_refs.append(gname)
            except Exception:
                continue
    # Stable sort: strings naming functions/classes first (e.g. "... in GetAttackSpeed()").
    strings.sort(key=string_priority)

    clipped_code = fit_code(code_text, code_char_limit) if pseudo else clip_code(code_text, code_char_limit)
    has_pseudo = source_type == "Hex-Rays"
    if has_pseudo:
        # Hex-Rays already prints string literals, named globals, the
        # prototype with argument names and local declarations with types.
        strings = [item for item in strings if item[:48] not in clipped_code]
        globals_refs = [item for item in globals_refs if item not in clipped_code]

    callee_eas = get_callees(f)
    callees_named = [fname(c) for c in callee_eas][:16]
    callers_named = get_callers(f, limit=16) if depth_level >= 1 else []
    xref_summary = get_function_xrefs(f) if depth_level >= 1 else {"count": 0, "code_count": 0, "data_count": 0, "items": []}
    callback_refs = get_callback_refs(f) if depth_level >= 3 else []
    callback_eas = [item["ea"] for item in callback_refs]

    # Low-level hints only: instructions Hex-Rays hides (cpuid, rdtsc, aes*, crc32, ...).
    disasm_hint = ""
    if depth_level >= 2 and pseudo:
        disasm_hint = get_notable_disasm(ea, max_lines=12)

    return {
        "ea": ea,
        "name": name,
        "is_auto": is_auto_generated_name(name),
        "is_library": is_library_or_thunk(ea),
        "source_type": source_type,
        "has_code": bool(code_text),
        "code": clipped_code,
        "code_lines": count_code_lines(code_text),
        "disasm_hint": disasm_hint,
        "prototype": "" if has_pseudo else proto,
        "args": "" if (has_pseudo or proto) else args_str,
        "struct_types": [] if has_pseudo else struct_types,
        "strings": strings[:8],
        "globals": globals_refs[:10],
        "callees": callees_named,
        "callee_eas": callee_eas,
        "callers": callers_named,
        "xref_summary": xref_summary,
        "address_escaped_locals": address_escaped_locals,
        "callback_refs": [f"{item['name']} @ {item['ea']:#x} (sites: {', '.join(hex(x) for x in item['sites'][:3])})" for item in callback_refs],
        "callback_eas": callback_eas,
    }

def _call_args(line, start):
    """Split the argument list starting at *start* (index of "(") into strings."""
    depth, cur, args = 0, [], []
    for ch in line[start:]:
        if ch == "(":
            depth += 1
            if depth == 1:
                continue
        elif ch == ")":
            depth -= 1
            if depth == 0:
                if "".join(cur).strip():
                    args.append("".join(cur).strip())
                return args
        elif ch == "," and depth == 1:
            args.append("".join(cur).strip())
            cur = []
            continue
        cur.append(ch)
    return args


_IDENT_RE = re.compile(r"\b[A-Za-z_]\w*\b")


def get_callsite_context(caller_ea, callee_ea, pseudo_text=None, escaped_locals=None,
                         max_sites=2, max_chars=520, lookback=15):
    """Return concrete caller-side evidence for one call-graph edge.

    For each of the first *max_sites* calls of the callee in the caller:
    - 2 statements before and 1 after the call (declarations and braces skipped);
    - the last assignment (within *lookback* lines) of every local passed to the call;
    - the declaration of aggregate/BYREF locals passed to the call.
    Lines are joined with " | ", call sites with " … ".
    """
    caller = ida_funcs.get_func(caller_ea)
    callee_name = fname(callee_ea)
    if not caller:
        return ""
    sites = []
    try:
        if pseudo_text is None:
            _, pseudo_text = get_pseudo_at(caller_ea)
        if pseudo_text:
            lines = [ln.strip() for ln in pseudo_text.splitlines()]
            decls = {}
            body_start = 0
            block = _find_decl_block(lines)
            if block:
                for line in lines[block[0]:block[1]]:
                    d = parse_decl_line(line)
                    if d:
                        decls[d["name"]] = d
                body_start = block[1]
            escaped = {item.get("name") for item in (escaped_locals or []) if item.get("name")}
            call_re = re.compile(rf"\b{re.escape(callee_name)}\b")
            noise = {"{", "}", "else", "do", ""}

            def is_stmt(i):
                return lines[i] not in noise and not parse_decl_line(lines[i]) and not lines[i].startswith("//")

            for idx in range(body_start, len(lines)):
                m = call_re.search(lines[idx])
                if not m:
                    continue
                picked = {idx}
                # context window: 2 statements before, 1 after
                j, got = idx - 1, 0
                while j >= body_start and got < 2:
                    if is_stmt(j):
                        picked.add(j)
                        got += 1
                    j -= 1
                j = idx + 1
                while j < len(lines) and j - idx <= 3:
                    if is_stmt(j):
                        picked.add(j)
                        break
                    j += 1
                # arguments passed to this call
                arg_names = []
                paren = lines[idx].find("(", m.end())
                if paren != -1 and not lines[idx][m.end():paren].strip():
                    for arg in _call_args(lines[idx], paren):
                        for name in _IDENT_RE.findall(arg):
                            if name not in arg_names and (name in decls or name in escaped or re.fullmatch(r"v\d+", name)):
                                arg_names.append(name)
                extra_decls = []
                for name in arg_names:
                    assign_re = re.compile(rf"(?:^|[^\w.>])\*?{re.escape(name)}\b(?:\[[^\]]*\]|\.\w+)*\s*(?:[-+*/|&^]|<<|>>)?=(?!=)")
                    for k in range(idx - 1, max(body_start, idx - lookback) - 1, -1):
                        if assign_re.search(lines[k]) and is_stmt(k):
                            picked.add(k)
                            break
                    d = decls.get(name)
                    if d and d["kind"] == "important" and (name in escaped or "BYREF" in d["raw"] or "[" in d["raw"]):
                        extra_decls.append(d["raw"])
                site_lines = extra_decls + [lines[k] for k in sorted(picked)]
                sites.append(" | ".join(site_lines))
                if len(sites) >= max_sites:
                    break
    except Exception:
        pass
    if not sites:
        try:
            for insn_ea in idautils.FuncItems(caller.start_ea):
                if not ida_bytes.is_code(ida_bytes.get_flags(insn_ea)):
                    continue
                if any((ida_funcs.get_func(t) and ida_funcs.get_func(t).start_ea == callee_ea)
                       for t in idautils.CodeRefsFrom(insn_ea, 0)):
                    dis = ida_lines.tag_remove(idc.generate_disasm_line(insn_ea, 0) or "")
                    sites.append(f"{insn_ea:#x}: {dis}")
                    if len(sites) >= max_sites:
                        break
        except Exception:
            pass
    text = " … ".join(sites)
    if len(text) > max_chars:
        text = text[:max_chars].rstrip() + " …"
    return text

def collect_call_graph(root_f, max_depth, max_funcs):
    """Traverse direct callees; at very-deep mode also follow data-referenced function pointers.

    Callback candidates are deliberately treated as lower-priority graph edges and
    remain labelled as candidates in the context supplied to the model.
    """
    nodes = []
    visited = set()
    queue = [(root_f.start_ea, 0, "root", None)]
    edge_contexts = {}
    max_depth = max(0, min(3, int(max_depth)))
    max_funcs = max(1, int(max_funcs))

    if max_depth <= 1:
        per_node_chars = 3000
    elif max_depth == 2:
        per_node_chars = 2300
    else:
        per_node_chars = 1800

    analysable = 0
    # Named/library/thunk functions are not sent to the model, so they do not
    # consume the user's node limit; a hard cap still bounds IDA-side work.
    hard_cap = max_funcs * 4
    while queue and analysable < max_funcs and len(nodes) < hard_cap:
        ea, depth, edge_kind, parent_ea = queue.pop(0)
        if ea in visited:
            continue
        visited.add(ea)
        is_lib = is_library_or_thunk(ea)
        if is_lib and depth > 0:
            # Library code and thunks: listed once, never analysed or traversed.
            nodes.append({
                "ea": ea, "name": fname(ea), "is_auto": False, "is_library": True,
                "source_type": "Library", "has_code": False, "code": "", "code_lines": 0,
                "strings": [], "callee_eas": [], "callback_eas": [], "depth": depth,
                "edge_kind": edge_kind, "address_escaped_locals": [],
            })
            continue
        ctx = extract_func_rich_context(ea, depth_level=max_depth, code_char_limit=per_node_chars)
        if not ctx:
            continue
        ctx["depth"] = depth
        ctx["edge_kind"] = edge_kind
        if parent_ea is not None:
            edge_contexts[ea] = (parent_ea, edge_kind)
        nodes.append(ctx)
        if ctx.get("is_auto") and (ctx.get("has_code") or ctx.get("strings")):
            analysable += 1

        if depth >= max_depth:
            continue
        for callee_ea in ctx["callee_eas"]:
            if callee_ea not in visited:
                queue.append((callee_ea, depth + 1, "direct_call", ea))
        if max_depth >= 3:
            for callback_ea in ctx.get("callback_eas", []):
                if callback_ea not in visited:
                    queue.append((callback_ea, depth + 1, "function_pointer_candidate", ea))

    node_by_ea = {node["ea"]: node for node in nodes}
    parent_pseudo_cache = {}
    for child_ea, (parent_ea, edge_kind) in edge_contexts.items():
        child = node_by_ea.get(child_ea)
        if not child:
            continue
        parent = node_by_ea.get(parent_ea)
        if not parent:
            continue
        if edge_kind == "direct_call":
            if parent_ea not in parent_pseudo_cache:
                _, parent_pseudo_cache[parent_ea] = get_pseudo_at(parent_ea)
            parent_pseudo = compact_pseudocode(parent_pseudo_cache[parent_ea]) if parent_pseudo_cache[parent_ea] else ""
            call_site = get_callsite_context(
                parent_ea, child_ea, parent_pseudo, parent.get("address_escaped_locals", [])
            )
            child["incoming_context"] = {
                "from": parent["name"],
                "kind": edge_kind,
                "call_site": call_site,
                # Only locals that really appear in the recovered call-site lines.
                "caller_address_escaped_locals": [
                    item for item in parent.get("address_escaped_locals", [])
                    if item.get("name") and re.search(rf"\b{re.escape(item['name'])}\b", call_site or "")
                ],
            }
        else:
            child["incoming_context"] = {
                "from": parent["name"],
                "kind": edge_kind,
                "call_site": "; ".join(item for item in parent.get("callback_refs", []) if child["name"] in item) or "",
                "caller_address_escaped_locals": [],
            }

    return nodes

def get_selected_variable_name():
    if not hx_ok():
        return "a1"
    try:
        widget = ida_kernwin.get_current_widget()
        if ida_kernwin.get_widget_type(widget) == ida_kernwin.BWN_PSEUDOCODE:
            vu = ida_hexrays.get_widget_vdui(widget)
            if vu and vu.cfunc and len(vu.cfunc.get_lvars()) > 0:
                for lv in vu.cfunc.get_lvars():
                    if lv.is_arg_var:
                        return lv.name
    except Exception:
        pass
    return "a1"


# ---------------------------------------------------------------------------
# IDA-style byte signatures ("48 8B 05 ? ? ? ? 48 85 C0")
# ---------------------------------------------------------------------------
def _operand_wildcards(insn, insn_ea):
    """Return a set of byte offsets (inside the instruction) that must be wildcarded.

    Wildcards: relative branch/call targets, RIP-relative / absolute memory
    addresses, immediates that are addresses or have fixups (relocations).
    Stack/struct displacements and plain constants stay concrete.
    """
    import ida_ua
    try:
        import ida_fixup
    except Exception:  # pragma: no cover
        ida_fixup = None
    size = int(insn.size)
    wild = set()
    for op in insn.ops:
        if op.type == ida_ua.o_void:
            break
        offb = int(getattr(op, "offb", 0) or 0)
        if offb <= 0 or offb >= size:
            continue
        has_fixup = False
        if ida_fixup is not None:
            try:
                has_fixup = bool(ida_fixup.exists_fixup(insn_ea + offb))
            except Exception:
                has_fixup = False
        if op.type in (ida_ua.o_near, ida_ua.o_far):
            n = size - offb
        elif op.type == ida_ua.o_mem:
            n = min(4, size - offb)
        elif op.type == ida_ua.o_imm:
            try:
                width = int(ida_ua.get_dtype_size(op.dtype))
            except Exception:
                width = 4
            value = int(getattr(op, "value", 0) or 0)
            is_addr = False
            try:
                is_addr = value > 0xFFFF and ida_bytes.is_mapped(value)
            except Exception:
                is_addr = False
            if not (has_fixup or is_addr):
                continue
            n = min(width, size - offb)
        elif has_fixup:
            n = min(4, size - offb)
        else:
            continue
        wild.update(range(offb, offb + max(0, n)))
    return wild


def _function_byte_tokens(f, max_insns=64):
    """[(ea, [tokens], disasm)] for the first instructions of *f*."""
    import ida_ua
    out = []
    ea = f.start_ea
    while ea < f.end_ea and len(out) < max_insns:
        insn = ida_ua.insn_t()
        size = ida_ua.decode_insn(insn, ea)
        if not size or size <= 0:
            break
        raw = ida_bytes.get_bytes(ea, size) or b""
        wild = _operand_wildcards(insn, ea)
        toks = ["?" if i in wild else f"{b:02X}" for i, b in enumerate(raw)]
        dis = ida_lines.tag_remove(idc.generate_disasm_line(ea, 0) or "").split(";")[0].rstrip()
        out.append((ea, toks, dis))
        ea += size
    return out


def _pattern_matches(pattern, limit=2):
    """Addresses where the IDA pattern occurs (at most *limit*)."""
    try:
        import ida_ida
        start, end = ida_ida.inf_get_min_ea(), ida_ida.inf_get_max_ea()
    except Exception:
        start, end = 0, ida_idaapi.BADADDR
    hits = []
    ea = start
    while len(hits) < limit:
        try:
            found = ida_bytes.find_bytes(pattern, ea, range_end=end)
        except TypeError:
            found = ida_bytes.find_bytes(pattern, ea, None, end)
        if found is None or found == ida_idaapi.BADADDR or found < ea:
            break
        hits.append(found)
        ea = found + 1
    return hits


def make_function_signature(f, min_concrete=6, max_insns=48):
    """Build the shortest unique IDA-style signature from the function start.

    Longer prefixes can only match fewer places, so the shortest unique prefix
    is found by binary search over the instruction count (~log2(N) DB scans).
    Returns {"pattern", "unique", "length", "insns", "matches", "listing"}.
    """
    if not f:
        return {}
    items = _function_byte_tokens(f, max_insns=max_insns)
    if not items:
        return {}

    def pattern_for(count):
        toks = [t for _, row, _ in items[:count] for t in row]
        while toks and toks[-1] == "?":
            toks.pop()
        return " ".join(toks)

    def unique(count):
        hits = _pattern_matches(pattern_for(count), limit=2)
        return len(hits) == 1 and hits[0] == f.start_ea

    lo = 1
    while lo < len(items) and sum(1 for t in pattern_for(lo).split() if t != "?") < min_concrete:
        lo += 1
    hi = len(items)
    if unique(hi):
        while lo < hi:
            mid = (lo + hi) // 2
            if unique(mid):
                hi = mid
            else:
                lo = mid + 1
        result = {"pattern": pattern_for(hi), "unique": True, "insns": hi, "matches": 1}
    else:
        pattern = pattern_for(hi)
        result = {"pattern": pattern, "unique": False, "insns": hi,
                  "matches": len(_pattern_matches(pattern, limit=5))}
    result["length"] = len(result["pattern"].split())
    shown = items[:min(len(items), max(result["insns"], 8), 24)]
    result["listing"] = "\n".join(f"{ea:#x}: {' '.join(toks):<36} {dis}" for ea, toks, dis in shown)
    return result
