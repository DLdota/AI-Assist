# -*- coding: utf-8 -*-
"""
Configuration, logging, provider profiles, migration, and pricing logic.
"""
import datetime
import json
import os
import re
import ida_diskio
import ida_kernwin

PLUGIN_NAME = "AI Assistant"
FORM_CAPTION = "AI Assistant (Advanced)"
ACTION_PREFIX = "ollama_ai_adv:"
NETNODE = "$ ollama_ai_advanced_v24"

DEFAULT_OLLAMA_CFG = {
    "host": "http://127.0.0.1:11434",
    "model": "qwen3:8b",
    "num_ctx": 8192,
    "num_predict": 1500,
    "temperature": 0.2,
    "think": "false",
    "saved_models": ["qwen3:8b"],
}

DEFAULT_CLOUD_CFG = {
    "provider_name": "OpenAI-Compatible",
    "host": "https://api.openai.com/v1",
    "api_key": "",
    "model": "gpt-4o-mini",
    "context_length": 128000,
    "max_output_tokens": 2000,
    "temperature": 0.2,
    "input_cost_per_1m": 0.15,
    "output_cost_per_1m": 0.60,
    "cached_input_cost_per_1m": 0.0,  # 0 = same as input price
    "saved_models": ["gpt-4o-mini"],
    "models_by_host": {},
}

DEFAULT_CFG = {
    "config_version": 2,
    "active_mode": "ollama",  # "ollama" | "cloud"
    "ollama": dict(DEFAULT_OLLAMA_CFG),
    "cloud": dict(DEFAULT_CLOUD_CFG),
    "timeout": 300,
    "language": "Russian",  # model response language
    "interface_language": "Russian",
    "deep_output_limits": {"0": 1800, "1": 10000, "2": 16000, "3": 24000},
    "max_code_chars": 6000,
    "deep_depth": 1,
    # Chat defaults to fast answers; users can opt into model reasoning in Settings.
    "chat_reasoning": False,
    # Hard cap for one chat answer (reasoning + text); protects against runaway reasoning.
    "chat_max_output_tokens": 8192,
    # Code budget for version comparison in chat (both versions, characters).
    "compare_max_code_chars": 40000,
    # Avoid inheriting a broken Windows/system proxy unless the user opts in.
    "network_proxy_mode": "direct",  # direct | system | custom
    "network_proxy_url": "",
    "max_deep_funcs": 15,
    "theme": "Dark",          # pseudocode syntax theme: Dark | Light | Midnight
    "ui_theme": "Light",      # interface theme (independent from IDA): Light | Dark
    "debug": True,
    "custom_prompt": "",
    "extra_api_json": "{}",
}

def cfg_path():
    return os.path.join(ida_diskio.get_user_idadir(), "ollama_ai_advanced.json")

def clean_host(url_str, fallback="http://127.0.0.1:11434"):
    if not url_str:
        return fallback
    s = str(url_str).strip()
    s = re.sub(r"^\[(.*)\]\(.*\)$", r"\1", s)
    s = s.strip('`"\'[]()')
    if not s.startswith("http://") and not s.startswith("https://"):
        s = "http://" + s
    return s.rstrip("/")

def _deep_merge(base, extra):
    for k, v in extra.items():
        if k in base and isinstance(base[k], dict) and isinstance(v, dict):
            _deep_merge(base[k], v)
        else:
            base[k] = v
    return base

def _migrate_v1_to_v2(raw):
    """Migrates legacy flat v1 configuration into separate ollama & cloud profiles."""
    cfg = json.loads(json.dumps(DEFAULT_CFG))
    old_provider = str(raw.get("provider", "ollama")).strip().lower()
    old_host = clean_host(raw.get("host", ""))
    old_model = str(raw.get("model", "")).strip()

    is_cloud = (
        old_provider == "openai_compatible"
        or "/v1" in old_host.lower()
        or any(h in old_host.lower() for h in ("openrouter", "polza", "openai", "groq", "deepseek", "together", "mistral"))
    )

    if is_cloud:
        cfg["active_mode"] = "cloud"
        if old_host:
            cfg["cloud"]["host"] = old_host
        if raw.get("api_key"):
            cfg["cloud"]["api_key"] = str(raw["api_key"]).strip()
        if old_model:
            cfg["cloud"]["model"] = old_model
            cfg["cloud"]["saved_models"] = [old_model]
        if "temperature" in raw:
            cfg["cloud"]["temperature"] = float(raw["temperature"])
        if "num_predict" in raw:
            cfg["cloud"]["max_output_tokens"] = int(raw["num_predict"])
    else:
        cfg["active_mode"] = "ollama"
        if old_host:
            cfg["ollama"]["host"] = old_host
        if old_model:
            cfg["ollama"]["model"] = old_model
            cfg["ollama"]["saved_models"] = [old_model]
        if "temperature" in raw:
            cfg["ollama"]["temperature"] = float(raw["temperature"])
        if "num_ctx" in raw:
            cfg["ollama"]["num_ctx"] = int(raw["num_ctx"])
        if "num_predict" in raw:
            cfg["ollama"]["num_predict"] = int(raw["num_predict"])
        if "think" in raw:
            cfg["ollama"]["think"] = str(raw["think"])

    for shared_key in ("timeout", "language", "interface_language", "deep_output_limits", "max_code_chars", "deep_depth", "max_deep_funcs", "theme", "ui_theme", "debug", "custom_prompt", "extra_api_json"):
        if shared_key in raw:
            cfg[shared_key] = raw[shared_key]

    return cfg

_THEME_ALIASES = {
    "light": "Light", "светлая": "Light", "浅色": "Light",
    "dark": "Dark", "тёмная": "Dark", "темная": "Dark", "深色": "Dark",
    "midnight": "Midnight",
}


def normalize_theme_name(value, allowed, default):
    """Map a stored theme name (possibly a translated label) to its key."""
    name = _THEME_ALIASES.get(str(value or "").strip().lower(), str(value or ""))
    return name if name in allowed else default


def load_cfg():
    cfg = json.loads(json.dumps(DEFAULT_CFG))
    migrated = False
    try:
        with open(cfg_path(), "r", encoding="utf-8") as fh:
            raw = json.load(fh)
            if isinstance(raw, dict):
                if raw.get("config_version", 1) < 2 or "ollama" not in raw:
                    cfg = _migrate_v1_to_v2(raw)
                    migrated = True
                else:
                    _deep_merge(cfg, raw)
    except FileNotFoundError:
        pass
    except Exception:
        pass

    cfg["ollama"]["host"] = clean_host(cfg["ollama"].get("host"), "http://127.0.0.1:11434")
    cfg["cloud"]["host"] = clean_host(cfg["cloud"].get("host"), "https://api.openai.com/v1")
    if cfg.get("interface_language") not in ("Russian", "English", "Chinese"):
        cfg["interface_language"] = "Russian"
    limits = cfg.get("deep_output_limits") or {}
    if not isinstance(limits, dict):
        limits = {}
    defaults = {"0": 1800, "1": 10000, "2": 16000, "3": 24000}
    for key, default in defaults.items():
        try:
            limits[key] = max(256, min(65536, int(limits.get(key, default))))
        except (TypeError, ValueError):
            limits[key] = default
    cfg["deep_output_limits"] = limits
    if cfg.get("active_mode") not in ("ollama", "cloud"):
        cfg["active_mode"] = "ollama"
    cfg["theme"] = normalize_theme_name(cfg.get("theme"), ("Dark", "Light", "Midnight"), "Dark")
    cfg["ui_theme"] = normalize_theme_name(cfg.get("ui_theme"), ("Light", "Dark"), "Light")

    if migrated:
        save_cfg(cfg)
    return cfg

def save_cfg(cfg):
    try:
        cfg["ollama"]["host"] = clean_host(cfg["ollama"].get("host"), "http://127.0.0.1:11434")
        cfg["cloud"]["host"] = clean_host(cfg["cloud"].get("host"), "https://api.openai.com/v1")
        with open(cfg_path(), "w", encoding="utf-8") as fh:
            json.dump(cfg, fh, indent=2, ensure_ascii=False)
    except Exception as e:
        log_msg("ERROR", "Config", f"Cannot save config: {e}")

def get_active_profile(cfg):
    mode = cfg.get("active_mode", "ollama")
    return mode, cfg.get(mode, cfg["ollama"])

def log_msg(level, stage, text, cfg=None):
    if cfg is None:
        cfg = load_cfg()
    if level == "DEBUG" and not cfg.get("debug", False):
        return
    ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    mode, prof = get_active_profile(cfg)
    model = prof.get("model", "unknown")
    prefix = f"[AI {level}] [{stage}] ({mode}:{model}) ({ts})"
    ida_kernwin.msg(f"{prefix} {text}\n")

def get_language_instruction(cfg):
    lang = cfg.get("language", "Russian")
    return (
        f"LANGUAGE RULE: All human-readable explanations, descriptions, purposes, reasons, statuses, "
        f"and statistics MUST be written in {lang}. Keep original spelling for all technical identifiers, "
        f"function names, API names, variable names, types, constants, and technical terms."
    )

def get_custom_prompt_instruction(cfg):
    return str(cfg.get("custom_prompt", "") or "").strip()

def get_extra_api_payload(cfg):
    raw = str(cfg.get("extra_api_json", "") or "").strip()
    if not raw or raw == "{}":
        return {}
    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            return data
        return {}
    except Exception:
        return {}

def estimate_tokens(text):
    """Conservative fallback token estimator (~3.5 chars per token for mixed code/Russian)."""
    if not text:
        return 0
    return max(1, int(len(str(text)) / 3.5))

def calculate_cost(cfg, prompt_tokens, completion_tokens, cached_tokens=0):
    """Cost of a request; cache hits are billed at the cached input price.

    ``cached_input_cost_per_1m`` = 0 means the provider has no separate cache
    price, so cached tokens are billed as ordinary input.
    """
    mode, prof = get_active_profile(cfg)
    if mode != "cloud":
        return 0.0
    in_price = float(prof.get("input_cost_per_1m", 0.0) or 0.0)
    out_price = float(prof.get("output_cost_per_1m", 0.0) or 0.0)
    cached_price = float(prof.get("cached_input_cost_per_1m", 0.0) or 0.0) or in_price
    cached = max(0, min(int(cached_tokens or 0), int(prompt_tokens or 0)))
    fresh = int(prompt_tokens or 0) - cached
    return ((fresh * in_price) + (cached * cached_price) + (completion_tokens * out_price)) / 1_000_000.0
