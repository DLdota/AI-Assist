# -*- coding: utf-8 -*-
"""
Unified HTTP / Streaming / Non-Streaming LLM client for Ollama and OpenAI-compatible APIs.
Includes token accounting, cost calculation, finish_reason normalization, and retry logic.
"""
import io
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

# urllib3 is bundled with the plugin so the transport does not depend on the
# Python packages installed in IDA. It provides pooled, thread-safe HTTP(S).
_VENDOR_DIR = os.path.join(os.path.dirname(__file__), "_vendor")
if _VENDOR_DIR not in sys.path:
    sys.path.insert(0, _VENDOR_DIR)
import urllib3
from urllib3.util import Timeout as _HTTPTimeout

from .config import (
    calculate_cost,
    clean_host,
    estimate_tokens,
    get_active_profile,
    get_extra_api_payload,
    log_msg,
)
from .parser import AIResponseError, strip_thinking_blocks

# A small number of pooled connections avoids repeated TLS handshakes when
# DeepScan runs several functions concurrently. urllib3 PoolManager is thread-safe.
_POOL_LOCK = threading.Lock()
_POOLS = {}


def _get_http_pool(url, cfg=None):
    """Return a shared pool using the explicitly selected proxy policy."""
    cfg = cfg or {}
    proxy_mode = str(cfg.get("network_proxy_mode", "direct") or "direct").lower()
    proxy_url = None
    parsed = urlsplit(url)
    if proxy_mode == "system":
        proxies = urllib.request.getproxies()
        proxy_url = proxies.get(parsed.scheme) or proxies.get("all")
        if parsed.hostname and urllib.request.proxy_bypass(parsed.hostname):
            proxy_url = None
    elif proxy_mode == "custom":
        proxy_url = str(cfg.get("network_proxy_url", "") or "").strip() or None
        if not proxy_url:
            raise ValueError("Custom proxy mode is selected, but its URL is empty")
        proxy_parts = urlsplit(proxy_url)
        if proxy_parts.scheme not in ("http", "https") or not proxy_parts.hostname:
            raise ValueError("Custom proxy must be a valid http:// or https:// URL")
    else:
        proxy_url = None
    key = f"{proxy_mode}:{proxy_url or '<direct>'}"
    with _POOL_LOCK:
        pool = _POOLS.get(key)
        if pool is None:
            common = {"num_pools": 4, "maxsize": 6, "block": True, "cert_reqs": "CERT_REQUIRED"}
            pool = urllib3.ProxyManager(proxy_url, **common) if proxy_url else urllib3.PoolManager(**common)
            _POOLS[key] = pool
        return pool


class _HTTPResponseAdapter:
    """Expose urllib3's streaming response using the small urllib-style API used below."""
    def __init__(self, response):
        self._response = response
        self.headers = response.headers
        self.status = response.status
        self._closed = False
        self._consumed = False

    def read(self, amount=None):
        data = self._response.read(amt=amount, decode_content=True)
        if amount is None:
            self._consumed = True
        return data

    def __iter__(self):
        pending = b""
        try:
            for chunk in self._response.stream(amt=8192, decode_content=True):
                pending += chunk
                while b"\n" in pending:
                    line, pending = pending.split(b"\n", 1)
                    yield line + b"\n"
            if pending:
                yield pending
            self._consumed = True
        finally:
            if not self._consumed:
                self._response.close()

    def close(self):
        if not self._closed:
            self._closed = True
            if not self._consumed:
                self._response.close()
            self._response.release_conn()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()


def _open_with_retry(req, timeout, *, stage="HTTP", cfg=None, cancel_event=None, attempts=2):
    """Perform a pooled HTTP request; retry transient connection/TLS failures only."""
    last_error = None
    method = req.get_method()
    headers = dict(req.header_items())
    body = req.data
    for attempt in range(attempts):
        if cancel_event is not None and cancel_event.is_set():
            raise APIError("Запрос отменён пользователем")
        response = None
        try:
            pool = _get_http_pool(req.full_url, cfg)
            response = pool.request(
                method, req.full_url, body=body, headers=headers,
                preload_content=False, redirect=True, retries=False,
                timeout=_HTTPTimeout(connect=min(15, max(3, timeout)), read=timeout),
            )
            if response.status >= 400:
                error_body = response.read(decode_content=True)[:1200]
                status = response.status
                reason = response.reason or "HTTP error"
                response.release_conn()
                raise urllib.error.HTTPError(
                    req.full_url, status, reason, response.headers, io.BytesIO(error_body)
                )
            return _HTTPResponseAdapter(response)
        except urllib.error.HTTPError:
            raise
        except (urllib3.exceptions.HTTPError, OSError, TimeoutError) as exc:
            if response is not None:
                try:
                    response.release_conn()
                except Exception:
                    pass
            reason = str(exc)
            lower = reason.lower()
            retryable = isinstance(exc, (
                urllib3.exceptions.SSLError, urllib3.exceptions.ProtocolError,
                urllib3.exceptions.TimeoutError, urllib3.exceptions.NewConnectionError,
                urllib3.exceptions.MaxRetryError, urllib3.exceptions.ProxyError,
            )) or any(token in lower for token in (
                "unexpected_eof_while_reading", "eof occurred", "connection reset",
                "connection aborted", "remote end closed", "timed out", "timeout",
                "incompleteread", "ssl",
            ))
            last_error = exc
            if not retryable or attempt + 1 >= attempts:
                raise urllib.error.URLError(exc)
            delay = float(2 ** attempt)
            log_msg(
                "WARNING", stage,
                f"Временный сбой TLS/соединения: попытка {attempt + 1}/{attempts}; "
                f"повтор через {delay:.0f} с ({reason}).", cfg,
            )
            # The caller is always a worker thread (model-list refresh is also async).
            time.sleep(delay)
    raise urllib.error.URLError(last_error)


class APIError(Exception):
    def __init__(self, message, status_code=None, retryable=False, duration=0.0):
        super().__init__(message)
        self.status_code = status_code
        self.retryable = retryable
        self.duration = float(duration or 0.0)


def _fit_messages_to_context_budget(cfg, messages, max_output_tokens, stage="request"):
    """Fit a request conservatively without cutting code or the current user prompt.

    Only old chat-history turns may be removed. If the actual task context is still
    too large, fail clearly rather than silently truncating pseudocode/decompiler data.
    """
    mode, prof = get_active_profile(cfg)
    context_limit = int(
        (prof.get("context_length") or 8192) if mode == "cloud" else (prof.get("num_ctx") or 8192)
    )
    context_limit = max(1024, context_limit)
    usable_limit = int(context_limit * 0.90)
    output_limit = max(1, int(max_output_tokens))
    prepared = [dict(message) for message in messages]

    def input_estimate(items):
        serialized = "\n".join(
            f"{item.get('role', 'user')}: {item.get('content', '')}"
            for item in items
        )
        # Leave margin for message framing and the estimator's uncertainty.
        return int(estimate_tokens(serialized) * 1.15) + 8 * len(items)

    estimated_input = input_estimate(prepared)
    removed_turns = 0
    # Keep the system prompt and the latest user request intact. Trim only the
    # oldest conversational history, preferably as user/assistant pairs.
    while estimated_input + output_limit > usable_limit and len(prepared) > 2:
        history_count = len(prepared) - 2
        remove_count = 2 if history_count >= 2 else 1
        del prepared[1:1 + remove_count]
        removed_turns += remove_count
        estimated_input = input_estimate(prepared)

    if removed_turns:
        log_msg(
            "WARNING", stage,
            f"Pre-flight context guard removed {removed_turns} oldest chat-history message(s); "
            f"estimated_input={estimated_input}, context_limit={context_limit}.", cfg,
        )

    available_output = usable_limit - estimated_input
    if available_output < 512:
        raise APIError(
            f"Контекст запроса слишком большой: примерно {estimated_input} входных токенов "
            f"при доступном окне {context_limit}. Код и текущий вопрос не обрезались. "
            "Уменьши объём вспомогательного контекста или увеличь context_length/num_ctx.",
            retryable=False,
        )

    effective_output = min(output_limit, available_output)
    if effective_output < output_limit:
        log_msg(
            "WARNING", stage,
            f"Pre-flight context guard limited output budget: {output_limit} -> "
            f"{effective_output} tokens (estimated_input={estimated_input}, "
            f"usable_context={usable_limit}).", cfg,
        )
    return prepared, effective_output

def _deep_merge(base, extra):
    for k, v in extra.items():
        if k in base and isinstance(base[k], dict) and isinstance(v, dict):
            _deep_merge(base[k], v)
        else:
            base[k] = v
    return base

def _build_headers(cfg):
    mode, prof = get_active_profile(cfg)
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "User-Agent": "IDA-AI-Assistant/2.4",
    }
    if mode == "cloud":
        key = str(prof.get("api_key", "")).strip()
        if key:
            headers["Authorization"] = f"Bearer {key}"
    return headers

def _http_get_json(cfg, path, timeout=10):
    _, prof = get_active_profile(cfg)
    url = clean_host(prof["host"]) + path
    req = urllib.request.Request(url, headers=_build_headers(cfg), method="GET")
    try:
        with _open_with_retry(req, timeout, stage=f"Models {path}", cfg=cfg) as resp:
            raw = resp.read().decode("utf-8", "replace")
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")[:600]
        raise APIError(f"HTTP {e.code} ({path}): {body}", status_code=e.code)
    except urllib.error.URLError as e:
        raise APIError(f"Сервис недоступен по адресу {url}: {e.reason}")
    except Exception as e:
        raise APIError(f"Ошибка запроса ({path}): {e}")

def fetch_available_models(cfg):
    """Fetches model list from Ollama (/api/tags) or Cloud (/models) with graceful fallback."""
    mode, prof = get_active_profile(cfg)
    saved = list(prof.get("saved_models") or [])
    current = prof.get("model", "")
    if current and current not in saved:
        saved.insert(0, current)

    try:
        if mode == "cloud":
            data = _http_get_json(cfg, "/models", timeout=12)
            items = data.get("data") if isinstance(data, dict) else data
            if isinstance(items, list):
                ids = sorted({str(m.get("id") or m.get("name")) for m in items if isinstance(m, dict) and (m.get("id") or m.get("name"))})
                if ids:
                    return ids, True
            return saved, False
        else:
            data = _http_get_json(cfg, "/api/tags", timeout=6)
            models = sorted({str(m["name"]) for m in data.get("models", []) if m.get("name")})
            if models:
                return models, True
            return saved, False
    except Exception as e:
        log_msg("DEBUG", "Models", f"Could not fetch remote models ({mode}): {e}", cfg)
        return saved, False

def _extract_text_from_choice(choice, stage="unknown", cfg=None, allow_reasoning_fallback=False):
    """Extract text and reasoning from one response chunk. Never log per chunk."""
    if not isinstance(choice, dict):
        return "", ""

    msg = choice.get("message") or choice.get("delta") or {}
    
    content = ""
    reasoning = ""
    
    if isinstance(msg, dict):
        c = msg.get("content")
        if isinstance(c, str):
            content = c
        elif isinstance(c, list):
            content = "".join(str(part.get("text", "")) for part in c if isinstance(part, dict))
            
        r = msg.get("reasoning_content") or msg.get("reasoning") or choice.get("reasoning_content")
        if isinstance(r, str):
            reasoning = r
            
    if not content and isinstance(choice.get("text"), str):
        content = choice["text"]

    # Reasoning is diagnostic metadata, not the final answer. In JSON mode it must
    # never be substituted for message.content, otherwise hidden thoughts are parsed as JSON.
    if allow_reasoning_fallback and not content.strip() and reasoning.strip():
        content = reasoning

    return content, reasoning

def _cached_prompt_tokens(usage):
    """Prompt-cache hits reported by OpenAI-compatible providers."""
    if not isinstance(usage, dict):
        return 0
    details = usage.get("prompt_tokens_details") or {}
    for value in (
        details.get("cached_tokens") if isinstance(details, dict) else None,  # OpenAI, OpenRouter, Qwen
        usage.get("prompt_cache_hit_tokens"),                                  # DeepSeek
        usage.get("cached_tokens"),
        usage.get("cache_read_input_tokens"),                                  # Anthropic-style proxies
    ):
        try:
            if value:
                return int(value)
        except (TypeError, ValueError):
            continue
    return 0


def _normalize_finish_reason(raw_reason):
    if not raw_reason:
        return "stop"
    r = str(raw_reason).lower().strip()
    if r in ("length", "max_tokens", "token_limit"):
        return "length"
    if r in ("content_filter", "safety"):
        return "content_filter"
    return r

def chat_completion(
    cfg,
    messages,
    stage="unknown",
    chunk_callback=None,
    json_mode=False,
    cancel_event=None,
    max_output_override=None,
    stream=True,
    disable_reasoning=False,
    enable_reasoning=False,
):
    """
    Executes a chat completion request against Ollama or OpenAI-compatible Cloud API.
    Handles SSE streaming, non-streaming fallback, HTTP errors, token usage, and cost logging.
    """
    mode, prof = get_active_profile(cfg)
    model = prof.get("model", "")
    timeout = int(cfg.get("timeout", 300))
    prompt_text_joined = "\n".join(str(m.get("content", "")) for m in messages)

    if mode == "cloud":
        url = clean_host(prof["host"]) + "/chat/completions"
        max_tokens = int(max_output_override or prof.get("max_output_tokens", 2000))
        payload = {
            "model": model,
            "messages": messages,
            "temperature": float(prof.get("temperature", 0.2)),
            "max_tokens": max_tokens,
            "stream": bool(stream),
        }
        if stream:
            payload["stream_options"] = {"include_usage": True}
        if json_mode:
            payload["response_format"] = {"type": "json_object"}
        if disable_reasoning:
            # Reasoning tokens share the output budget on reasoning models.
            # Pseudocode analysis needs a compact final JSON, not a hidden CoT stream.
            payload["reasoning_effort"] = "none"
    else:
        url = clean_host(prof["host"]) + "/api/chat"
        max_tokens = int(max_output_override or prof.get("num_predict", 1500))
        payload = {
            "model": model,
            "messages": messages,
            "stream": bool(stream),
            "options": {
                "temperature": float(prof.get("temperature", 0.2)),
                "num_ctx": int(prof.get("num_ctx", 8192)),
                "num_predict": max_tokens,
            },
        }
        if json_mode:
            payload["format"] = "json"
        if disable_reasoning:
            payload["think"] = False
        elif enable_reasoning:
            payload["think"] = True
        elif prof.get("think") in ("true", "false"):
            payload["think"] = (prof["think"] == "true")

    extra_api = get_extra_api_payload(cfg)
    if extra_api:
        _deep_merge(payload, extra_api)

    # These per-task flags have higher priority than optional Extra API JSON.
    if mode == "cloud" and disable_reasoning:
        payload["reasoning_effort"] = "none"
    elif mode == "ollama" and disable_reasoning:
        payload["think"] = False
    elif mode == "ollama" and enable_reasoning:
        payload["think"] = True

    # Apply the guard after Extra API JSON so its overrides cannot silently bypass
    # the configured context window. Never truncate the current code/pseudocode.
    if mode == "cloud":
        requested_output = int(payload.get("max_tokens", max_tokens))
    else:
        requested_output = int((payload.get("options") or {}).get("num_predict", max_tokens))
    messages, effective_output = _fit_messages_to_context_budget(
        cfg, payload.get("messages", messages), requested_output, stage=stage
    )
    payload["messages"] = messages
    if mode == "cloud":
        payload["max_tokens"] = effective_output
    else:
        payload.setdefault("options", {})["num_predict"] = effective_output
    prompt_text_joined = "\n".join(str(m.get("content", "")) for m in messages)

    actual_model = payload.get("model", model)
    if mode == "cloud":
        actual_max_output = payload.get("max_tokens", max_tokens)
        reasoning_mode = payload.get("reasoning_effort") or "provider-default"
    else:
        actual_max_output = (payload.get("options") or {}).get("num_predict", max_tokens)
        reasoning_mode = f"think={payload.get('think', 'profile-default')}"
    log_msg("DEBUG", stage,
            f"Request config -> provider={mode}, model={actual_model}, "
            f"actual_max_output={actual_max_output}, "
            f"reasoning={reasoning_mode}, "
            f"stream={bool(stream)}, json_mode={bool(json_mode)}, "
            f"proxy_mode={cfg.get('network_proxy_mode', 'direct')}", cfg)

    headers = _build_headers(cfg)
    req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST")

    t0 = time.time()
    full_chunks = []
    finish_reason = "stop"
    prompt_tokens = None
    completion_tokens = None
    cached_tokens = 0
    reasoning_chars = 0
    content_chars = 0

    try:
        with _open_with_retry(req, timeout, stage=stage, cfg=cfg, cancel_event=cancel_event) as resp:
            content_type = (resp.headers.get("Content-Type") or "").lower()
            is_sse = stream and ("text/event-stream" in content_type or mode == "ollama")

            if not stream or (mode == "cloud" and "application/json" in content_type):
                # Non-streaming JSON response (or provider ignored stream=True)
                raw_body = resp.read().decode("utf-8", "replace")
                data = json.loads(raw_body) if raw_body else {}
                if mode == "cloud":
                    if "error" in data and data["error"]:
                        raise APIError(f"API Error: {data['error']}")
                    usage = data.get("usage") or {}
                    prompt_tokens = usage.get("prompt_tokens")
                    completion_tokens = usage.get("completion_tokens")
                    cached_tokens = _cached_prompt_tokens(usage) or cached_tokens
                    choices = data.get("choices") or []
                    if choices:
                        choice = choices[0]
                        finish_reason = _normalize_finish_reason(choice.get("finish_reason"))
                        content, reasoning = _extract_text_from_choice(
                            choice, stage=stage, cfg=cfg, allow_reasoning_fallback=False
                        )
                        reasoning_chars += len(reasoning)
                        content_chars += len(content)
                        log_msg("DEBUG", stage,
                                f"API Response Structure -> finish_reason={finish_reason}, "
                                f"content_len={len(content)}, reasoning_len={len(reasoning)}, "
                                f"choice_keys={list(choice.keys())}", cfg)
                        if content:
                            full_chunks.append(content)
                        if finish_reason == "length" and not content.strip():
                            log_msg("WARNING", stage,
                                    f"Model reached max_output_tokens ({actual_max_output}) without final content; "
                                    "the response will be rejected and retried with a larger budget.", cfg)
                else:
                    msg = data.get("message") or {}
                    ollama_content = msg.get("content", "")
                    ollama_reasoning = msg.get("thinking") or msg.get("reasoning", "")
                    full_chunks.append(ollama_content)
                    content_chars += len(ollama_content or "")
                    reasoning_chars += len(ollama_reasoning or "")
                    finish_reason = _normalize_finish_reason(data.get("done_reason"))
                    prompt_tokens = data.get("prompt_eval_count")
                    completion_tokens = data.get("eval_count")
                if chunk_callback and full_chunks:
                    chunk_callback("".join(full_chunks))
            else:
                # Line-by-line streaming reader (supports both SSE `data: ...` and Ollama NDJSON)
                for raw_line in resp:
                    if cancel_event and cancel_event.is_set():
                        finish_reason = "cancelled"
                        break
                    line = raw_line.decode("utf-8", "replace").strip()
                    if not line:
                        continue
                    if line == "data: [DONE]":
                        break
                    if line.startswith("data:"):
                        line = line[5:].strip()
                    if not line or line.startswith(":"):
                        continue

                    try:
                        chunk = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    if isinstance(chunk, dict) and chunk.get("error"):
                        raise APIError(f"Stream API Error: {chunk['error']}")

                    if mode == "cloud":
                        usage = chunk.get("usage") or {}
                        if usage:
                            if usage.get("prompt_tokens") is not None:
                                prompt_tokens = usage["prompt_tokens"]
                            if usage.get("completion_tokens") is not None:
                                completion_tokens = usage["completion_tokens"]
                            cached_tokens = _cached_prompt_tokens(usage) or cached_tokens
                        choices = chunk.get("choices") or []
                        if choices:
                            ch = choices[0]
                            
                            # --- СЮДА ВСТАВЛЯЕМ ВТОРОЙ ПУНКТ ---
                            piece, reasoning = _extract_text_from_choice(ch, stage=stage, cfg=cfg, allow_reasoning_fallback=False)
                            reasoning_chars += len(reasoning)
                            content_chars += len(piece)
                            
                            # Для стрима логируем и проверяем finish_reason, когда он приходит в чанке
                            if ch.get("finish_reason"):
                                finish_reason = _normalize_finish_reason(ch["finish_reason"])
                                # One final-chunk diagnostic per request; individual SSE chunks
                                # are intentionally not logged to avoid flooding IDA Output.
                                log_msg("DEBUG", stage, f"Stream completed -> finish_reason={finish_reason}", cfg)

                                if finish_reason == "length" and not piece.strip() and not full_chunks:
                                    log_msg("WARNING", stage, f"Model reached max_output_tokens ({actual_max_output}) during reasoning/generation without producing content. Increase max_output_tokens.", cfg)

                            if piece:
                                full_chunks.append(piece)
                                if chunk_callback:
                                    chunk_callback(piece)
                            # ------------------------------------
                            if ch.get("finish_reason"):
                                finish_reason = _normalize_finish_reason(ch["finish_reason"])
                    else:
                        msg = chunk.get("message") or {}
                        piece = msg.get("content", "")
                        reasoning_piece = msg.get("thinking") or msg.get("reasoning", "")
                        reasoning_chars += len(reasoning_piece or "")
                        content_chars += len(piece or "")
                        if piece:
                            full_chunks.append(piece)
                            if chunk_callback:
                                chunk_callback(piece)
                        if chunk.get("done", False):
                            finish_reason = _normalize_finish_reason(chunk.get("done_reason"))
                            prompt_tokens = chunk.get("prompt_eval_count", prompt_tokens)
                            completion_tokens = chunk.get("eval_count", completion_tokens)
                            break

    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")[:1000]
        # Некоторые OpenAI-совместимые эндпоинты отклоняют response_format={"type":"json_object"} с HTTP 400
        if e.code == 400 and json_mode and ("response_format" in body or "json_object" in body):
            log_msg("INFO", stage, "Provider rejected response_format=json_object (HTTP 400), retrying without response_format...", cfg)
            fallback_started = time.time()
            fallback_result = chat_completion(
                cfg, messages, stage=stage, chunk_callback=chunk_callback,
                json_mode=False, cancel_event=cancel_event,
                max_output_override=max_output_override, stream=stream,
                disable_reasoning=disable_reasoning, enable_reasoning=enable_reasoning,
            )
            # Include the rejected JSON-mode attempt in the total response duration.
            fallback_result[1]["duration"] += max(0.0, fallback_started - t0)
            return fallback_result
        if e.code == 400 and disable_reasoning and "reasoning_effort" in body.lower():
            log_msg("INFO", stage, "Provider does not support reasoning_effort=none; retrying without this optional parameter.", cfg)
            fallback_started = time.time()
            fallback_result = chat_completion(
                cfg, messages, stage=stage, chunk_callback=chunk_callback,
                json_mode=json_mode, cancel_event=cancel_event,
                max_output_override=max_output_override, stream=stream,
                disable_reasoning=False, enable_reasoning=enable_reasoning,
            )
            fallback_result[1]["duration"] += max(0.0, fallback_started - t0)
            return fallback_result
        retryable = e.code in (408, 429, 500, 502, 503, 504) or "SSL" in body or "EOF" in body
        raise APIError(f"HTTP {e.code}: {body}", status_code=e.code, retryable=retryable, duration=time.time() - t0)

    except (urllib.error.URLError, TimeoutError) as e:
        reason_str = str(e)
        retryable = True
        if "SSLError" in reason_str or "UNEXPECTED_EOF_WHILE_READING" in reason_str or "IncompleteRead" in reason_str:
            log_msg("WARNING", stage, f"SSL/Connection EOF detected ({reason_str}), marking as retryable...", cfg)
        raise APIError(f"Ошибка соединения с {url}: {reason_str}", retryable=retryable, duration=time.time() - t0)

    except urllib3.exceptions.HTTPError as e:
        # A chunked/SSE body can be cut after headers were received. This is a
        # transport failure and is safe to retry at the caller with a fresh request.
        reason_str = str(e)
        retryable = isinstance(e, (
            urllib3.exceptions.ProtocolError,
            urllib3.exceptions.ReadTimeoutError,
            urllib3.exceptions.ConnectTimeoutError,
            urllib3.exceptions.SSLError,
            urllib3.exceptions.NewConnectionError,
            urllib3.exceptions.ProxyError,
        ))
        if retryable:
            log_msg("WARNING", stage, f"Streaming transport interrupted ({reason_str}); request may be retried.", cfg)
        raise APIError(
            f"Ошибка потокового ответа ({stage}): {reason_str}",
            retryable=retryable, duration=time.time() - t0,
        )

    except APIError:
        raise

    except Exception as e:
        # Programming, parsing and unexpected local errors must not trigger an
        # expensive duplicate generation request.
        raise APIError(f"Ошибка запроса ({stage}): {e}", retryable=False, duration=time.time() - t0)

    dt = time.time() - t0
    raw_output = "".join(full_chunks)
    clean_output = strip_thinking_blocks(raw_output)

    estimated = False
    if prompt_tokens is None:
        prompt_tokens = estimate_tokens(prompt_text_joined)
        estimated = True
    if completion_tokens is None:
        completion_tokens = estimate_tokens(raw_output)
        estimated = True

    cached_tokens = max(0, min(int(cached_tokens or 0), int(prompt_tokens)))
    cost = calculate_cost(cfg, prompt_tokens, completion_tokens, cached_tokens)
    meta = {
        "provider": mode,
        "model": model,
        "stage": stage,
        "finish_reason": finish_reason,
        "prompt_tokens": int(prompt_tokens),
        "cached_prompt_tokens": cached_tokens,
        "completion_tokens": int(completion_tokens),
        "total_tokens": int(prompt_tokens) + int(completion_tokens),
        "tokens_estimated": estimated,
        "cost_usd": cost,
        "duration": dt,
        "reasoning_chars": reasoning_chars,
        "content_chars": content_chars,
    }
    return clean_output, meta
