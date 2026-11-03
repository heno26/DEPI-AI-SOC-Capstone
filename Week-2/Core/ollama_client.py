"""Minimal local Ollama client (standard library only).

Safety properties:
  * Only loopback hosts are accepted (logs never leave the machine).
  * System proxies are bypassed for the local call.
  * Models are never switched silently; failures are raised with clear messages.
  * One controlled retry (same model) only for repeat-limit/empty-output failures;
    every attempt and its settings are recorded.
"""
import json
import socket
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from urllib.parse import urlparse

import config


class OllamaError(Exception):
    def __init__(self, message, attempts=None):
        super().__init__(message)
        self.attempts = attempts or []


class OllamaNotRunning(OllamaError):
    pass


class ModelNotInstalled(OllamaError):
    pass


class GenerationFailed(OllamaError):
    def __init__(self, message, status=None, body="", attempts=None):
        super().__init__(message, attempts)
        self.status = status
        self.body = body

    @property
    def repeat_limit(self):
        return "token repeat limit" in (self.body or "").lower() or "token repeat limit" in str(self).lower()


class GenerationTimeout(OllamaError):
    pass


class EmptyResponse(OllamaError):
    pass


@dataclass
class GenerationResult:
    text: str
    model: str
    options_used: dict
    attempts: list = field(default_factory=list)
    done_reason: str = ""
    eval_count: int = 0
    eval_duration_ns: int = 0
    total_duration_ns: int = 0
    wall_seconds: float = 0.0

    @property
    def truncated(self):
        return self.done_reason == "length"

    @property
    def tokens_per_second(self):
        if self.eval_duration_ns:
            return round(self.eval_count / (self.eval_duration_ns / 1e9), 2)
        return None

    @property
    def retry_used(self):
        return len(self.attempts) > 1


def _base_url(url=None):
    url = url or config.OLLAMA_URL
    host = urlparse(url).hostname
    if host not in ("127.0.0.1", "localhost", "::1"):
        raise OllamaError(
            f"Refusing non-local Ollama host '{host}'. This project only sends security data to "
            "a loopback Ollama server (127.0.0.1 / localhost)."
        )
    return url.rstrip("/")


def _http(path, payload=None, timeout=30, url=None):
    base = _base_url(url)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(base + path, data=data, headers={"Content-Type": "application/json"})
    try:
        with opener.open(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode("utf-8", "replace")
        except Exception:
            pass
        if e.code == 404 and "not found" in body.lower():
            raise ModelNotInstalled(f"Ollama reports the model was not found: {body.strip()[:200]}")
        raise GenerationFailed(f"Ollama HTTP {e.code}: {body.strip()[:300]}", status=e.code, body=body)
    except (socket.timeout, TimeoutError):
        raise GenerationTimeout(f"Ollama did not answer within {timeout}s.")
    except urllib.error.URLError as e:
        if isinstance(e.reason, (socket.timeout, TimeoutError)):
            raise GenerationTimeout(f"Ollama did not answer within {timeout}s.")
        raise OllamaNotRunning(
            "Cannot reach Ollama at " + base + ". Start it (open the Ollama app or run `ollama serve`) "
            f"and try again. Detail: {e.reason}"
        )
    except (ConnectionError, OSError) as e:
        raise OllamaNotRunning(f"Cannot reach Ollama at {base}: {e}")
    except json.JSONDecodeError as e:
        raise GenerationFailed(f"Ollama returned invalid JSON: {e}")


def installed_models(url=None):
    data = _http("/api/tags", timeout=10, url=url)
    return [m.get("name", "") for m in data.get("models", [])]


def resolve_model(model, installed):
    if model in installed:
        return model
    if ":" not in model and model + ":latest" in installed:
        return model + ":latest"
    return None


def check_environment(url=None):
    """Return a status dict. Never raises."""
    status = {"server_up": False, "version": None, "installed": [], "primary": None, "backup": None, "error": None}
    try:
        status["installed"] = installed_models(url)
        status["server_up"] = True
        try:
            status["version"] = _http("/api/version", timeout=5, url=url).get("version")
        except OllamaError:
            pass
    except OllamaError as e:
        status["error"] = str(e)
        return status
    status["primary"] = resolve_model(config.PRIMARY_MODEL, status["installed"])
    status["backup"] = resolve_model(config.BACKUP_MODEL, status["installed"])
    return status


def generate(prompt, model=None, options=None, timeout=None, retries=None, url=None):
    """Run one generation. Raises an OllamaError subclass on failure (with .attempts)."""
    model = model or config.PRIMARY_MODEL
    base_opts = dict(config.GENERATION)
    if options:
        base_opts.update({k: v for k, v in options.items() if v is not None})
    timeout = timeout or config.REQUEST_TIMEOUT_S
    retries = config.MAX_RETRIES if retries is None else retries

    installed = installed_models(url)  # raises OllamaNotRunning if server is down
    resolved = resolve_model(model, installed)
    if not resolved:
        raise ModelNotInstalled(
            f"Model '{model}' is not installed. Run: ollama pull {model}   (installed: {', '.join(installed) or 'none'})"
        )

    attempts = []
    for i in range(retries + 1):
        opts = dict(base_opts)
        if i > 0:
            opts.update(config.RETRY_OVERRIDES)
        payload = {"model": resolved, "prompt": prompt, "stream": False,
                   "keep_alive": config.KEEP_ALIVE, "options": opts}
        t0 = time.time()
        rec = {"attempt": i + 1, "model": resolved, "options": opts}
        try:
            data = _http("/api/generate", payload, timeout=timeout, url=url)
            text = (data.get("response") or "").strip()
            if not text:
                raise EmptyResponse("Model returned an empty response.")
            rec.update(outcome="success", seconds=round(time.time() - t0, 2))
            attempts.append(rec)
            return GenerationResult(
                text=text, model=resolved, options_used=opts, attempts=attempts,
                done_reason=data.get("done_reason", ""), eval_count=data.get("eval_count", 0) or 0,
                eval_duration_ns=data.get("eval_duration", 0) or 0,
                total_duration_ns=data.get("total_duration", 0) or 0,
                wall_seconds=round(time.time() - t0, 2),
            )
        except (GenerationFailed, EmptyResponse) as e:
            rec.update(outcome="failed", error=str(e)[:300], seconds=round(time.time() - t0, 2))
            attempts.append(rec)
            retryable = isinstance(e, EmptyResponse) or getattr(e, "repeat_limit", False)
            if retryable and i < retries:
                continue
            e.attempts = attempts
            raise
        except OllamaError as e:
            rec.update(outcome="failed", error=str(e)[:300], seconds=round(time.time() - t0, 2))
            attempts.append(rec)
            e.attempts = attempts
            raise
