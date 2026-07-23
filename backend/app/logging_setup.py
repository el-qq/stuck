"""Structured logging for the STUCK backend (Phase 2.5).

Design (see the security invariants in docs/ARCHITECTURE.md):
- stdlib ``logging`` only; one root handler (stdout by default, docker-friendly).
- Two formats: ``text`` (key-value) and ``json``; chosen via conf.
- Secret masking is CENTRAL, not ad-hoc: a ``SecretMaskingFilter`` attached to
  every handler (ours + pre-existing uvicorn ones) both
  (a) masks structured fields whose key looks sensitive, and
  (b) regex-scrubs rendered messages for password/cookie/authorization patterns.
  Passwords, NGFW cookies and ``stuck_session`` therefore cannot reach any log
  destination even if a future call site logs them by mistake.

Usage: ``log_event(logger, "event_name", key=value, ...)``.
"""

from __future__ import annotations

import json
import logging
import re
import sys
from datetime import UTC, datetime
from typing import Any

MASK = "***"

# Field names that are always masked in structured fields (substring match,
# case-insensitive). Covers password bodies, NGFW cookies, stuck_session ids.
_SENSITIVE_KEY_PARTS = (
    "password",
    "passwd",
    "pwd",
    "psw",
    "secret",
    "token",
    "cookie",
    "authorization",
    "session_id",
    "stuck_session",
)

# Regex scrubbing of already-rendered log messages (defence in depth: catches
# secrets embedded in plain strings, incl. httpx header dumps if ever enabled).
_SCRUB_PATTERNS: list[re.Pattern[str]] = [
    # password=..., "password": "...", psw='...', token=... etc.
    re.compile(
        r"(?i)((?:password|passwd|pwd|psw|secret|token|authorization)"
        r"[\"']?\s*[:=]\s*)(\"[^\"]*\"|'[^']*'|[^\s,;}\]]+)"
    ),
    # Known session cookie names: NGFW cookies and our own stuck_session.
    re.compile(
        r"(?i)((?:insecure-ideco-session|__Secure-ideco-[\w.-]*|stuck_session)"
        r"\s*=\s*)([^;,\s\"']+)"
    ),
    # Cookie / Set-Cookie header values ("Cookie: ..." or "set-cookie": "...").
    re.compile(r"(?i)((?:^|[\s\"'{,])(?:cookie|set-cookie)[\"']?\s*[:=]\s*)([^\r\n]+)"),
]


def scrub_text(text: str) -> str:
    """Mask secret-looking substrings in a rendered string."""
    for pat in _SCRUB_PATTERNS:
        text = pat.sub(lambda m: m.group(1) + MASK, text)
    return text


def _key_is_sensitive(key: str) -> bool:
    low = key.lower()
    return any(part in low for part in _SENSITIVE_KEY_PARTS)


def sanitize_value(key: str, value: Any) -> Any:
    """Mask a structured field by key name; recurse into containers."""
    if _key_is_sensitive(key):
        return MASK
    if isinstance(value, dict):
        return {k: sanitize_value(str(k), v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [sanitize_value(key, v) for v in value]
    if isinstance(value, str):
        return scrub_text(value)
    return value


class SecretMaskingFilter(logging.Filter):
    """Handler-level filter: no record leaves a handler with secrets intact."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except KeyError, TypeError, ValueError:  # pragma: no cover - malformed %-format args
            return True
        scrubbed = scrub_text(message)
        if scrubbed != message:
            record.msg = scrubbed
            record.args = ()
        fields = getattr(record, "stuck_fields", None)
        if isinstance(fields, dict):
            record.stuck_fields = {str(k): sanitize_value(str(k), v) for k, v in fields.items()}
        return True


def _iso(created: float) -> str:
    return datetime.fromtimestamp(created, tz=UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _fmt_value(value: Any) -> str:
    if isinstance(value, str) and (" " in value or "=" in value or '"' in value):
        return json.dumps(value, ensure_ascii=False)
    if value is None:
        return "-"
    return str(value)


class KeyValueFormatter(logging.Formatter):
    """``2026-07-09T09:00:00.000Z INFO stuck.access request method=GET ...``"""

    def format(self, record: logging.LogRecord) -> str:
        parts = [_iso(record.created), record.levelname, record.name, record.getMessage()]
        fields = getattr(record, "stuck_fields", None)
        if isinstance(fields, dict):
            parts.extend(f"{k}={_fmt_value(v)}" for k, v in fields.items())
        out = " ".join(parts)
        if record.exc_info:
            out += "\n" + self.formatException(record.exc_info)
        return out


class JsonFormatter(logging.Formatter):
    """One JSON object per line."""

    def format(self, record: logging.LogRecord) -> str:
        doc: dict[str, Any] = {
            "ts": _iso(record.created),
            "level": record.levelname,
            "logger": record.name,
            "event": record.getMessage(),
        }
        fields = getattr(record, "stuck_fields", None)
        if isinstance(fields, dict):
            for k, v in fields.items():
                doc.setdefault(k, v)
        if record.exc_info:
            doc["exc"] = self.formatException(record.exc_info)
        return json.dumps(doc, ensure_ascii=False, default=str)


def log_event(
    logger: logging.Logger,
    event: str,
    *,
    level: int = logging.INFO,
    exc_info: Any = None,
    **fields: Any,
) -> None:
    """Emit a structured event; fields are sanitized by the handler filter."""
    logger.log(level, event, exc_info=exc_info, extra={"stuck_fields": fields})


_configured = False


def configure_logging(level: str, fmt: str, log_file: str) -> None:
    """Install the root handler with masking. Idempotent."""
    global _configured
    if _configured:
        return
    _configured = True

    handler: logging.Handler
    if log_file:
        handler = logging.FileHandler(log_file, encoding="utf-8")
    else:
        handler = logging.StreamHandler(sys.stdout)
    formatter: logging.Formatter = JsonFormatter() if fmt.lower() == "json" else KeyValueFormatter()
    handler.setFormatter(formatter)
    handler.addFilter(SecretMaskingFilter())

    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    root.addHandler(handler)

    # Defence in depth: uvicorn installs its own handlers before importing the
    # app; make sure anything they emit is scrubbed too.
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        for h in logging.getLogger(name).handlers:
            if not any(isinstance(f, SecretMaskingFilter) for f in h.filters):
                h.addFilter(SecretMaskingFilter())

    # httpx/httpcore INFO logs each request URL; keep them quiet (we log NGFW
    # calls ourselves) and scrubbed via root propagation anyway.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
