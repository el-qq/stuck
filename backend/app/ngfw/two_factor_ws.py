"""WebSocket client for the NGFW second-factor (2FA) challenge.

The backend is the ONLY party that talks to NGFW: the browser never opens this
socket. After a provisional password login whose ``whoami`` is blocked awaiting
a second factor, the backend opens ``wss://<host>:<port>/web/two_factor/challenge``
with the same provisional NGFW cookies, relays the admin's code, and interprets
the result. See docs/source/mfa2-plan.md §3 for the observed protocol and
docs/NGFW_API_NOTES.md for the recorded assumptions.

Observed protocol (mfa2-plan.md §3). NOTE: the client sends ``2fa_start`` FIRST
to kick off the challenge — the server stays silent until it receives it (a
timed-out ``recv`` right after connect means we forgot to send it):
    client → {"type": "2fa_start",     "payload": {}}
    server → {"type": "2fa_challenge", "payload": {"message": "<optional hint>"}}
    client → {"type": "2fa_challenge", "payload": {"2fa_code": "123123"}}
    error  → {"type": "2fa_error",     "payload": {"message": "...",
                                                    "can_retry": true|false}}
    success → {"type": "2fa_success", "payload": {}}  (confirmed on live NGFW).
              A clean socket close with no prior error is also accepted as a
              success candidate; either way ``whoami`` is re-read and
              ``blocked_flags == 0`` remains the source of truth.

Transport rules (AGENTS.md #10, mfa2-plan.md §Инварианты):
- Reuse the SAME TLS decision as the HTTP client (``Settings.ngfw_verify`` /
  ``STUCK_NGFW_CA_BUNDLE``).
- The ``wss://`` host/port must pass the SAME allowlist/CIDR check as HTTP via
  ``client._enforce_current_access`` BEFORE the socket is opened (fail-closed).
- Cookies, codes and raw payloads are SECRET: never log them (log only the
  message ``type`` and timing, like ``client._log_call``).
"""

from __future__ import annotations

import asyncio
import json
import logging
import ssl
import time
from dataclasses import dataclass
from typing import Any

import websockets
from websockets.exceptions import (
    ConnectionClosed,
    ConnectionClosedError,
    ConnectionClosedOK,
    InvalidHandshake,
    InvalidStatus,
)

from ..config import get_settings
from ..errors import StuckError
from ..logging_setup import log_event
from .client import _NGFW_COOKIE_PREFIXES, _enforce_current_access

_ws_log = logging.getLogger("stuck.ngfw.2fa")

# --- Message-type vocabulary (single source of truth) ------------------------
# Keep every literal here so the protocol lives in one auditable place.
MSG_START = "2fa_start"
MSG_CHALLENGE = "2fa_challenge"
MSG_ERROR = "2fa_error"
# NGFW aborts a challenge it will not fulfil (e.g. a locked account) with this,
# often ~10-15s after an initial error. Treated as a terminal, like an error.
MSG_CANCELLED = "2fa_cancelled"

# Confirmed on live NGFW: a correct code yields {"type": "2fa_success", ...}.
# Kept as a single named constant so the vocabulary stays in one auditable place.
MSG_SUCCESS = "2fa_success"

# Internal sentinel returned by recv_typed() for a clean socket close with no
# prior error frame. NOT a wire value -- never sent and never expected from NGFW.
# Defensive fallback only (the confirmed happy path is an explicit MSG_SUCCESS
# frame): callers treat it as a success candidate, then confirm by re-reading
# whoami (blocked_flags == 0), so a bare close cannot forge a login.
MSG_CLOSED = "__closed__"

# The JSON field the client sends the code under (server contract, §3).
CODE_FIELD = "2fa_code"

# NGFW path for the challenge socket (host/port are prepended by the caller).
CHALLENGE_PATH = "/web/two_factor/challenge"


def _log_ws(server: str, event: str, start: float, *, status: str | None = None, error: str | None = None) -> None:
    """Log one 2FA WS operation: event, status/type (or error), duration.

    Never logs cookies, codes or raw payloads -- only the message type/outcome
    and timing (mirrors ``client._log_call``).
    """
    log_event(
        _ws_log,
        f"ngfw_2fa_{event}",
        level=logging.WARNING if error else logging.INFO,
        server=server,
        status=status,
        error=error,
        duration_ms=round((time.perf_counter() - start) * 1000, 1),
    )


def _build_ssl_context(verify: bool | str) -> ssl.SSLContext:
    """Mirror the HTTP client's TLS decision (``Settings.ngfw_verify``) for wss://.

    ``verify`` is the same value passed to httpx: ``False`` (self-signed NGFW,
    the default), a CA-bundle path, or ``True``. Never diverge from the HTTP
    client's trust decision (mfa2-plan.md §Инварианты).
    """
    if verify is False:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    if isinstance(verify, str) and verify:
        return ssl.create_default_context(cafile=verify)
    return ssl.create_default_context()


@dataclass(frozen=True)
class TwoFactorMessage:
    """A parsed, non-secret view of one inbound challenge frame.

    ``type`` is one of the ``MSG_*`` constants (or an unknown string, tolerated).
    ``message`` is the optional human hint/error text NGFW may attach. ``can_retry``
    is only meaningful for :data:`MSG_ERROR` frames. The raw payload is
    deliberately NOT retained beyond these safe fields.
    """

    type: str
    message: str | None = None
    can_retry: bool = False

    @property
    def is_error(self) -> bool:
        return self.type == MSG_ERROR

    @property
    def is_success(self) -> bool:
        """True on the confirmed explicit ``2fa_success`` frame.

        Callers ALSO treat a clean socket close with no prior error as a
        success candidate (``type == MSG_CLOSED``, defensive fallback) and then
        confirm via a fresh ``whoami`` (``blocked_flags == 0``); this property
        alone only recognizes the explicit success type.
        """
        return self.type == MSG_SUCCESS


def parse_challenge_frame(raw: Any) -> TwoFactorMessage:
    """Map a decoded JSON frame to a safe :class:`TwoFactorMessage`.

    Input: the ``json.loads`` result of one text frame (dict expected).
    Output: TwoFactorMessage with only ``type`` / ``message`` / ``can_retry``.
    Edge cases:
      - Non-dict / missing ``type`` → tolerate: return a message with an
        ``"unknown"`` type; the caller decides (do NOT crash the read loop).
      - ``payload.message`` absent → ``None``. ``payload.can_retry`` absent →
        ``False`` (conservative: no silent infinite retries).
    """
    if not isinstance(raw, dict):
        return TwoFactorMessage(type="unknown")

    msg_type = raw.get("type")
    if not isinstance(msg_type, str) or not msg_type:
        msg_type = "unknown"

    payload = raw.get("payload")
    message: str | None = None
    can_retry = False
    if isinstance(payload, dict):
        raw_message = payload.get("message")
        if isinstance(raw_message, str) and raw_message:
            message = raw_message
        can_retry = bool(payload.get("can_retry", False))

    return TwoFactorMessage(type=msg_type, message=message, can_retry=can_retry)


class NgfwTwoFactorChannel:
    """One NGFW challenge WebSocket, opened fresh for a single code attempt.

    Uses the ``websockets`` library (async). Lifecycle (all within one
    ``POST /api/auth/2fa`` request): :meth:`open` → :meth:`send_start` →
    :meth:`recv_typed` (challenge) → :meth:`send_code` → :meth:`recv_typed`
    (success/error) → :meth:`close`. Nothing is held between requests, so
    retries and separate devices each drive an independent socket.
    """

    def __init__(self, server: str, cookies: dict[str, str]) -> None:
        self.server = server
        # SECRET: provisional NGFW cookies; used only to authenticate the socket.
        self._cookies = cookies
        # The live ``websockets`` connection, set by :meth:`open`.
        self._ws: Any | None = None

    async def open(self) -> None:
        """Enforce access policy, build the wss URL + TLS ctx, and connect.

        Maps connect/TLS/timeout failures to ``server_unreachable`` and a
        401/403 handshake rejection (provisional cookies already gone) to
        ``second_factor_expired``. Never logs cookies or the URL query — only
        host/path/timing.
        """
        settings = get_settings()
        # Fail-closed allowlist check — SAME policy as the HTTP client
        # (AGENTS.md #10) — BEFORE any socket is opened.
        await _enforce_current_access(self.server)

        origin = f"https://{self.server}:{settings.STUCK_NGFW_PORT}"
        url = f"wss://{self.server}:{settings.STUCK_NGFW_PORT}{CHALLENGE_PATH}"
        ssl_ctx = _build_ssl_context(settings.ngfw_verify)
        # Only the allowlisted NGFW cookie names ever leave the backend.
        cookie_header = "; ".join(
            f"{name}={value}"
            for name, value in self._cookies.items()
            if any(name.startswith(p) for p in _NGFW_COOKIE_PREFIXES)
        )
        # NGFW validates a same-origin ``Origin`` on the challenge socket (the
        # browser sends it); without it NGFW refuses to issue a ``2fa_challenge``
        # and answers ``2fa_error``. Mirror the browser's same-origin value.
        headers = {"Origin": origin}
        if cookie_header:
            headers["Cookie"] = cookie_header

        start = time.perf_counter()
        try:
            self._ws = await websockets.connect(
                url,
                ssl=ssl_ctx,
                additional_headers=headers,
                open_timeout=settings.STUCK_NGFW_TIMEOUT_SECONDS,
            )
        except InvalidStatus as exc:
            status_code = exc.response.status_code
            _log_ws(self.server, "open", start, error=f"http_{status_code}")
            if status_code in (401, 403):
                raise StuckError(
                    "second_factor_expired",
                    "NGFW rejected the provisional 2FA session",
                ) from exc
            raise StuckError(
                "server_unreachable",
                "NGFW 2FA challenge handshake failed",
                details={"reason": type(exc).__name__},
            ) from exc
        except (OSError, TimeoutError, InvalidHandshake) as exc:
            _log_ws(self.server, "open", start, error=type(exc).__name__)
            raise StuckError(
                "server_unreachable",
                "NGFW 2FA challenge socket unreachable",
                details={"reason": type(exc).__name__},
            ) from exc
        _log_ws(self.server, "open", start, status="open")

    async def recv_typed(self, *, timeout: float | None = None) -> TwoFactorMessage:
        """Receive and parse the next frame within ``timeout`` seconds.

        Returns a :class:`TwoFactorMessage`. Raises ``StuckError`` on transport
        loss / timeout (mapped to ``second_factor_expired`` — the challenge
        window closed).
        A clean server close with no pending error is a *terminal* the caller
        interprets as a success candidate (OQ #1): it is surfaced as a message
        with ``type == MSG_CLOSED`` (not an error) rather than an exception.
        """
        if self._ws is None:
            raise StuckError("second_factor_expired", "The second-factor challenge socket is not open")

        start = time.perf_counter()
        try:
            raw = await asyncio.wait_for(self._ws.recv(), timeout)
        except TimeoutError as exc:
            _log_ws(self.server, "recv", start, error="timeout")
            raise StuckError("second_factor_expired", "The second-factor challenge timed out") from exc
        except ConnectionClosedOK:
            # Clean close, no prior error frame -- OQ #1 success candidate.
            _log_ws(self.server, "recv", start, status=MSG_CLOSED)
            return TwoFactorMessage(type=MSG_CLOSED)
        except ConnectionClosedError as exc:
            _log_ws(self.server, "recv", start, error="closed_error")
            raise StuckError("second_factor_expired", "The second-factor challenge socket closed unexpectedly") from exc
        except ConnectionClosed as exc:  # pragma: no cover - defensive base-class fallback
            _log_ws(self.server, "recv", start, error="closed")
            raise StuckError("second_factor_expired", "The second-factor challenge socket closed") from exc

        try:
            decoded = json.loads(raw)
        except TypeError, ValueError:
            decoded = None
        message = parse_challenge_frame(decoded)
        _log_ws(self.server, "recv", start, status=message.type)
        return message

    async def send_start(self) -> None:
        """Kick off the challenge; the server replies with ``2fa_challenge``.

        Observed live: NGFW sends nothing until the client sends this first
        frame (``{"type": MSG_START, "payload": {}}``). Without it, the next
        ``recv`` blocks until it times out.
        """
        if self._ws is None:
            raise StuckError("second_factor_expired", "The second-factor challenge socket is not open")

        start = time.perf_counter()
        frame = json.dumps({"type": MSG_START, "payload": {}})
        try:
            await self._ws.send(frame)
        except ConnectionClosed as exc:
            _log_ws(self.server, "start", start, error="closed")
            raise StuckError("second_factor_expired", "The second-factor challenge socket closed") from exc
        _log_ws(self.server, "start", start, status="sent")

    async def send_code(self, code: str) -> None:
        """Send the admin's code as a challenge frame.

        Wire shape: ``{"type": MSG_CHALLENGE, "payload": {CODE_FIELD: code}}``.
        The code is SECRET — never logged; only that a frame was sent + timing.
        """
        if self._ws is None:
            raise StuckError("second_factor_expired", "The second-factor challenge socket is not open")

        start = time.perf_counter()
        frame = json.dumps({"type": MSG_CHALLENGE, "payload": {CODE_FIELD: code}})
        try:
            await self._ws.send(frame)
        except ConnectionClosed as exc:
            _log_ws(self.server, "send", start, error="closed")
            raise StuckError("second_factor_expired", "The second-factor challenge socket closed") from exc
        _log_ws(self.server, "send", start, status="sent")

    async def close(self) -> None:
        """Best-effort close of the challenge socket (idempotent).

        Mirrors ``ngfw_logout``: teardown never surfaces an error to the caller.
        """
        if self._ws is None:
            return
        start = time.perf_counter()
        try:
            await self._ws.close()
        except (ConnectionClosed, OSError, RuntimeError) as exc:  # pragma: no cover - best-effort teardown
            _log_ws(self.server, "close", start, error=type(exc).__name__)
        else:
            _log_ws(self.server, "close", start, status="closed")
        finally:
            self._ws = None
