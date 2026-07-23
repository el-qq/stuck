"""HTTP client for the Ideco NGFW REST API.

The backend is a *trusted proxy*: it holds the NGFW session cookies server-side
and never exposes them to the browser. Network / TLS / HTTP failures are mapped
to the typed error catalog (docs/API_CONTRACT.md, mapping notes in
docs/NGFW_API_NOTES.md).
"""

from __future__ import annotations

import asyncio
import logging
import time
from types import TracebackType
from typing import Any, Self

import httpx

from ..config import get_settings
from ..domain.admin_access import (
    AdminAccessProfile,
    TwoFactorPending,
    detect_two_factor_pending,
    parse_whoami,
)
from ..domain.ngfw_access import enforce_ngfw_access
from ..errors import StuckError
from ..logging_setup import log_event

_ngfw_log = logging.getLogger("stuck.ngfw")

# Login body extras added by the backend (contract §3.1: rest_path "/").
_REST_PATH = "/"


def _log_call(
    server: str,
    method: str,
    path: str,
    start: float,
    *,
    status: int | None = None,
    error: str | None = None,
) -> None:
    """Log one NGFW call: endpoint, status (or error), duration.

    Never logs cookies, bodies or query params — only method/path/timing.
    """
    log_event(
        _ngfw_log,
        "ngfw_call",
        level=logging.WARNING if error else logging.INFO,
        server=server,
        method=method,
        path=path,
        status=status,
        error=error,
        duration_ms=round((time.perf_counter() - start) * 1000, 1),
    )


# NGFW cookie names we persist (docs/NGFW_API_NOTES.md).
_NGFW_COOKIE_PREFIXES = ("insecure-ideco-session", "__Secure-ideco-")


def _base_url(server: str) -> str:
    """(v2) ``server`` is a bare host (IP/domain); the API port comes from conf."""
    return f"https://{server}:{get_settings().STUCK_NGFW_PORT}"


def _new_client(server: str, cookies: dict[str, str] | None = None) -> httpx.AsyncClient:
    s = get_settings()
    return httpx.AsyncClient(
        base_url=_base_url(server),
        verify=s.ngfw_verify,
        timeout=s.STUCK_NGFW_TIMEOUT_SECONDS,
        cookies=cookies or {},
        follow_redirects=False,
    )


async def _enforce_current_access(server: str) -> None:
    """Apply the installation policy immediately before an NGFW call."""

    settings = get_settings()
    await enforce_ngfw_access(
        server,
        port=settings.STUCK_NGFW_PORT,
        allow_any=settings.STUCK_ALLOW_ANY_NGFW,
        allowed_hosts=settings.allowed_ngfw_hosts,
        allowed_networks=settings.allowed_ngfw_networks,
    )


def _unreachable(exc: Exception) -> StuckError:
    return StuckError(
        "server_unreachable",
        "NGFW is unreachable (connect/timeout/TLS handshake failed)",
        details={"reason": type(exc).__name__},
    )


def _looks_like_2fa(payload: Any) -> bool:
    """Best-effort detection of a 2FA-required login response.

    NGFW's exact shape is undocumented (docs/NGFW_API_NOTES.md), so this is
    heuristic and recorded as an assumption in docs/NGFW_API_NOTES.md.
    """
    if not isinstance(payload, dict):
        return False
    flat = str(payload).lower()
    return any(k in flat for k in ("two_factor", "second_factor", "2fa", "otp_required"))


async def ngfw_login(server: str, login: str, password: str) -> dict[str, str]:
    """Authenticate to NGFW and return the session cookies to persist.

    Raises StuckError: ngfw_host_not_allowed, invalid_credentials,
    second_factor_required, server_unreachable, api_changed, ngfw_error.
    """
    await _enforce_current_access(server)
    start = time.perf_counter()
    try:
        async with _new_client(server) as client:
            resp = await client.post(
                "/web/auth/login",
                json={"login": login, "password": password, "rest_path": _REST_PATH},
            )
    except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout, httpx.WriteTimeout, httpx.PoolTimeout) as exc:
        _log_call(server, "POST", "/web/auth/login", start, error=type(exc).__name__)
        raise _unreachable(exc) from exc
    except httpx.TransportError as exc:  # covers TLS/protocol errors
        _log_call(server, "POST", "/web/auth/login", start, error=type(exc).__name__)
        raise _unreachable(exc) from exc

    _log_call(server, "POST", "/web/auth/login", start, status=resp.status_code)

    if resp.status_code in (401, 403):
        raise StuckError("invalid_credentials", "NGFW rejected login/password")

    # Some deployments answer 200 with a 2FA challenge instead of a session.
    if resp.status_code == 200:
        cookies = _extract_ngfw_cookies(resp)
        if cookies:
            return cookies
        # 200 but no session cookie -> inspect body for a 2FA challenge.
        payload = _json_or_none(resp)
        if _looks_like_2fa(payload):
            raise StuckError(
                "second_factor_required",
                "NGFW requires a second authentication factor",
            )
        raise StuckError(
            "api_changed",
            "NGFW login returned 200 without a session cookie",
        )

    if 500 <= resp.status_code < 600:
        raise StuckError("ngfw_error", f"NGFW returned {resp.status_code} on login")

    raise StuckError("ngfw_error", f"Unexpected NGFW login status {resp.status_code}")


async def _get_whoami_response(server: str, cookies: dict[str, str]) -> httpx.Response:
    """Shared GET /web/whoami plumbing for :func:`ngfw_whoami` and the probe.

    Raises StuckError("server_unreachable") on transport failure. Callers
    handle the response status ladder themselves since the two callers map
    401/403 differently.
    """
    await _enforce_current_access(server)
    start = time.perf_counter()
    try:
        async with _new_client(server, cookies) as client:
            resp = await client.get("/web/whoami")
    except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout, httpx.WriteTimeout, httpx.PoolTimeout) as exc:
        _log_call(server, "GET", "/web/whoami", start, error=type(exc).__name__)
        raise _unreachable(exc) from exc
    except httpx.TransportError as exc:
        _log_call(server, "GET", "/web/whoami", start, error=type(exc).__name__)
        raise _unreachable(exc) from exc

    _log_call(server, "GET", "/web/whoami", start, status=resp.status_code)
    return resp


def _raise_for_whoami_status(resp: httpx.Response) -> None:
    """Status mapping shared by every non-401/403 whoami outcome."""
    if resp.status_code == 404 or 300 <= resp.status_code < 400:
        # ``whoami`` is a required part of the supported login flow.  A
        # missing or redirecting endpoint means this NGFW response shape is not
        # compatible; do not guess another endpoint or follow a redirect.
        raise StuckError("api_changed", "NGFW administrator profile is unavailable")
    if 500 <= resp.status_code < 600:
        raise StuckError("ngfw_error", f"NGFW returned {resp.status_code} for administrator profile")
    if resp.status_code != 200:
        raise StuckError("ngfw_error", f"Unexpected NGFW status {resp.status_code} for administrator profile")


async def ngfw_whoami(
    server: str,
    cookies: dict[str, str],
    *,
    provisional: bool = False,
) -> AdminAccessProfile:
    """Read the authenticated administrator profile from NGFW.

    ``provisional`` is true only during password login, before a STUCK session
    exists.  Some NGFW 2FA flows set provisional cookies and reject this call;
    that must remain a 2FA prompt rather than an authenticated STUCK session.
    """

    resp = await _get_whoami_response(server, cookies)

    if resp.status_code in (401, 403):
        if provisional:
            raise StuckError("second_factor_required", "NGFW requires a second authentication factor")
        raise StuckError("session_expired", "NGFW session expired or revoked")
    _raise_for_whoami_status(resp)

    # NGFW may rotate a session cookie while reporting the active profile.
    # Keep only the allowlisted cookie names in the existing server-side
    # dictionary; they never appear in responses or logs.
    cookies.update(_extract_ngfw_cookies(resp))
    return parse_whoami(_json_or_none(resp))


async def ngfw_whoami_probe(
    server: str,
    cookies: dict[str, str],
    *,
    submitted_login: str,
) -> AdminAccessProfile | TwoFactorPending:
    """Provisional-login whoami read that recognizes the blocked-2FA profile.

    Used ONLY by ``POST /api/auth/login`` (before a STUCK session exists). It
    replaces ``ngfw_whoami(..., provisional=True)`` for the login path and adds
    the new 2FA branch:

      * 401 / 403  → ``second_factor_required`` (provisional cookies rejected;
        preserves the existing contract + test — no challenge is possible).
      * 200 blocked (``detect_two_factor_pending`` matches) → return
        :class:`TwoFactorPending` so login can open the challenge WebSocket.
      * 200 normal → strict :func:`parse_whoami` → :class:`AdminAccessProfile`.
      * other statuses → the same ``api_changed`` / ``ngfw_error`` mapping as
        :func:`ngfw_whoami`.

    On the blocked 200 the provisional cookies ARE valid, so they are refreshed
    into ``cookies`` (never logged) exactly like the authenticated path, then
    carried into the pending entry for the WebSocket handshake.
    """
    resp = await _get_whoami_response(server, cookies)

    if resp.status_code in (401, 403):
        raise StuckError("second_factor_required", "NGFW requires a second authentication factor")

    if resp.status_code == 200:
        payload = _json_or_none(resp)
        pending = detect_two_factor_pending(payload, submitted_login=submitted_login)
        if pending is not None:
            cookies.update(_extract_ngfw_cookies(resp))
            return pending
        cookies.update(_extract_ngfw_cookies(resp))
        return parse_whoami(payload)

    _raise_for_whoami_status(resp)
    # Unreachable: _raise_for_whoami_status always raises for a non-200 status.
    raise StuckError("ngfw_error", f"Unexpected NGFW status {resp.status_code} for administrator profile")


async def ngfw_logout(server: str, cookies: dict[str, str]) -> None:
    """Best-effort NGFW logout (contract v2.1 §3.2).

    The NGFW cookie is never reused after STUCK logout (it dies with the STUCK
    session), so the orphaned NGFW admin session is killed here. Any failure is
    logged and swallowed — STUCK logout always succeeds. DELETE /web/auth/login
    only affects the session behind OUR cookie, not other admin sessions.
    """
    start = time.perf_counter()
    try:
        await _enforce_current_access(server)
        async with _new_client(server, cookies) as client:
            resp = await client.delete("/web/auth/login")
        _log_call(server, "DELETE", "/web/auth/login", start, status=resp.status_code)
    except (httpx.HTTPError, OSError, RuntimeError, StuckError, ValueError) as exc:
        # Logout must be idempotent and never surface NGFW errors.
        _log_call(server, "DELETE", "/web/auth/login", start, error=type(exc).__name__)
        return


def _extract_ngfw_cookies(resp: httpx.Response) -> dict[str, str]:
    out: dict[str, str] = {}
    for name, value in resp.cookies.items():
        if any(name.startswith(p) for p in _NGFW_COOKIE_PREFIXES):
            out[name] = value
    return out


def _json_or_none(resp: httpx.Response) -> Any:
    try:
        return resp.json()
    except ValueError:
        return None


class NgfwClient:
    """Session-bound client for read-only NGFW data calls."""

    def __init__(self, server: str, cookies: dict[str, str]) -> None:
        self.server = server
        self.cookies = cookies
        self._client: httpx.AsyncClient | None = None
        self._access_checked = False
        self._access_lock = asyncio.Lock()
        # Snapshot loading issues many requests concurrently.  If the role is
        # denied, all of them can receive 403 at once; coalesce the safe
        # whoami recheck rather than multiplying requests with the NGFW cookie.
        self._forbidden_lock = asyncio.Lock()
        self._forbidden_role_id: str | None = None

    async def _ensure_access(self) -> None:
        if self._access_checked:
            return
        async with self._access_lock:
            if self._access_checked:
                return
            await _enforce_current_access(self.server)
            self._access_checked = True

    async def _raise_forbidden(self) -> None:
        """Raise the typed result of a diagnostic-endpoint 403.

        A successful profile read proves the session remains active and makes
        this an authorization error.  ``ngfw_whoami`` raises
        ``session_expired`` itself when the cookie was actually rejected.
        """

        async with self._forbidden_lock:
            if self._forbidden_role_id is None:
                profile = await ngfw_whoami(self.server, self.cookies)
                self._forbidden_role_id = profile.role_id
            role_id = self._forbidden_role_id
        raise StuckError(
            "insufficient_ngfw_permissions",
            "NGFW administrator role cannot access diagnostic data",
            details={"role_id": role_id},
        )

    async def __aenter__(self) -> Self:
        self._client = _new_client(self.server, self.cookies)
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def get_json(self, path: str, *, params: dict[str, Any] | None = None) -> Any:
        return await self._request("GET", path, params=params)

    async def get_json_optional(self, path: str, *, params: dict[str, Any] | None = None) -> Any | None:
        """Like :meth:`get_json`, but a 404 returns ``None`` instead of raising.

        For OPTIONAL NGFW sections (e.g. hardware filtering, absent on releases
        before v22): the missing endpoint means "feature not present here", not
        an error. Every other failure keeps the strict mapping — a 200 with a
        wrong shape still becomes ``api_changed`` downstream.
        """
        try:
            return await self._request("GET", path, params=params)
        except StuckError as exc:
            if exc.code == "ngfw_error" and "endpoint not found" in exc.message:
                return None
            raise

    async def get_text(self, path: str, *, params: dict[str, Any] | None = None) -> str:
        """Return a successful read-only response as text (for CSV exports)."""

        return await self._request("GET", path, params=params, as_text=True)

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        as_text: bool = False,
    ) -> Any:
        await self._ensure_access()
        start = time.perf_counter()
        try:
            if self._client is not None:
                resp = await self._client.request(method, path, params=params)
            else:
                async with _new_client(self.server, self.cookies) as client:
                    resp = await client.request(method, path, params=params)
        except (
            httpx.ConnectError,
            httpx.ConnectTimeout,
            httpx.ReadTimeout,
            httpx.WriteTimeout,
            httpx.PoolTimeout,
        ) as exc:
            _log_call(self.server, method, path, start, error=type(exc).__name__)
            raise _unreachable(exc) from exc
        except httpx.TransportError as exc:
            _log_call(self.server, method, path, start, error=type(exc).__name__)
            raise _unreachable(exc) from exc

        _log_call(self.server, method, path, start, status=resp.status_code)

        # A 401 is an expired/revoked NGFW cookie.  A 403 is ambiguous: it can
        # mean the same thing, or a still-valid administrator session without
        # access to this particular read-only diagnostic endpoint.  Re-read
        # the safe, reduced profile to distinguish those cases instead of
        # misleading the UI into asking for a password again.
        if resp.status_code == 401:
            raise StuckError("session_expired", "NGFW session expired or revoked")
        if resp.status_code == 403:
            await self._raise_forbidden()

        if resp.status_code == 404:
            raise StuckError("ngfw_error", f"NGFW endpoint not found: {path}")

        if 500 <= resp.status_code < 600:
            raise StuckError("ngfw_error", f"NGFW returned {resp.status_code} for {path}")

        if resp.status_code != 200:
            raise StuckError("ngfw_error", f"Unexpected NGFW status {resp.status_code} for {path}")

        if as_text:
            return resp.text

        data = _json_or_none(resp)
        if data is None:
            raise StuckError("api_changed", f"NGFW returned non-JSON body for {path}")
        return data
