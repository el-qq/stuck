"""FastAPI application assembly for STUCK backend.

Wires routers, CORS, typed-error handlers, structured logging, and process-wide
in-memory stores. Contract: docs/API_CONTRACT.md.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections.abc import AsyncIterator

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from . import __version__
from .api import auth, config, export, hygiene, snapshots, trace, users
from .api import session as session_api
from .config import get_settings
from .domain.binding_pool import BindingPool
from .domain.pending_2fa import PendingTwoFactorStore
from .domain.session_store import SessionStore
from .errors import (
    StuckError,
    stuck_error_handler,
    unhandled_error_handler,
    validation_exception_handler,
)
from .logging_setup import configure_logging, log_event
from .ngfw.client import ngfw_logout

_access_log = logging.getLogger("stuck.access")
_security_log = logging.getLogger("stuck.security")


class AccessLogMiddleware:
    """ASGI-native access logging without BaseHTTPMiddleware buffering.

    FastAPI's decorator middleware is implemented through Starlette's legacy
    BaseHTTPMiddleware. On the current Starlette release it can stall streamed
    responses that carry Set-Cookie headers. Logging directly at the ASGI send
    boundary avoids that class of issue and observes the final status code.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        start = time.perf_counter()
        status = 500

        async def send_with_status(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = int(message["status"])
            await send(message)

        try:
            await self.app(scope, receive, send_with_status)
        except Exception:
            log_event(
                _access_log,
                "request",
                level=logging.ERROR,
                method=scope["method"],
                path=scope["path"],
                status=500,
                duration_ms=round((time.perf_counter() - start) * 1000, 1),
            )
            raise
        else:
            level = logging.DEBUG if scope["path"] == "/api/health" else logging.INFO
            log_event(
                _access_log,
                "request",
                level=level,
                method=scope["method"],
                path=scope["path"],
                status=status,
                duration_ms=round((time.perf_counter() - start) * 1000, 1),
            )
        finally:
            # Drop expired server-side NGFW cookies without touching the
            # binding pool. The next login for the same pair still reuses its
            # rules snapshot, while Docker health checks keep idle processes
            # tidy as well.
            store = getattr(scope["app"].state, "session_store", None)
            if store is not None:
                store.purge_expired()


_sweep_log = logging.getLogger("stuck.pool")


async def _sweep_pending_2fa(app: FastAPI, interval: float) -> None:
    """Periodically release 2FA challenges abandoned by the browser.

    If the admin closes the tab or the device drops off while on the code form,
    no request ever tears the pending entry down. This loop drops every expired
    entry and closes its orphaned provisional NGFW session (best-effort), so
    neither backend memory nor an NGFW admin session leaks. The per-attempt
    challenge WebSocket is already closed inside each request, so there is no
    long-lived socket to reap here.
    """
    store: PendingTwoFactorStore = app.state.pending_2fa_store
    while True:
        await asyncio.sleep(interval)
        try:
            for entry in store.expire_sweep():
                # Close the held challenge socket first, then the NGFW session.
                if entry.channel is not None:
                    await entry.channel.close()
                await ngfw_logout(entry.server, entry.ngfw_cookies)
        except asyncio.CancelledError:
            raise
        except (OSError, RuntimeError, StuckError) as exc:
            # Teardown helpers translate expected network failures. Let coding
            # defects surface instead of silently losing the cleanup loop.
            log_event(_sweep_log, "pending_2fa_sweep_error", level=logging.WARNING, error=type(exc).__name__)


@contextlib.asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    # Sweep a few times per TTL so abandoned challenges are reaped promptly.
    ttl = app.state.settings.STUCK_2FA_TTL_SECONDS
    interval = min(60.0, max(10.0, ttl / 3))
    task = asyncio.create_task(_sweep_pending_2fa(app, interval))
    try:
        yield
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(settings.STUCK_LOG_LEVEL, settings.STUCK_LOG_FORMAT, settings.STUCK_LOG_FILE)
    if settings.STUCK_ALLOW_ANY_NGFW:
        log_event(
            _security_log,
            "ngfw_access_unrestricted",
            level=logging.WARNING,
            message="STUCK_ALLOW_ANY_NGFW is enabled; use only in a trusted lab",
        )

    app = FastAPI(title="STUCK backend", version=__version__, lifespan=_lifespan)

    # Process-wide in-memory stores (single worker; see docs/ARCHITECTURE.md).
    # Initialized eagerly so the app works with or without a lifespan runner.
    # v2: the binding pool lives for the whole process life (no TTL); sessions
    # keep the NGFW cookies and die on logout/expiry.
    app.state.settings = settings
    app.state.session_store = SessionStore(settings.session_ttl_seconds)
    app.state.binding_pool = BindingPool()
    # In-flight 2FA challenges (opaque pending_id → provisional NGFW state).
    # Cleared on restart like every other in-memory store.
    app.state.pending_2fa_store = PendingTwoFactorStore(settings.STUCK_2FA_TTL_SECONDS)

    if settings.allowed_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.allowed_origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
    app.add_middleware(AccessLogMiddleware)

    # Typed error envelope everywhere (contract §2).
    app.add_exception_handler(StuckError, stuck_error_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(Exception, unhandled_error_handler)

    app.include_router(auth.router)
    app.include_router(config.router)
    app.include_router(session_api.router)
    app.include_router(users.router)
    app.include_router(trace.router)
    app.include_router(export.router)
    app.include_router(hygiene.router)
    app.include_router(snapshots.router)

    @app.get("/api/health", tags=["health"])
    async def health():
        # (v2.2) ngfw_port: the port the backend will connect to on the NGFW —
        # shown to the user by the frontend next to the server field.
        # rules_export_enabled: debug rules-export feature flag.
        return {
            "status": "ok",
            "version": __version__,
            "ngfw_port": settings.STUCK_NGFW_PORT,
            "rules_export_enabled": settings.STUCK_ENABLE_RULES_EXPORT,
            "rule_hygiene_enabled": settings.STUCK_ENABLE_RULE_HYGIENE,
            "rule_snapshots_enabled": settings.STUCK_ENABLE_RULE_SNAPSHOTS,
            "ngfw_access_mode": settings.ngfw_access_mode,
        }

    return app


app = create_app()
