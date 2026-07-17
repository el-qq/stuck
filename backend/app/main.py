"""FastAPI application assembly for STUCK backend.

Wires routers, CORS, typed-error handlers, structured logging, and process-wide
in-memory stores. Contract: docs/API_CONTRACT.md.
"""

from __future__ import annotations

import logging
import time

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from . import __version__
from .api import auth, config, export, session as session_api, trace, users
from .config import get_settings
from .domain.binding_pool import BindingPool
from .domain.session_store import SessionStore
from .errors import (
    StuckError,
    stuck_error_handler,
    unhandled_error_handler,
    validation_exception_handler,
)
from .logging_setup import configure_logging, log_event

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

    app = FastAPI(title="STUCK backend", version=__version__)

    # Process-wide in-memory stores (single worker; see docs/ARCHITECTURE.md).
    # Initialized eagerly so the app works with or without a lifespan runner.
    # v2: the binding pool lives for the whole process life (no TTL); sessions
    # keep the NGFW cookies and die on logout/expiry.
    app.state.settings = settings
    app.state.session_store = SessionStore(settings.session_ttl_seconds)
    app.state.binding_pool = BindingPool()

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

    @app.get("/api/health", tags=["health"])
    async def health():
        # (v2.2) ngfw_port: the port the backend will connect to on the NGFW —
        # shown to the user by the frontend next to the server field.
        # (v2.3) rules_export_enabled: debug rules-export feature flag.
        return {
            "status": "ok",
            "version": __version__,
            "ngfw_port": settings.STUCK_NGFW_PORT,
            "rules_export_enabled": settings.STUCK_ENABLE_RULES_EXPORT,
            "ngfw_access_mode": settings.ngfw_access_mode,
        }

    return app


app = create_app()
