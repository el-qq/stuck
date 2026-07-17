"""Typed errors and the single error envelope used across the API.

The error catalog is defined by docs/API_CONTRACT.md. Every failure the
frontend can observe maps to one of these codes; the outward contract is stable
regardless of the (uncertain) NGFW status codes.
"""

from __future__ import annotations

import logging as _logging
from typing import Any

from fastapi import Request
from fastapi.responses import JSONResponse

# Import-safe: logging_setup has no imports from errors (no cycle).
from .logging_setup import log_event as _log_event

# code -> default HTTP status (docs/API_CONTRACT.md)
ERROR_HTTP_STATUS: dict[str, int] = {
    "validation_error": 400,
    "invalid_server_address": 400,
    "ngfw_host_not_allowed": 403,
    "invalid_credentials": 401,
    "second_factor_required": 401,
    "not_authenticated": 401,
    "session_expired": 401,
    "server_unreachable": 502,
    "api_changed": 502,
    "ngfw_error": 502,
    "not_found": 404,
    "internal_error": 500,
}


class StuckError(Exception):
    """A typed application error rendered as the contract error envelope."""

    def __init__(
        self,
        code: str,
        message: str = "",
        *,
        details: dict[str, Any] | None = None,
        http_status: int | None = None,
    ) -> None:
        self.code = code
        self.message = message or code
        self.details = details
        self.http_status = http_status or ERROR_HTTP_STATUS.get(code, 500)
        super().__init__(f"{code}: {self.message}")

    def to_response(self) -> JSONResponse:
        body: dict[str, Any] = {"error": {"code": self.code, "message": self.message}}
        if self.details:
            body["error"]["details"] = self.details
        return JSONResponse(status_code=self.http_status, content=body)


# --- Convenience constructors ------------------------------------------------


def validation_error(message: str, **details: Any) -> StuckError:
    return StuckError("validation_error", message, details=details or None)


def not_authenticated() -> StuckError:
    return StuckError("not_authenticated", "No valid STUCK session")


def session_expired() -> StuckError:
    return StuckError("session_expired", "STUCK session expired")


def not_found(message: str, **details: Any) -> StuckError:
    return StuckError("not_found", message, details=details or None)


# --- FastAPI exception handlers ----------------------------------------------

_error_log = _logging.getLogger("stuck.error")


def _log_typed_error(request: Request, exc: StuckError, *, exc_info: Any = None) -> None:
    """Every typed error is logged with its contract code (Phase 2.5)."""
    _log_event(
        _error_log,
        "api_error",
        level=_logging.ERROR if exc.http_status >= 500 else _logging.WARNING,
        exc_info=exc_info,
        code=exc.code,
        status=exc.http_status,
        method=request.method,
        path=request.url.path,
        message=exc.message,
    )


async def stuck_error_handler(request: Request, exc: StuckError) -> JSONResponse:
    _log_typed_error(request, exc)
    return exc.to_response()


async def unhandled_error_handler(request: Request, exc: Exception) -> JSONResponse:
    # Never leak internals / secrets; details stay generic.
    err = StuckError("internal_error", "Unexpected backend error")
    _log_typed_error(request, err, exc_info=exc)
    return err.to_response()


async def validation_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    # FastAPI RequestValidationError -> our validation_error envelope.
    details = None
    errs = getattr(exc, "errors", None)
    if callable(errs):
        try:
            # Keep only type/loc/msg: pydantic's "input" echoes the raw body,
            # which for /api/auth/login would include the password.
            details = {"fields": [{k: e.get(k) for k in ("type", "loc", "msg")} for e in errs() if isinstance(e, dict)]}
        except Exception:  # pragma: no cover - defensive
            details = None
    err = StuckError("validation_error", "Invalid request body", details=details)
    _log_typed_error(request, err)
    return err.to_response()
