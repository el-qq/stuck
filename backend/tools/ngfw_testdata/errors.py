"""Typed, user-facing failures for the NGFW test-data command."""

from __future__ import annotations


class NgfwToolError(Exception):
    """Base error carrying a stable CLI exit code and an optional hint."""

    exit_code = 6

    def __init__(self, message: str, *, hint: str | None = None) -> None:
        super().__init__(message)
        self.hint = hint


class InputError(NgfwToolError):
    exit_code = 2


class AuthenticationError(NgfwToolError):
    exit_code = 3


class AuthorizationError(NgfwToolError):
    exit_code = 4


class NetworkError(NgfwToolError):
    exit_code = 5


class ApiError(NgfwToolError):
    exit_code = 6


class ConflictError(NgfwToolError):
    exit_code = 7
