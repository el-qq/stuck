"""Safe, server-side representation of an authenticated NGFW admin role.

Only the five fields returned by the read-only ``GET /web/whoami`` endpoint
are accepted.  The raw NGFW response is deliberately never retained or sent
to the browser.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..errors import StuckError


# STUCK loads a full rules snapshot, so permit only the two built-in roles that
# are documented as full administrator and administrator read-only.  Do not
# infer permission from a partial competence list.
TRACE_ROLE_IDS = frozenset({"predefined_admin_write", "predefined_admin_readonly"})

# whoami ``blocked_flags`` is a bitfield; bit 0 (value 1) means the profile is
# authenticated but blocked awaiting a second factor (mfa2-plan.md §2).
BLOCKED_FLAG_TWO_FACTOR = 0b1


@dataclass(frozen=True)
class TwoFactorPending:
    """Non-secret marker that a 200 ``whoami`` is blocked awaiting a 2FA code.

    Returned (instead of an :class:`AdminAccessProfile`) by the provisional
    whoami probe so ``POST /api/auth/login`` can open the challenge WebSocket and
    register a pending entry rather than mistaking the blocked profile for a
    finished login. ``submitted_login`` is echoed back only to re-run the strict
    whoami after unblock; the canonical identity is re-read then. ``message`` is
    the optional hint NGFW may show on the form (never a secret / token).
    """

    submitted_login: str
    admin_id: str | None = None
    message: str | None = None


@dataclass(frozen=True)
class AdminAccessProfile:
    """Non-secret current-admin identity and access decision."""

    login: str
    name: str
    role_id: str
    role_name: str
    competence: tuple[str, ...]

    @property
    def trace_allowed(self) -> bool:
        return self.role_id in TRACE_ROLE_IDS

    def public(self) -> dict[str, str | bool]:
        """Return the intentionally small profile safe for ``GET /api/session``."""

        return {
            "role_id": self.role_id,
            # This is one of the five strict whoami fields.  The UI maps the
            # closed role id to its own localized label and does not render
            # this vendor-provided value, but it remains part of the small
            # public compatibility contract.
            "role_name": self.role_name,
            "trace_allowed": self.trace_allowed,
        }


def parse_whoami(payload: Any) -> AdminAccessProfile:
    """Validate only the stable fields STUCK needs from ``/web/whoami``.

    Keep the error generic: a vendor response may contain information that is
    not safe to reflect to the browser or logs.
    """

    if not isinstance(payload, dict):
        raise StuckError("api_changed", "NGFW administrator profile is unavailable")

    login = payload.get("login")
    name = payload.get("name")
    role_id = payload.get("role_id")
    role_name = payload.get("role_name")
    competence = payload.get("competence")
    if (
        not isinstance(login, str)
        or not login.strip()
        or not isinstance(name, str)
        or not isinstance(role_id, str)
        or not role_id.strip()
        or not isinstance(role_name, str)
        or not isinstance(competence, list)
        or any(not isinstance(item, str) for item in competence)
    ):
        raise StuckError("api_changed", "NGFW administrator profile is unavailable")

    return AdminAccessProfile(
        login=login.strip(),
        name=name,
        role_id=role_id.strip(),
        role_name=role_name,
        competence=tuple(competence),
    )


def detect_two_factor_pending(payload: Any, *, submitted_login: str) -> TwoFactorPending | None:
    """Soft pre-check run BEFORE the strict :func:`parse_whoami`.

    The blocked-2FA whoami has ``blocked_flags`` bit 0 set and empty
    ``role_id`` / ``role_name`` (``login`` may be a placeholder like ``"mfa"``),
    which would otherwise trip ``parse_whoami`` into ``api_changed``
    (mfa2-plan.md §2). This must therefore run first and, on a match, short-
    circuit to the challenge flow.

    Args:
        payload: The raw JSON dict from ``GET /web/whoami`` (may be anything).
        submitted_login: The login the admin typed (carried into the pending
            entry; the real identity is re-read from whoami after unblock).

    Returns:
        A :class:`TwoFactorPending` when the profile is authenticated-but-blocked
        for a second factor; otherwise ``None`` (caller proceeds to strict parse).

    """
    if not isinstance(payload, dict):
        return None

    blocked_flags = payload.get("blocked_flags")
    flags_blocked = isinstance(blocked_flags, int) and bool(blocked_flags & BLOCKED_FLAG_TWO_FACTOR)

    role_id = payload.get("role_id")
    role_id_blank = not isinstance(role_id, str) or not role_id.strip()

    # ``two_factor``/``admin_id`` presence is only meaningful together with a
    # blank role_id -- an ordinary complete profile also has a role_id and must
    # never be mistaken for a pending 2FA challenge.
    has_two_factor_marker = "two_factor" in payload or bool(payload.get("admin_id"))

    if not (flags_blocked or (role_id_blank and has_two_factor_marker)):
        return None

    admin_id = payload.get("admin_id")
    admin_id = admin_id.strip() if isinstance(admin_id, str) and admin_id.strip() else None

    message = payload.get("message")
    message = message.strip() if isinstance(message, str) and message.strip() else None

    return TwoFactorPending(submitted_login=submitted_login, admin_id=admin_id, message=message)


def require_trace_access(profile: AdminAccessProfile) -> None:
    """Reject snapshot/trace access for a known but insufficient role."""

    if not profile.trace_allowed:
        # The role id is safe diagnostic metadata.  Do not disclose an NGFW
        # path, raw permission set, session cookie or a vendor response body.
        raise StuckError(
            "insufficient_ngfw_permissions",
            "The current NGFW administrator role cannot run traffic diagnostics",
            details={"role_id": profile.role_id},
        )
