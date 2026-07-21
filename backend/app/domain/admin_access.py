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
