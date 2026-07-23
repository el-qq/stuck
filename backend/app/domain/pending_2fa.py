"""In-memory store for in-flight second-factor (2FA) challenges.

A pending entry lives between ``POST /api/auth/login`` (which detected that the
authenticated NGFW profile is blocked awaiting a second factor) and the terminal
``POST /api/auth/2fa`` (code accepted) or ``POST /api/auth/2fa/cancel`` /
TTL expiry. It is keyed by an opaque, unguessable ``pending_id`` carried in the
short-lived ``stuck_2fa`` cookie — NOT by ``(admin, host)`` — so several
administrators can authenticate against the same NGFW host at the same time
(see docs/source/mfa2-plan.md §Требования).

Security / invariants (AGENTS.md #3, #4, #5):
- The provisional NGFW cookies and the 2FA code never leave the backend and are
  never logged. Only the opaque ``pending_id`` and non-secret timing metadata
  are safe to surface.
- This is process-local, in-memory state. A backend restart clears every
  pending challenge (the browser's ``stuck_2fa`` cookie then resolves to
  nothing → ``second_factor_expired``).
- A live NGFW challenge WebSocket and its background read task are owned here so
  they can be closed deterministically on success / cancel / expiry.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - typing only, avoids an import cycle
    import asyncio

    from ..ngfw.two_factor_ws import NgfwTwoFactorChannel


@dataclass
class PendingTwoFactor:
    """One in-flight 2FA challenge bound to a provisional NGFW login.

    Fields:
        pending_id: Opaque token stored in the ``stuck_2fa`` cookie (the key).
        server: Normalized NGFW host the provisional login authenticated to.
        ngfw_cookies: Provisional NGFW session cookies (SECRET; never emitted).
        submitted_login: The login the admin typed, used only to re-run the
            strict ``whoami`` and create the real session on success. NGFW's
            canonical identity is re-read from ``whoami`` after unblock.
        admin_id: NGFW ``admin_id`` from the blocked whoami, if present
            (diagnostic only; non-secret).
        created_at / expires_at: Wall-clock TTL bounds (STUCK_2FA_TTL_SECONDS).
        channel: The open NGFW challenge WebSocket wrapper (SECRET transport).
        reader_task: Background task draining ``channel`` (start/challenge/error
            messages), owned so it can be cancelled on teardown.
    """

    pending_id: str
    server: str
    ngfw_cookies: dict[str, str]
    submitted_login: str
    admin_id: str | None
    created_at: float
    expires_at: float
    channel: NgfwTwoFactorChannel | None = field(default=None, repr=False)
    reader_task: asyncio.Task[None] | None = field(default=None, repr=False)

    def is_expired(self, now: float | None = None) -> bool:
        return (now or time.time()) >= self.expires_at


class PendingTwoFactorStore:
    """Process-wide registry of opaque ``pending_id`` → :class:`PendingTwoFactor`.

    Mirrors the shape of :class:`~app.domain.session_store.SessionStore` but with
    a much shorter TTL and ownership of an async WebSocket + reader task per
    entry. Constructed once in ``app.main`` and exposed via ``app.state``.
    """

    def __init__(self, ttl_seconds: int) -> None:
        self._ttl = ttl_seconds
        self._by_id: dict[str, PendingTwoFactor] = {}

    def create(
        self,
        server: str,
        ngfw_cookies: dict[str, str],
        submitted_login: str,
        admin_id: str | None,
        channel: NgfwTwoFactorChannel | None = None,
        reader_task: asyncio.Task[None] | None = None,
    ) -> PendingTwoFactor:
        """Register a new challenge and return it (with a fresh ``pending_id``).

        The NGFW challenge WebSocket is opened per attempt inside the 2FA
        endpoint, so ``channel`` is normally ``None`` here. Several entries may
        share the same ``server`` (multi-admin / multi-device).
        """
        now = time.time()
        entry = PendingTwoFactor(
            pending_id=secrets.token_urlsafe(32),
            server=server,
            ngfw_cookies=dict(ngfw_cookies),
            submitted_login=submitted_login,
            admin_id=admin_id,
            created_at=now,
            expires_at=now + self._ttl,
            channel=channel,
            reader_task=reader_task,
        )
        self._by_id[entry.pending_id] = entry
        return entry

    def get(self, pending_id: str | None) -> PendingTwoFactor | None:
        """Return an active entry, dropping it first if its TTL elapsed.

        Mirrors :meth:`SessionStore.resolve` — missing/unknown → None; an
        expired entry is popped (not left behind) but its async teardown is the
        caller's responsibility (this store is sync).
        """
        if not pending_id:
            return None
        entry = self._by_id.get(pending_id)
        if entry is None:
            return None
        if entry.is_expired():
            self._by_id.pop(pending_id, None)
            return None
        return entry

    def pop(self, pending_id: str | None) -> PendingTwoFactor | None:
        """Remove and return an entry regardless of expiry (terminal transition).

        The caller is responsible for awaiting ``channel.close()`` and
        cancelling ``reader_task`` (this store is sync; teardown is async).
        """
        if not pending_id:
            return None
        return self._by_id.pop(pending_id, None)

    def expire_sweep(self, now: float | None = None) -> list[PendingTwoFactor]:
        """Remove every timed-out entry and return them for async teardown.

        Returning the objects (not just a count) keeps the store synchronous
        while letting the caller release the NGFW WebSockets.
        """
        cutoff = now if now is not None else time.time()
        expired_ids = [pid for pid, entry in self._by_id.items() if entry.is_expired(cutoff)]
        return [self._by_id.pop(pid) for pid in expired_ids]
