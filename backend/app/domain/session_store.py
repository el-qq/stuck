"""In-memory STUCK session store.

Maps an opaque ``stuck_session`` cookie value to the (admin_login, server)
binding, the NGFW session cookies, and expiry metadata.

v2.1: NGFW cookies live ONLY here, in the active STUCK session — they die with
it (logout / TTL expiry). The binding pool (``binding_pool.py``) keeps just the
rules snapshot and survives logout. NGFW cookies never leave the backend
(NFR-S2 / contract invariant 2).

Limitation (documented in docs/ARCHITECTURE.md): in-memory only. Restarting the
backend drops all sessions (and the pool). For multi-process / persistence,
swap for Redis.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass


@dataclass
class Session:
    session_id: str
    admin_login: str
    server: str
    ngfw_cookies: dict[str, str]
    created_at: float
    expires_at: float

    def is_expired(self, now: float | None = None) -> bool:
        return (now or time.time()) >= self.expires_at


class SessionStore:
    def __init__(self, ttl_seconds: int) -> None:
        self._ttl = ttl_seconds
        self._by_id: dict[str, Session] = {}

    def create(self, admin_login: str, server: str, ngfw_cookies: dict[str, str]) -> Session:
        now = time.time()
        sid = secrets.token_urlsafe(32)
        sess = Session(
            session_id=sid,
            admin_login=admin_login,
            server=server,
            ngfw_cookies=dict(ngfw_cookies),
            created_at=now,
            expires_at=now + self._ttl,
        )
        self._by_id[sid] = sess
        return sess

    def get(self, session_id: str | None) -> Session | None:
        """Return an active session, dropping an expired entry if present."""
        session, _ = self.resolve(session_id)
        return session

    def resolve(self, session_id: str | None) -> tuple[Session | None, bool]:
        """Return ``(session, expired)`` for a browser session identifier.

        Missing or unknown identifiers are not expired sessions. Keeping that
        distinction lets the API tell the UI whether it should show the
        password re-login flow or the normal anonymous login screen.
        """
        if not session_id:
            return None, False
        sess = self._by_id.get(session_id)
        if sess is None:
            return None, False
        if sess.is_expired():
            self._by_id.pop(session_id, None)
            return None, True
        return sess, False

    def delete(self, session_id: str | None) -> Session | None:
        if not session_id:
            return None
        return self._by_id.pop(session_id, None)

    def purge_expired(self) -> int:
        now = time.time()
        expired = [sid for sid, s in self._by_id.items() if s.is_expired(now)]
        for sid in expired:
            self._by_id.pop(sid, None)
        return len(expired)
