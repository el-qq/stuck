"""Shared FastAPI dependencies and app-state accessors.

The session store and the binding pool live on ``app.state`` so they are
process-wide singletons (in-memory semantics; see docs/ARCHITECTURE.md).

v2.1: NGFW cookies come from the ACTIVE session only; the pool holds just the
rules snapshot. If the NGFW-side session has expired, any NGFW call raises the
contract's ``session_expired`` (mapped in ngfw/client.py) so the UI re-prompts
for credentials.
"""

from __future__ import annotations

import logging

from fastapi import Depends, Request

from .domain.binding_pool import Binding, BindingPool, RulesSnapshot
from .domain.admin_access import require_trace_access
from .domain.session_store import Session, SessionStore
from .errors import not_authenticated, session_expired
from .logging_setup import log_event
from .ngfw import endpoints as ep
from .ngfw.client import NgfwClient

SESSION_COOKIE = "stuck_session"

_pool_log = logging.getLogger("stuck.pool")


def get_session_store(request: Request) -> SessionStore:
    return request.app.state.session_store


def get_binding_pool(request: Request) -> BindingPool:
    return request.app.state.binding_pool


def current_session(
    request: Request,
    store: SessionStore = Depends(get_session_store),
) -> Session:
    """Resolve and validate the STUCK session from the cookie.

    Missing or unknown cookies are ``not_authenticated``. A known cookie whose
    STUCK session reached its TTL is ``session_expired`` so the UI can preserve
    the server/login fields and ask only for a new password. Neither case
    touches the per-binding rules snapshot.
    """
    sid = request.cookies.get(SESSION_COOKIE)
    sess, expired = store.resolve(sid)
    if expired:
        raise session_expired()
    if sess is None:
        raise not_authenticated()
    return sess


def binding_for(session: Session, pool: BindingPool) -> Binding:
    """The pool binding backing a session (created at login; recreated if lost)."""
    binding, _ = pool.ensure(session.admin_login, session.server)
    return binding


def ngfw_client_for(session: Session) -> NgfwClient:
    """NGFW client using the ACTIVE session's NGFW cookies (v2.1)."""
    return NgfwClient(session.server, session.ngfw_cookies)


async def get_or_load_snapshot(
    session: Session,
    pool: BindingPool,
    *,
    force: bool = False,
) -> RulesSnapshot:
    """Return the binding's snapshot, loading it on first use.

    ``force=True`` (POST /api/rules/refresh) reloads the snapshot. All NGFW
    calls use the ACTIVE session's NGFW cookies (v2.1); if those have expired on
    the NGFW side, NgfwClient raises the contract's ``session_expired`` and the
    UI re-prompts for credentials. No TTL: without ``force`` an existing
    snapshot is served as-is until process restart (contract v2 invariant 9).
    """
    # This guard is intentionally before ``binding_for``: a known insufficient
    # role must not create a binding or begin snapshot I/O.
    require_trace_access(session.admin_access)
    binding = binding_for(session, pool)
    if not force and binding.snapshot is not None:
        return binding.snapshot

    async with pool.load_lock(binding):
        # Another request can have completed the initial load while this one
        # waited for the lock. A manual refresh deliberately still reloads.
        if not force and binding.snapshot is not None:
            return binding.snapshot

        # A shared client keeps the concurrent snapshot reads on one connection
        # pool instead of opening a separate TLS connection for every endpoint.
        async with ngfw_client_for(session) as client:
            raw = await ep.load_snapshot(client)
        snap = RulesSnapshot.from_raw(raw)
        is_refresh = binding.snapshot is not None
        pool.set_snapshot(binding, snap)
        log_event(
            _pool_log,
            "rules_refreshed" if is_refresh else "rules_loaded",
            login=binding.admin_login,
            server=binding.server,
            counts=snap.counts(),
        )
        return snap
