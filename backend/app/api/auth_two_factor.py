"""2FA challenge lifecycle used by the ``/api/auth`` router.

This module owns terminal cleanup of provisional NGFW sessions.  Keeping all
success, cancellation and expiration paths together makes the secret lifetime
auditable: a pending entry either remains retryable or its WebSocket, NGFW
cookies and opaque browser cookie are all discarded together.
"""

from __future__ import annotations

import logging
from collections.abc import Callable

from fastapi import Response

from ..config import Settings
from ..domain.admin_access import AdminAccessProfile, TwoFactorPending, require_readonly_admin
from ..domain.binding_pool import BindingPool
from ..domain.pending_2fa import PendingTwoFactor, PendingTwoFactorStore
from ..domain.session_store import SessionStore
from ..errors import StuckError, second_factor_expired, second_factor_invalid
from ..logging_setup import log_event
from ..ngfw.client import ngfw_logout, ngfw_whoami_probe
from ..ngfw.two_factor_ws import MSG_CANCELLED, MSG_CHALLENGE, MSG_CLOSED, NgfwTwoFactorChannel
from .auth_session import clear_pending_two_factor_cookie, finalize_login

_auth_log = logging.getLogger("stuck.auth")

ChannelFactory = Callable[[str, dict[str, str]], NgfwTwoFactorChannel]


async def discard_pending(
    pending_store: PendingTwoFactorStore,
    pending_id: str | None,
    entry: PendingTwoFactor | None = None,
) -> PendingTwoFactor | None:
    """Remove a pending challenge and best-effort release its private resources."""
    current = entry if entry is not None else pending_store.pop(pending_id)
    if current is None:
        return None
    pending_store.pop(pending_id)
    if current.channel is not None:
        await current.channel.close()
    await ngfw_logout(current.server, current.ngfw_cookies)
    return current


async def submit_two_factor(
    *,
    code: str,
    pending_id: str | None,
    response: Response,
    settings: Settings,
    store: SessionStore,
    pool: BindingPool,
    pending_store: PendingTwoFactorStore,
    channel_factory: ChannelFactory,
) -> dict[str, object]:
    """Submit one 2FA code and make every terminal transition explicit.

    A retryable NGFW rejection intentionally leaves the pending entry and its
    channel untouched.  Every other non-success path clears all provisional
    state before raising the established contract error.
    """
    entry = pending_store.get(pending_id)
    if entry is None:
        clear_pending_two_factor_cookie(response, settings)
        raise second_factor_expired()

    async def reset_to_login() -> None:
        await discard_pending(pending_store, pending_id, entry)
        clear_pending_two_factor_cookie(response, settings)

    timeout = float(settings.STUCK_NGFW_TIMEOUT_SECONDS)
    reached_challenge = False
    verdict = None
    role: AdminAccessProfile | TwoFactorPending | None = None
    try:
        channel = entry.channel
        if channel is None:
            channel = channel_factory(entry.server, entry.ngfw_cookies)
            await channel.open()
            entry.channel = channel

        await channel.send_start()
        for _ in range(4):
            message = await channel.recv_typed(timeout=timeout)
            if message.type == MSG_CHALLENGE:
                reached_challenge = True
                break
            if message.is_error or message.type in (MSG_CANCELLED, MSG_CLOSED):
                break
        if reached_challenge:
            await channel.send_code(code)
            verdict = await channel.recv_typed(timeout=timeout)
            if not verdict.is_error:
                # A WebSocket success is only a candidate. The updated whoami
                # profile remains the source of truth for access and unblocking.
                role = await ngfw_whoami_probe(entry.server, entry.ngfw_cookies, submitted_login=entry.submitted_login)
    except StuckError:
        await reset_to_login()
        raise second_factor_expired() from None

    if not reached_challenge or (verdict.is_error and not verdict.can_retry):
        await reset_to_login()
        raise second_factor_expired()

    if verdict.is_error or isinstance(role, TwoFactorPending):
        message = verdict.message if (verdict.is_error and verdict.message) else ""
        raise second_factor_invalid(can_retry=True, message=message)

    if settings.STUCK_REQUIRE_READONLY_ADMIN:
        try:
            require_readonly_admin(role)
        except StuckError:
            await reset_to_login()
            log_event(
                _auth_log,
                "login_rejected_readonly_required",
                login=role.login,
                server=entry.server,
            )
            raise

    # The accepted provisional cookies now move into the real session. The
    # socket and opaque pending identifier have no further purpose.
    pending_store.pop(pending_id)
    if entry.channel is not None:
        await entry.channel.close()
    result = finalize_login(response, settings, store, pool, entry.server, entry.ngfw_cookies, role)
    clear_pending_two_factor_cookie(response, settings)
    return result


async def cancel_two_factor(
    *,
    pending_id: str | None,
    response: Response,
    settings: Settings,
    pending_store: PendingTwoFactorStore,
) -> dict[str, bool]:
    """Idempotently abandon an in-flight challenge and its provisional login."""
    entry = await discard_pending(pending_store, pending_id)
    if entry is not None:
        log_event(_auth_log, "two_factor_cancelled", server=entry.server)
    clear_pending_two_factor_cookie(response, settings)
    return {"ok": True}
