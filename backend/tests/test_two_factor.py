"""Tests for second-factor (2FA) authentication flow (docs/API_CONTRACT.md, mfa2-plan.md)."""

import asyncio
import json
from types import SimpleNamespace

import pytest
from conftest import NGFW_SERVER, NGFW_SESSION_COOKIE, NGFW_SESSION_VALUE
from fastapi.testclient import TestClient


def _stuck_2fa_cookie_header(resp) -> str | None:
    """Extract stuck_2fa Set-Cookie header from response."""
    for header, value in resp.headers.multi_items():
        if header.lower() == "set-cookie" and "stuck_2fa" in value:
            return value
    return None


def _stuck_session_cookie_set(resp) -> bool:
    """Check if stuck_session cookie is set in response."""
    for header, value in resp.headers.multi_items():
        if header.lower() == "set-cookie" and "stuck_session" in value:
            return True
    return False


class TestDetectTwoFactorPending:
    """Unit tests for detect_two_factor_pending (domain/admin_access.py)."""

    def test_detect_blocked_flags_bit_0(self):
        """blocked_flags with bit 0 set and blank role_id → TwoFactorPending."""
        from app.domain.admin_access import detect_two_factor_pending

        payload = {
            "login": "mfa",
            "blocked_flags": 1,  # bit 0 = waiting for 2FA
            "role_id": "",
            "role_name": "",
            "two_factor": "",
            "admin_id": "admin.id.123",
        }
        result = detect_two_factor_pending(payload, submitted_login="admin")

        assert result is not None
        assert result.submitted_login == "admin"
        assert result.admin_id == "admin.id.123"

    def test_normal_profile_not_pending(self):
        """Normal authenticated profile (blocked_flags=0) → None."""
        from app.domain.admin_access import detect_two_factor_pending

        payload = {
            "login": "admin",
            "blocked_flags": 0,
            "role_id": "predefined_admin_readonly",
            "role_name": "Read-only administrator",
            "competence": ["admin_read"],
        }
        result = detect_two_factor_pending(payload, submitted_login="admin")

        assert result is None

    def test_invalid_payload_returns_none(self):
        """Non-dict or malformed payload → None (not an error)."""
        from app.domain.admin_access import detect_two_factor_pending

        assert detect_two_factor_pending(None, submitted_login="admin") is None
        assert detect_two_factor_pending("not a dict", submitted_login="admin") is None
        assert detect_two_factor_pending({}, submitted_login="admin") is None


class TestLoginWith2FaRequired:
    """POST /api/auth/login when NGFW requires 2FA (blocked_flags=1, empty role_id).

    Note: WebSocket mocking requires additional infrastructure. These unit tests
    verify the domain logic; integration tests for the full 2FA flow (with WebSocket)
    would require respx fixtures for WebSocket mocking (websockets library does
    not integrate with respx like httpx does).
    """

    def test_two_factor_pending_message_extraction(self):
        """TwoFactorPending extracts optional hint message from blocked whoami."""
        from app.domain.admin_access import detect_two_factor_pending

        payload = {
            "login": "mfa",
            "blocked_flags": 1,
            "role_id": "",
            "role_name": "",
            "two_factor": "",
            "admin_id": "admin.id.123",
            "message": "Enter code from authenticator app",
        }
        result = detect_two_factor_pending(payload, submitted_login="admin")

        assert result is not None
        assert result.message == "Enter code from authenticator app"

    def test_2fa_ngfw_cookie_not_exposed(self):
        """Verify password/cookie masking in TwoFactorRequest model."""
        from app.api.auth import TwoFactorRequest

        # Verify that TwoFactorRequest only accepts code, not secrets
        req = TwoFactorRequest(code="123456")
        assert req.code == "123456"
        assert not hasattr(req, "password")
        assert not hasattr(req, "ngfw_cookie")


class TestPendingTwoFactorStore:
    """Unit tests for PendingTwoFactorStore (domain/pending_2fa.py)."""

    def test_store_create_and_get(self):
        """Store can create and retrieve a pending entry."""
        from app.domain.pending_2fa import PendingTwoFactorStore
        from app.ngfw.two_factor_ws import NgfwTwoFactorChannel

        store = PendingTwoFactorStore(ttl_seconds=180)
        channel = NgfwTwoFactorChannel(NGFW_SERVER, {"session": "token"})

        entry = store.create(
            NGFW_SERVER,
            {"session": "token"},
            "admin",
            "admin.id.123",
            channel,
        )

        assert entry.pending_id is not None
        assert entry.server == NGFW_SERVER
        assert entry.submitted_login == "admin"
        assert entry.admin_id == "admin.id.123"

        # Retrieve by pending_id
        retrieved = store.get(entry.pending_id)
        assert retrieved is not None
        assert retrieved.pending_id == entry.pending_id

    def test_store_pop(self):
        """Store.pop() removes and returns an entry."""
        from app.domain.pending_2fa import PendingTwoFactorStore
        from app.ngfw.two_factor_ws import NgfwTwoFactorChannel

        store = PendingTwoFactorStore(ttl_seconds=180)
        channel = NgfwTwoFactorChannel(NGFW_SERVER, {"session": "token"})

        entry = store.create(
            NGFW_SERVER,
            {"session": "token"},
            "admin",
            None,
            channel,
        )

        # Pop the entry
        popped = store.pop(entry.pending_id)
        assert popped is not None
        assert popped.pending_id == entry.pending_id

        # After pop, get returns None
        assert store.get(entry.pending_id) is None

    def test_store_multi_admin_same_server(self):
        """Multiple pending entries can exist for the same server (multi-admin)."""
        from app.domain.pending_2fa import PendingTwoFactorStore
        from app.ngfw.two_factor_ws import NgfwTwoFactorChannel

        store = PendingTwoFactorStore(ttl_seconds=180)

        entry1 = store.create(
            NGFW_SERVER,
            {"session": "token1"},
            "admin1",
            "admin.id.1",
            NgfwTwoFactorChannel(NGFW_SERVER, {"session": "token1"}),
        )

        entry2 = store.create(
            NGFW_SERVER,
            {"session": "token2"},
            "admin2",
            "admin.id.2",
            NgfwTwoFactorChannel(NGFW_SERVER, {"session": "token2"}),
        )

        # Both should exist
        assert store.get(entry1.pending_id) is not None
        assert store.get(entry2.pending_id) is not None
        assert entry1.pending_id != entry2.pending_id

    def test_store_ttl_expiry(self):
        """Expired entries are dropped by get()."""
        import time

        from app.domain.pending_2fa import PendingTwoFactorStore
        from app.ngfw.two_factor_ws import NgfwTwoFactorChannel

        store = PendingTwoFactorStore(ttl_seconds=1)  # 1 second TTL
        channel = NgfwTwoFactorChannel(NGFW_SERVER, {"session": "token"})

        entry = store.create(
            NGFW_SERVER,
            {"session": "token"},
            "admin",
            None,
            channel,
        )

        # Immediately available
        assert store.get(entry.pending_id) is not None

        # After expiry
        time.sleep(1.1)
        assert store.get(entry.pending_id) is None


class TestCancel2FA:
    """POST /api/auth/2fa/cancel — abort an in-flight challenge (idempotent)."""

    def test_cancel_2fa_without_pending(self, client: TestClient, ngfw_mock):
        """Cancel without a session or pending entry returns 200 {ok: true}."""
        resp = client.post("/api/auth/2fa/cancel")

        assert resp.status_code == 200
        assert resp.json()["ok"] is True

    def test_cancel_2fa_idempotent(self, client: TestClient, ngfw_mock):
        """Cancel can be called multiple times without error."""
        resp1 = client.post("/api/auth/2fa/cancel")
        resp2 = client.post("/api/auth/2fa/cancel")

        assert resp1.status_code == 200
        assert resp2.status_code == 200
        assert resp1.json()["ok"] is True
        assert resp2.json()["ok"] is True


# --------------------------------------------------------------------------- #
# WebSocket challenge coverage (the parts qa left untested).                   #
# --------------------------------------------------------------------------- #


class TestParseChallengeFrame:
    """Unit tests for parse_challenge_frame (ngfw/two_factor_ws.py)."""

    def test_challenge_with_message(self):
        from app.ngfw.two_factor_ws import parse_challenge_frame

        msg = parse_challenge_frame({"type": "2fa_challenge", "payload": {"message": "Enter code"}})
        assert msg.type == "2fa_challenge"
        assert msg.message == "Enter code"
        assert msg.can_retry is False
        assert msg.is_error is False

    def test_error_with_can_retry(self):
        from app.ngfw.two_factor_ws import parse_challenge_frame

        msg = parse_challenge_frame({"type": "2fa_error", "payload": {"message": "Denied", "can_retry": True}})
        assert msg.is_error is True
        assert msg.can_retry is True
        assert msg.message == "Denied"

    def test_success_frame(self):
        from app.ngfw.two_factor_ws import MSG_SUCCESS, parse_challenge_frame

        msg = parse_challenge_frame({"type": MSG_SUCCESS, "payload": {}})
        assert msg.is_success is True

    def test_non_dict_or_missing_type_tolerated(self):
        from app.ngfw.two_factor_ws import parse_challenge_frame

        assert parse_challenge_frame(None).type == "unknown"
        assert parse_challenge_frame("nope").type == "unknown"
        assert parse_challenge_frame({"payload": {}}).type == "unknown"
        m = parse_challenge_frame({"type": "2fa_error"})
        assert m.message is None and m.can_retry is False


class _FakeWS:
    """Minimal stand-in for a ``websockets`` connection."""

    def __init__(self, frames=None):
        self._frames = list(frames or [])
        self.sent: list[str] = []
        self.closed = False

    async def recv(self):
        if not self._frames:
            from websockets.exceptions import ConnectionClosedOK

            raise ConnectionClosedOK(None, None)
        return self._frames.pop(0)

    async def send(self, data):
        self.sent.append(data)

    async def close(self):
        self.closed = True


def _patch_channel_transport(monkeypatch, connect_result):
    """Patch the address check + ``websockets.connect`` used by the channel.

    ``connect_result`` is either a _FakeWS to return, or an Exception to raise.
    """
    from app.ngfw import two_factor_ws as ws

    async def _noop_access(server):
        return None

    async def _connect(*args, **kwargs):
        if isinstance(connect_result, Exception):
            raise connect_result
        return connect_result

    monkeypatch.setattr(ws, "_enforce_current_access", _noop_access)
    monkeypatch.setattr(ws.websockets, "connect", _connect)


class TestNgfwTwoFactorChannel:
    """Unit tests for the challenge WebSocket wrapper (transport faked)."""

    @pytest.mark.asyncio
    async def test_open_success_sets_socket(self, monkeypatch):
        from app.ngfw.two_factor_ws import NgfwTwoFactorChannel

        fake = _FakeWS()
        _patch_channel_transport(monkeypatch, fake)
        ch = NgfwTwoFactorChannel(NGFW_SERVER, {NGFW_SESSION_COOKIE: NGFW_SESSION_VALUE})
        await ch.open()
        assert ch._ws is fake

    @pytest.mark.asyncio
    async def test_open_sends_origin_and_cookie(self, monkeypatch):
        # NGFW validates a same-origin Origin on the challenge socket; without it
        # it refuses to issue a challenge (2fa_error). Mirror the browser.
        from app.ngfw import two_factor_ws as ws
        from app.ngfw.two_factor_ws import NgfwTwoFactorChannel

        captured: dict = {}

        async def _noop_access(server):
            return None

        async def _connect(url, **kwargs):
            captured["url"] = url
            captured["kwargs"] = kwargs
            return _FakeWS()

        monkeypatch.setattr(ws, "_enforce_current_access", _noop_access)
        monkeypatch.setattr(ws.websockets, "connect", _connect)

        ch = NgfwTwoFactorChannel(NGFW_SERVER, {NGFW_SESSION_COOKIE: NGFW_SESSION_VALUE})
        await ch.open()

        headers = captured["kwargs"]["additional_headers"]
        assert headers["Origin"] == f"https://{NGFW_SERVER}:8443"
        assert NGFW_SESSION_VALUE in headers["Cookie"]
        assert captured["url"] == f"wss://{NGFW_SERVER}:8443/web/two_factor/challenge"

    @pytest.mark.asyncio
    async def test_open_rejected_handshake_is_expired(self, monkeypatch):
        from websockets.exceptions import InvalidStatus

        from app.errors import StuckError
        from app.ngfw.two_factor_ws import NgfwTwoFactorChannel

        _patch_channel_transport(monkeypatch, InvalidStatus(SimpleNamespace(status_code=401)))
        ch = NgfwTwoFactorChannel(NGFW_SERVER, {NGFW_SESSION_COOKIE: NGFW_SESSION_VALUE})
        with pytest.raises(StuckError) as exc:
            await ch.open()
        assert exc.value.code == "second_factor_expired"

    @pytest.mark.asyncio
    async def test_open_transport_error_is_unreachable(self, monkeypatch):
        from app.errors import StuckError
        from app.ngfw.two_factor_ws import NgfwTwoFactorChannel

        _patch_channel_transport(monkeypatch, OSError("boom"))
        ch = NgfwTwoFactorChannel(NGFW_SERVER, {NGFW_SESSION_COOKIE: NGFW_SESSION_VALUE})
        with pytest.raises(StuckError) as exc:
            await ch.open()
        assert exc.value.code == "server_unreachable"

    @pytest.mark.asyncio
    async def test_recv_typed_parses_challenge(self, monkeypatch):
        from app.ngfw.two_factor_ws import NgfwTwoFactorChannel

        frame = json.dumps({"type": "2fa_challenge", "payload": {"message": "hi"}})
        _patch_channel_transport(monkeypatch, _FakeWS([frame]))
        ch = NgfwTwoFactorChannel(NGFW_SERVER, {NGFW_SESSION_COOKIE: NGFW_SESSION_VALUE})
        await ch.open()
        msg = await ch.recv_typed(timeout=1)
        assert msg.type == "2fa_challenge"
        assert msg.message == "hi"

    @pytest.mark.asyncio
    async def test_recv_typed_invalid_json_is_unknown(self, monkeypatch):
        from app.ngfw.two_factor_ws import NgfwTwoFactorChannel

        _patch_channel_transport(monkeypatch, _FakeWS(["not json {{"]))
        ch = NgfwTwoFactorChannel(NGFW_SERVER, {NGFW_SESSION_COOKIE: NGFW_SESSION_VALUE})
        await ch.open()
        msg = await ch.recv_typed(timeout=1)
        assert msg.type == "unknown"

    @pytest.mark.asyncio
    async def test_recv_typed_clean_close_is_closed_sentinel(self, monkeypatch):
        from app.ngfw.two_factor_ws import MSG_CLOSED, NgfwTwoFactorChannel

        _patch_channel_transport(monkeypatch, _FakeWS([]))
        ch = NgfwTwoFactorChannel(NGFW_SERVER, {NGFW_SESSION_COOKIE: NGFW_SESSION_VALUE})
        await ch.open()
        msg = await ch.recv_typed(timeout=1)
        assert msg.type == MSG_CLOSED
        assert msg.is_error is False

    @pytest.mark.asyncio
    async def test_recv_typed_timeout_is_expired(self, monkeypatch):
        from app.errors import StuckError
        from app.ngfw.two_factor_ws import NgfwTwoFactorChannel

        class _HangingWS(_FakeWS):
            async def recv(self):
                await asyncio.sleep(10)

        _patch_channel_transport(monkeypatch, _HangingWS())
        ch = NgfwTwoFactorChannel(NGFW_SERVER, {NGFW_SESSION_COOKIE: NGFW_SESSION_VALUE})
        await ch.open()
        with pytest.raises(StuckError) as exc:
            await ch.recv_typed(timeout=0.05)
        assert exc.value.code == "second_factor_expired"

    @pytest.mark.asyncio
    async def test_send_start_wire_shape(self, monkeypatch):
        from app.ngfw.two_factor_ws import NgfwTwoFactorChannel

        fake = _FakeWS()
        _patch_channel_transport(monkeypatch, fake)
        ch = NgfwTwoFactorChannel(NGFW_SERVER, {NGFW_SESSION_COOKIE: NGFW_SESSION_VALUE})
        await ch.open()
        await ch.send_start()
        assert fake.sent == [json.dumps({"type": "2fa_start", "payload": {}})]

    @pytest.mark.asyncio
    async def test_send_code_wire_shape(self, monkeypatch):
        from app.ngfw.two_factor_ws import NgfwTwoFactorChannel

        fake = _FakeWS()
        _patch_channel_transport(monkeypatch, fake)
        ch = NgfwTwoFactorChannel(NGFW_SERVER, {NGFW_SESSION_COOKIE: NGFW_SESSION_VALUE})
        await ch.open()
        await ch.send_code("123456")
        assert fake.sent == [json.dumps({"type": "2fa_challenge", "payload": {"2fa_code": "123456"}})]

    @pytest.mark.asyncio
    async def test_close_is_idempotent(self, monkeypatch):
        from app.ngfw.two_factor_ws import NgfwTwoFactorChannel

        fake = _FakeWS()
        _patch_channel_transport(monkeypatch, fake)
        ch = NgfwTwoFactorChannel(NGFW_SERVER, {NGFW_SESSION_COOKIE: NGFW_SESSION_VALUE})
        await ch.open()
        await ch.close()
        await ch.close()
        assert fake.closed is True


_BLOCKED_WHOAMI = {
    "login": "mfa",
    "blocked_flags": 1,
    "role_id": "",
    "role_name": "",
    "two_factor": "",
    "admin_id": "admin.id.123",
}


def _install_fake_channel(monkeypatch, frames):
    """Script the single, held challenge socket for a whole 2FA session.

    ONE ``NgfwTwoFactorChannel`` is opened (on the first ``/2fa``) and reused for
    every retry, so ``frames`` is the full sequence its ``recv_typed`` yields
    across all attempts (challenge, verdict, challenge, verdict, …). Returns a
    holder whose ``channels`` list grows one entry per opened socket.
    """
    from app.errors import StuckError

    holder: dict = {"channels": []}

    class _FakeChannel:
        def __init__(self, server, cookies):
            self.server = server
            self.cookies = cookies
            self._frames = list(frames)
            self.sent: list[str] = []
            self.started = False
            self.closed = False
            holder["channels"].append(self)

        async def open(self):
            self.opened = True

        async def send_start(self):
            self.started = True

        async def recv_typed(self, *, timeout=None):
            if not self._frames:
                raise StuckError("second_factor_expired", "no more frames")
            return self._frames.pop(0)

        async def send_code(self, code):
            self.sent.append(code)

        async def close(self):
            self.closed = True

    monkeypatch.setattr("app.api.auth.NgfwTwoFactorChannel", _FakeChannel)
    return holder


class TestTwoFactorEndpointFlow:
    """login → /2fa flow with the NGFW HTTP mocked (respx) and the WS faked."""

    def test_login_2fa_branch_opens_no_socket(self, client: TestClient, ngfw_mock, valid_login_data, monkeypatch):
        # Login must never touch the challenge WebSocket: it only arms the form,
        # so a locked/erroring challenge can never block re-authentication.
        ngfw_mock.state["whoami"] = (200, _BLOCKED_WHOAMI)
        holder = _install_fake_channel(monkeypatch, [])

        resp = client.post("/api/auth/login", json=valid_login_data)
        assert resp.status_code == 200
        body = resp.json()
        assert body["two_factor_required"] is True
        assert isinstance(body["expires_at"], str)
        assert _stuck_2fa_cookie_header(resp) is not None
        assert _stuck_session_cookie_set(resp) is False
        assert "session" not in body
        assert NGFW_SESSION_VALUE not in resp.text
        assert holder["channels"] == []  # no socket opened during login

    def test_2fa_success_creates_session(self, client: TestClient, ngfw_mock, valid_login_data, monkeypatch):
        # Confirmed live NGFW success frame: {"type": "2fa_success", "payload": {}}.
        from app.ngfw.two_factor_ws import MSG_SUCCESS, TwoFactorMessage

        original_whoami = ngfw_mock.state["whoami"]
        ngfw_mock.state["whoami"] = (200, _BLOCKED_WHOAMI)
        holder = _install_fake_channel(monkeypatch, [TwoFactorMessage("2fa_challenge"), TwoFactorMessage(MSG_SUCCESS)])

        assert client.post("/api/auth/login", json=valid_login_data).json()["two_factor_required"] is True
        ngfw_mock.state["whoami"] = original_whoami

        resp = client.post("/api/auth/2fa", json={"code": "123456"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["ok"] is True and "session" in body
        assert _stuck_session_cookie_set(resp) is True
        header = _stuck_2fa_cookie_header(resp)
        assert header is not None and ("max-age=0" in header.lower() or 'stuck_2fa=""' in header)
        # The code was relayed and the socket was closed on success.
        assert holder["channels"][0].sent == ["123456"]
        assert holder["channels"][0].closed is True

    def test_2fa_clean_close_fallback_succeeds(self, client: TestClient, ngfw_mock, valid_login_data, monkeypatch):
        # Defensive fallback: a clean close with no explicit success frame is a
        # success candidate, confirmed by an unblocked whoami.
        from app.ngfw.two_factor_ws import MSG_CLOSED, TwoFactorMessage

        original_whoami = ngfw_mock.state["whoami"]
        ngfw_mock.state["whoami"] = (200, _BLOCKED_WHOAMI)
        _install_fake_channel(monkeypatch, [TwoFactorMessage("2fa_challenge"), TwoFactorMessage(MSG_CLOSED)])

        client.post("/api/auth/login", json=valid_login_data)
        ngfw_mock.state["whoami"] = original_whoami
        resp = client.post("/api/auth/2fa", json={"code": "123456"})
        assert resp.status_code == 200
        assert "session" in resp.json()

    def test_2fa_wrong_codes_then_correct_on_one_socket(
        self, client: TestClient, ngfw_mock, valid_login_data, monkeypatch
    ):
        # Wrong codes then a correct one, all retried on the SAME held socket
        # (challenge → code → error → challenge → …), within NGFW's 3 attempts —
        # so the correct code still logs in. Exactly one socket is opened (opening
        # a fresh socket per code is what trips NGFW's lockout).
        from app.ngfw.two_factor_ws import MSG_SUCCESS, TwoFactorMessage

        original_whoami = ngfw_mock.state["whoami"]
        ngfw_mock.state["whoami"] = (200, _BLOCKED_WHOAMI)
        holder = _install_fake_channel(
            monkeypatch,
            [
                TwoFactorMessage("2fa_challenge"),
                TwoFactorMessage("2fa_error", message="Denied", can_retry=True),
                TwoFactorMessage("2fa_challenge"),
                TwoFactorMessage("2fa_error", message="Denied", can_retry=True),
                TwoFactorMessage("2fa_challenge"),
                TwoFactorMessage(MSG_SUCCESS),
            ],
        )

        client.post("/api/auth/login", json=valid_login_data)
        for code in ("000000", "111111"):
            bad = client.post("/api/auth/2fa", json={"code": code})
            assert bad.json()["error"]["code"] == "second_factor_invalid"
            assert bad.json()["error"]["details"]["can_retry"] is True

        ngfw_mock.state["whoami"] = original_whoami
        good = client.post("/api/auth/2fa", json={"code": "123456"})
        assert good.status_code == 200
        assert "session" in good.json()
        # One socket served all attempts (the key to avoiding NGFW's lockout).
        assert len(holder["channels"]) == 1
        assert holder["channels"][0].sent == ["000000", "111111", "123456"]

    def test_2fa_non_retryable_error_resets_to_login(
        self, client: TestClient, ngfw_mock, valid_login_data, monkeypatch
    ):
        # NGFW's own terminal rejection (can_retry=false) → reset to login so the
        # admin sees the notice (NGFW decided, not STUCK).
        from app.ngfw.two_factor_ws import TwoFactorMessage

        ngfw_mock.state["whoami"] = (200, _BLOCKED_WHOAMI)
        _install_fake_channel(
            monkeypatch, [TwoFactorMessage("2fa_challenge"), TwoFactorMessage("2fa_error", can_retry=False)]
        )

        client.post("/api/auth/login", json=valid_login_data)
        resp = client.post("/api/auth/2fa", json={"code": "000000"})
        assert resp.status_code == 401
        assert resp.json()["error"]["code"] == "second_factor_expired"
        assert ngfw_mock.routes["logout"].called

    def test_2fa_without_pending_is_expired(self, client: TestClient, ngfw_mock):
        resp = client.post("/api/auth/2fa", json={"code": "123456"})
        assert resp.status_code == 401
        assert resp.json()["error"]["code"] == "second_factor_expired"

    def test_2fa_error_before_challenge_resets_without_hanging(
        self, client: TestClient, ngfw_mock, valid_login_data, monkeypatch
    ):
        # NGFW would not issue a challenge (a previous one is still winding down,
        # or the account is locked). Reset to login without hanging.
        from app.ngfw.two_factor_ws import TwoFactorMessage

        ngfw_mock.state["whoami"] = (200, _BLOCKED_WHOAMI)
        _install_fake_channel(monkeypatch, [TwoFactorMessage("2fa_error", message="Access denied", can_retry=True)])

        client.post("/api/auth/login", json=valid_login_data)
        resp = client.post("/api/auth/2fa", json={"code": "123456"})
        assert resp.status_code == 401
        assert resp.json()["error"]["code"] == "second_factor_expired"

    def test_2fa_cancelled_frame_resets_to_login(self, client: TestClient, ngfw_mock, valid_login_data, monkeypatch):
        # 2fa_cancelled before a challenge means the challenge is gone → reset.
        from app.ngfw.two_factor_ws import TwoFactorMessage

        ngfw_mock.state["whoami"] = (200, _BLOCKED_WHOAMI)
        _install_fake_channel(monkeypatch, [TwoFactorMessage("2fa_cancelled")])

        client.post("/api/auth/login", json=valid_login_data)
        resp = client.post("/api/auth/2fa", json={"code": "123456"})
        assert resp.status_code == 401
        assert resp.json()["error"]["code"] == "second_factor_expired"

    def test_2fa_retryable_errors_never_cap_on_backend(
        self, client: TestClient, ngfw_mock, valid_login_data, monkeypatch
    ):
        # The backend imposes NO attempt limit — it relays NGFW's verdict and the
        # frontend enforces "reset after 3". Many retryable errors stay invalid.
        from app.ngfw.two_factor_ws import TwoFactorMessage

        ngfw_mock.state["whoami"] = (200, _BLOCKED_WHOAMI)
        _install_fake_channel(
            monkeypatch,
            [
                f
                for _ in range(5)
                for f in (TwoFactorMessage("2fa_challenge"), TwoFactorMessage("2fa_error", can_retry=True))
            ],
        )

        client.post("/api/auth/login", json=valid_login_data)
        for _ in range(5):
            resp = client.post("/api/auth/2fa", json={"code": "000000"})
            assert resp.json()["error"]["code"] == "second_factor_invalid"

    def test_relogin_after_failure_reaches_the_form(self, client: TestClient, ngfw_mock, valid_login_data, monkeypatch):
        # Regression: a re-login after a rejected code must reach the code form
        # again (login opens no socket), not fail with "invalid code".
        from app.ngfw.two_factor_ws import TwoFactorMessage

        ngfw_mock.state["whoami"] = (200, _BLOCKED_WHOAMI)
        _install_fake_channel(
            monkeypatch, [TwoFactorMessage("2fa_challenge"), TwoFactorMessage("2fa_error", can_retry=True)]
        )

        client.post("/api/auth/login", json=valid_login_data)
        client.post("/api/auth/2fa", json={"code": "000000"})  # rejected (retryable)
        again = client.post("/api/auth/login", json=valid_login_data)
        assert again.status_code == 200
        assert again.json()["two_factor_required"] is True

    def test_relogin_closes_previous_challenge_socket(
        self, client: TestClient, ngfw_mock, valid_login_data, monkeypatch
    ):
        # A new login must tear down this browser's previous 2FA challenge socket,
        # so NGFW gives the fresh login a fresh challenge (a lingering old socket
        # makes NGFW refuse the new one).
        from app.ngfw.two_factor_ws import TwoFactorMessage

        ngfw_mock.state["whoami"] = (200, _BLOCKED_WHOAMI)
        holder = _install_fake_channel(
            monkeypatch, [TwoFactorMessage("2fa_challenge"), TwoFactorMessage("2fa_error", can_retry=True)]
        )

        client.post("/api/auth/login", json=valid_login_data)
        client.post("/api/auth/2fa", json={"code": "000000"})  # opens + holds the socket
        socket = holder["channels"][0]
        assert socket.closed is False  # held for retries

        client.post("/api/auth/login", json=valid_login_data)  # re-login → tears it down
        assert socket.closed is True
        assert ngfw_mock.routes["logout"].called

    def test_session_reports_pending_2fa_on_reload(self, client: TestClient, ngfw_mock, valid_login_data, monkeypatch):
        # After the password step, a page reload (GET /api/session with only the
        # stuck_2fa cookie) must resume the code form, not drop to a fresh login.
        ngfw_mock.state["whoami"] = (200, _BLOCKED_WHOAMI)
        _install_fake_channel(monkeypatch, [])  # login opens no socket

        client.post("/api/auth/login", json=valid_login_data)
        resp = client.get("/api/session")
        assert resp.status_code == 200
        body = resp.json()
        assert body["two_factor_pending"] is True
        assert body["authenticated"] is False
        assert isinstance(body["expires_at"], str)
        assert "login" not in body  # no session identity leaked


class TestPendingSweeper:
    """The background sweeper releases challenges abandoned by the browser
    (tab closed / device offline) so neither memory nor an NGFW session leaks."""

    @pytest.mark.asyncio
    async def test_sweeper_logs_out_expired_pending(self, monkeypatch):
        import contextlib
        import time
        from types import SimpleNamespace

        from app import main
        from app.domain.pending_2fa import PendingTwoFactorStore

        store = PendingTwoFactorStore(ttl_seconds=1)
        entry = store.create(NGFW_SERVER, {NGFW_SESSION_COOKIE: NGFW_SESSION_VALUE}, "admin", None)
        entry.expires_at = time.time() - 1  # already abandoned/expired

        logged_out: list[str] = []

        async def _fake_logout(server, cookies):
            logged_out.append(server)

        monkeypatch.setattr(main, "ngfw_logout", _fake_logout)

        app = SimpleNamespace(state=SimpleNamespace(pending_2fa_store=store))
        task = asyncio.create_task(main._sweep_pending_2fa(app, interval=0.01))
        await asyncio.sleep(0.05)
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

        # The orphaned provisional NGFW session was closed and the entry removed.
        assert logged_out == [NGFW_SERVER]
        assert store.get(entry.pending_id) is None
