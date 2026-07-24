"""Tests for structured logging and secret masking (Phase 2.5, NFR-S5).

End-to-end assertions attach a capture handler configured EXACTLY like the
production one (KeyValueFormatter + SecretMaskingFilter, see
app/logging_setup.py:configure_logging), so the rendered text matches what
would reach stdout/file in production. Unit assertions exercise the masking
helpers directly.
"""

import logging
from io import StringIO

import pytest
from fastapi.testclient import TestClient

from app.logging_setup import (
    MASK,
    KeyValueFormatter,
    SecretMaskingFilter,
    scrub_text,
)


@pytest.fixture
def log_capture():
    """Capture root-logger output through the production formatter+filter."""
    stream = StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(KeyValueFormatter())
    handler.addFilter(SecretMaskingFilter())
    root = logging.getLogger()
    root.addHandler(handler)
    try:
        yield stream
    finally:
        root.removeHandler(handler)


class TestScrubHelpers:
    """Unit tests for the central masking helpers."""

    def test_scrub_password_kv(self):
        assert "hunter2" not in scrub_text("password=hunter2")
        assert "hunter2" not in scrub_text('{"password": "hunter2"}')
        assert "hunter2" not in scrub_text("psw='hunter2'")

    def test_scrub_session_cookies(self):
        assert "abc123" not in scrub_text("stuck_session=abc123; Path=/")
        assert "abc123" not in scrub_text("insecure-ideco-session=abc123")
        assert "abc123" not in scrub_text("__Secure-ideco-x=abc123")

    def test_scrub_cookie_header(self):
        text = "set-cookie: stuck_session=verysecret; HttpOnly"
        assert "verysecret" not in scrub_text(text)

    def test_scrub_keeps_normal_text(self):
        text = "request method=GET path=/api/health status=200"
        assert scrub_text(text) == text

    def test_filter_masks_structured_fields(self):
        record = logging.LogRecord(
            name="stuck.test",
            level=logging.INFO,
            pathname=__file__,
            lineno=1,
            msg="event",
            args=(),
            exc_info=None,
        )
        record.stuck_fields = {"login": "admin", "password": "hunter2"}
        assert SecretMaskingFilter().filter(record) is True
        assert record.stuck_fields["password"] == MASK
        assert record.stuck_fields["login"] == "admin"


class TestNoSecretsInLogs:
    """NFR-S5: password and session cookie values never reach log output."""

    def test_password_not_in_login_logs(self, client: TestClient, ngfw_mock, valid_login_data, log_capture):
        resp = client.post("/api/auth/login", json=valid_login_data)
        assert resp.status_code == 200

        logs = log_capture.getvalue()
        assert logs, "expected some log output from the login request"
        assert valid_login_data["password"] not in logs

    def test_password_not_in_logs_on_failed_login(self, client: TestClient, ngfw_mock, valid_login_data, log_capture):
        ngfw_mock.state["login"] = (401, {"message": "no"})

        resp = client.post("/api/auth/login", json=valid_login_data)
        assert resp.status_code == 401

        assert valid_login_data["password"] not in log_capture.getvalue()

    def test_password_not_in_logs_on_validation_error(self, client: TestClient, ngfw_mock, log_capture):
        """Bad request body with a password field: value must not hit the logs."""
        secret = "Sup3r-S3cret-Value"

        resp = client.post(
            "/api/auth/login",
            json={"login": "", "password": secret, "server": "192.168.1.1"},
        )
        assert resp.status_code == 400

        assert secret not in log_capture.getvalue()
        # And it must not be echoed in the response either (contract: no echo).
        assert secret not in resp.text

    def test_session_cookie_value_not_in_logs(self, client: TestClient, ngfw_mock, valid_login_data, log_capture):
        resp = client.post("/api/auth/login", json=valid_login_data)
        assert resp.status_code == 200
        stuck_session = resp.cookies.get("stuck_session")
        assert stuck_session

        # Exercise authenticated endpoints too (cookie travels with requests).
        client.get("/api/session")
        client.get("/api/users")

        assert stuck_session not in log_capture.getvalue()


class TestEventLogging:
    """Phase 2.5: requests, NGFW calls, errors and trace results are logged."""

    def test_request_access_log(self, client: TestClient, log_capture):
        client.get("/api/session")

        logs = log_capture.getvalue()
        assert "request" in logs
        assert "/api/session" in logs

    def test_typed_error_logged_with_code(self, client: TestClient, ngfw_mock, valid_login_data, log_capture):
        ngfw_mock.state["login"] = (401, {"message": "no"})

        client.post("/api/auth/login", json=valid_login_data)

        assert "invalid_credentials" in log_capture.getvalue()

    def test_ngfw_call_logged(self, client: TestClient, ngfw_mock, valid_login_data, log_capture):
        client.post("/api/auth/login", json=valid_login_data)

        logs = log_capture.getvalue()
        assert "ngfw_call" in logs
        assert "/web/auth/login" in logs

    def test_trace_result_logged(self, authenticated_client: TestClient, log_capture):
        resp = authenticated_client.post("/api/trace", json={"url": "example.com"})
        assert resp.status_code == 200

        logs = log_capture.getvalue()
        assert "trace_result" in logs
        assert "example.com" in logs
        assert "verdict=" in logs
