"""Unit checks kept alongside the opt-in NGFW test-data tool."""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from tools.ngfw_testdata.cli import _admin_login, _parser
from tools.ngfw_testdata.client import NgfwApiClient, parse_target
from tools.ngfw_testdata.errors import (
    ApiError,
    AuthorizationError,
    ConflictError,
    InputError,
)
from tools.ngfw_testdata.seeder import (
    ROOT_VCE_GROUP_ID,
    NgfwTestDataSeeder,
    SeedOptions,
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("ngfw.example:8443", "https://ngfw.example:8443"),
        ("192.168.100.11:8443", "https://192.168.100.11:8443"),
        ("[2001:db8::1]:8443", "https://[2001:db8::1]:8443"),
    ],
)
def test_parse_target_requires_host_and_port(raw: str, expected: str) -> None:
    assert parse_target(raw) == expected


@pytest.mark.parametrize(
    "raw",
    ["", "ngfw.example", "https://ngfw.example:8443", "ngfw.example:70000"],
)
def test_parse_target_rejects_unsafe_or_incomplete_values(raw: str) -> None:
    with pytest.raises(InputError):
        parse_target(raw)


def test_admin_login_is_requested_when_argument_is_omitted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("builtins.input", lambda prompt: "  admin@domain.test  ")

    assert _admin_login(None) == "admin@domain.test"


def test_empty_prompted_admin_login_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("builtins.input", lambda prompt: "   ")

    with pytest.raises(InputError, match="не может быть пустым"):
        _admin_login(None)


def test_tls_verification_is_opt_in() -> None:
    default_args = _parser().parse_args(["--target", "ngfw.example:8443"])
    verified_args = _parser().parse_args(["--target", "ngfw.example:8443", "--verify-tls"])

    assert default_args.verify_tls is False
    assert verified_args.verify_tls is True


def test_applying_changes_is_the_default_mode() -> None:
    default_args = _parser().parse_args(["--target", "ngfw.example:8443"])
    dry_run_args = _parser().parse_args(["--target", "ngfw.example:8443", "--dry-run"])

    assert default_args.dry_run is False
    assert dry_run_args.dry_run is True


def test_write_403_is_reported_as_read_only_permission_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/web/auth/login" and request.method == "POST":
            return httpx.Response(
                200,
                headers={"set-cookie": "insecure-ideco-session=test; Path=/"},
                json={"ok": True},
            )
        if request.url.path == "/web/auth/login" and request.method == "DELETE":
            return httpx.Response(200, json={})
        return httpx.Response(403, json={"message": "read only administrator"})

    transport = httpx.MockTransport(handler)
    with (
        NgfwApiClient(
            "ngfw.example:8443",
            "readonly",
            "secret",
            transport=transport,
        ) as client,
        pytest.raises(AuthorizationError, match="запретил операцию") as caught,
    ):
        client.post("/aliases/ip_addresses", {"value": "203.0.113.10"})

    assert "только чтение" in (caught.value.hint or "")


def test_api_error_never_echoes_submitted_password() -> None:
    test_password = "St9!must-not-leak"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/web/auth/login":
            return httpx.Response(
                200,
                headers={"set-cookie": "insecure-ideco-session=test; Path=/"},
                json={"ok": True},
            )
        return httpx.Response(400, json={"message": f"invalid psw {test_password}"})

    transport = httpx.MockTransport(handler)
    with (
        NgfwApiClient("ngfw.example:8443", "admin", "admin-secret", transport=transport) as client,
        pytest.raises(ApiError) as caught,
    ):
        client.post("/user_backend/users", {"psw": test_password})

    assert test_password not in str(caught.value)
    assert "[REDACTED]" in str(caught.value)


class _FakeClient:
    def __init__(self, *, deny_writes: bool = False) -> None:
        self.deny_writes = deny_writes
        self.posts: list[tuple[str, dict[str, Any], dict[str, Any] | None]] = []
        self.patches: list[tuple[str, dict[str, Any]]] = []
        self.deletes: list[str] = []
        self._counter = 10
        self.aliases: dict[str, list[dict[str, Any]]] = {
            "/aliases/ip_addresses": [],
            "/aliases/domains": [],
            "/aliases/ports": [],
        }
        self.content_filter_rules: list[dict[str, Any]] = []
        self.hw_rules: dict[str, list[dict[str, Any]]] = {
            "/firewall/hw_rules_src_ip": [],
            "/firewall/hw_rules_dst_ip": [],
            "/firewall/hw_rules_src_dst_ip": [],
        }
        self.firewall_rules: list[dict[str, Any]] = [
            {
                "id": "fwd.ngfw.1",
                "parent_id": ROOT_VCE_GROUP_ID,
                "comment": "existing allow",
            }
        ]

    def get(self, path: str, *, params: dict[str, Any] | None = None) -> Any:
        if path == "/user_backend/groups":
            return [
                {
                    "id": "group.id.1",
                    "name": "Все локальные",
                    "parent_id": "",
                    "domain_type": "local",
                }
            ]
        if path == "/firewall/rules/forward":
            return self.firewall_rules
        if path == "/content-filter/rules":
            return self.content_filter_rules
        if path in self.aliases:
            return self.aliases[path]
        if path == "/firewall/hw_settings":
            return {"mode": "src-ip"}
        if path in self.hw_rules:
            return self.hw_rules[path]
        if path in ("/firewall/state", "/content-filter/state", "/ips/state"):
            return {"enabled": True}
        return []

    def post(
        self,
        path: str,
        body: dict[str, Any],
        *,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if self.deny_writes:
            raise AuthorizationError("read only")
        self.posts.append((path, body, params))
        self._counter += 1
        if path == "/user_backend/groups":
            return {"id": self._counter}
        if path == "/user_backend/users":
            return {"id": self._counter}
        created_id = f"test.id.{self._counter}"
        if path in self.aliases:
            self.aliases[path].append({**body, "id": created_id})
        elif path == "/content-filter/rules":
            self.content_filter_rules.insert(0, {**body, "id": created_id})
        elif path == "/firewall/rules/forward":
            self.firewall_rules.insert(0, {**body, "id": created_id})
        elif path in self.hw_rules:
            self.hw_rules[path].append({**body, "id": created_id})
        return {"id": created_id}

    def patch(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        self.patches.append((path, body))
        return {}

    def delete(self, path: str) -> None:
        self.deletes.append(path)


class _NumericRootFakeClient(_FakeClient):
    def get(self, path: str, *, params: dict[str, Any] | None = None) -> Any:
        if path == "/user_backend/groups":
            return [
                {
                    "id": 1,
                    "name": "Все локальные",
                    "parent_id": None,
                    "domain_type": "local",
                }
            ]
        return super().get(path, params=params)


def test_ui_parent_id_is_resolved_to_numeric_api_id() -> None:
    client = _NumericRootFakeClient()

    NgfwTestDataSeeder(
        client,  # type: ignore[arg-type]
        SeedOptions(test_user_password="St9!safe-test-password"),
        emit=lambda _: None,
    ).seed(apply=True)

    group_post = next(item for item in client.posts if item[0] == "/user_backend/groups")
    user_post = next(item for item in client.posts if item[0] == "/user_backend/users")
    cf_posts = [item for item in client.posts if item[0] == "/content-filter/rules"]

    assert group_post[1]["parent_id"] == 1
    assert user_post[1]["parent_id"] == "11"
    assert all(item[1]["src_aliases"] == [{"aliases": ["user.id.12"], "negate": False}] for item in cf_posts)


def test_unlisted_custom_parent_is_still_rejected() -> None:
    client = _NumericRootFakeClient()

    with pytest.raises(ConflictError, match="не найдена"):
        NgfwTestDataSeeder(
            client,  # type: ignore[arg-type]
            SeedOptions(parent_group_id="group.id.404"),
            emit=lambda _: None,
        ).seed(apply=False)


def test_dry_run_builds_full_plan_without_writes() -> None:
    client = _FakeClient()
    output: list[str] = []
    summary = NgfwTestDataSeeder(
        client,  # type: ignore[arg-type]
        SeedOptions(),
        emit=output.append,
    ).seed(apply=False)

    assert len(summary.planned) == 19
    assert client.posts == []
    assert client.patches == []
    assert any("cf-block.example" in line for line in output)
    assert any("Ограничение скорости не добавлено" in warning for warning in summary.warnings)


def test_apply_creates_prefixed_resources_and_inserts_rules_first() -> None:
    client = _FakeClient()
    output: list[str] = []
    summary = NgfwTestDataSeeder(
        client,  # type: ignore[arg-type]
        SeedOptions(test_user_password="St9!safe-test-password"),
        emit=output.append,
    ).seed(apply=True)

    assert len(summary.created) == 19
    assert len(client.posts) == 19
    assert all(
        item[1].get("name", item[1].get("title", "STUCK TEST")).startswith("STUCK TEST")
        for item in client.posts
        if item[0] not in ("/firewall/rules/forward", "/ips/bypass")
    )
    firewall_posts = [item for item in client.posts if item[0] == "/firewall/rules/forward"]
    assert len(firewall_posts) == 4
    assert all(item[2] is not None for item in firewall_posts)
    assert all(item[2]["insert_after"] == "false" for item in firewall_posts if item[2])
    assert all(item[1]["source_ports"] == ["any"] for item in firewall_posts)
    assert all(item[1]["destination_ports"] == ["any"] for item in firewall_posts[:3])
    assert firewall_posts[3][1]["destination_ports"] != ["any"]
    assert all(item[1]["incoming_interface"] == "any" for item in firewall_posts)
    assert all(item[1]["outgoing_interface"] == "any" for item in firewall_posts)
    assert all(item[1]["hip_profiles_negate"] is False for item in firewall_posts)
    assert all(item[1]["timetable"] == ["any"] for item in firewall_posts)
    assert [rule["comment"] for rule in client.firewall_rules[:4]] == [
        "[STUCK TEST] FW drop 198.51.100.25:9443",
        "[STUCK TEST] FW allow 198.51.100.25:any",
        "[STUCK TEST] FW drop example.org",
        "[STUCK TEST] FW reject 203.0.113.10",
    ]
    assert sum(line.startswith("[OBJECT OK]") for line in output) == 5


class _UnpersistedAliasFakeClient(_FakeClient):
    def post(
        self,
        path: str,
        body: dict[str, Any],
        *,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        response = super().post(path, body, params=params)
        if path in self.aliases:
            self.aliases[path].clear()
        return response


def test_created_object_is_read_back_and_verified() -> None:
    client = _UnpersistedAliasFakeClient()

    with pytest.raises(ConflictError, match="не найден при проверке"):
        NgfwTestDataSeeder(
            client,  # type: ignore[arg-type]
            SeedOptions(test_user_password="St9!safe-test-password"),
            emit=lambda _: None,
        ).seed(apply=True)

    assert any(path.startswith("/aliases/ip_addresses/") for path in client.deletes)


def test_read_only_failure_does_not_delete_preexisting_data() -> None:
    client = _FakeClient(deny_writes=True)
    seeder = NgfwTestDataSeeder(
        client,  # type: ignore[arg-type]
        SeedOptions(test_user_password="St9!safe-test-password"),
        emit=lambda _: None,
    )

    with pytest.raises(AuthorizationError):
        seeder.seed(apply=True)

    assert client.deletes == []


class _ExistingFakeClient(_FakeClient):
    def get(self, path: str, *, params: dict[str, Any] | None = None) -> Any:
        if path == "/user_backend/groups":
            return [
                {"id": "group.id.1", "name": "Все локальные", "parent_id": ""},
                {
                    "id": "group.id.20",
                    "name": "STUCK TEST - group",
                    "parent_id": "group.id.1",
                },
            ]
        if path == "/user_backend/users":
            return [
                {
                    "id": "user.id.20",
                    "name": "STUCK TEST - user",
                    "login": "stuck-test-user",
                    "parent_id": "group.id.20",
                }
            ]
        if path == "/aliases/ip_addresses":
            return [
                {
                    "id": "ip.id.20",
                    "title": "STUCK TEST - FW block IP",
                    "value": "203.0.113.10",
                },
                {
                    "id": "ip.id.21",
                    "title": "STUCK TEST - IPS bypass",
                    "value": "192.0.2.30",
                },
                {
                    "id": "ip.id.22",
                    "title": "STUCK TEST - FW port target",
                    "value": "198.51.100.25",
                },
            ]
        if path == "/aliases/ports":
            return [
                {
                    "id": "port.id.20",
                    "title": "STUCK TEST - FW blocked port",
                    "value": 9443,
                }
            ]
        if path == "/aliases/domains":
            return [
                {
                    "id": "domain.id.20",
                    "title": "STUCK TEST - FW block domain",
                    "value": "example.org",
                }
            ]
        if path == "/content-filter/users_categories":
            return [
                {
                    "id": "users.id.20",
                    "name": "STUCK TEST - CF block category",
                    "urls": ["cf-block.example"],
                },
                {
                    "id": "users.id.21",
                    "name": "STUCK TEST - CF redirect category",
                    "urls": ["cf-redirect.example"],
                },
            ]
        if path == "/content-filter/rules":
            return [
                {
                    "id": 21,
                    "name": "STUCK TEST - CF redirect",
                    "src_aliases": [{"aliases": ["user.id.20"], "negate": False}],
                    "categories": ["users.id.21"],
                    "access": "redirect",
                    "redirect_url": "https://example.com/",
                },
                {
                    "id": 20,
                    "name": "STUCK TEST - CF deny",
                    "src_aliases": [{"aliases": ["user.id.20"], "negate": False}],
                    "categories": ["users.id.20"],
                    "access": "deny",
                    "redirect_url": None,
                },
            ]
        if path == "/firewall/rules/forward":
            return [
                {
                    "id": "fwd.ngfw.23",
                    "comment": "[STUCK TEST] FW drop 198.51.100.25:9443",
                    "sources": [{"addresses": ["user.id.20"]}],
                    "destinations": [{"addresses": ["ip.id.22"]}],
                    "destination_ports": ["port.id.20"],
                    "action": "drop",
                },
                {
                    "id": "fwd.ngfw.22",
                    "comment": "[STUCK TEST] FW allow 198.51.100.25:any",
                    "sources": [{"addresses": ["user.id.20"]}],
                    "destinations": [{"addresses": ["ip.id.22"]}],
                    "destination_ports": ["any"],
                    "action": "accept",
                },
                {
                    "id": "fwd.ngfw.21",
                    "comment": "[STUCK TEST] FW drop example.org",
                    "sources": [{"addresses": ["user.id.20"]}],
                    "destinations": [{"addresses": ["domain.id.20"]}],
                    "destination_ports": ["any"],
                    "action": "drop",
                },
                {
                    "id": "fwd.ngfw.20",
                    "comment": "[STUCK TEST] FW reject 203.0.113.10",
                    "sources": [{"addresses": ["user.id.20"]}],
                    "destinations": [{"addresses": ["ip.id.20"]}],
                    "destination_ports": ["any"],
                    "action": "reject",
                },
            ]
        if path == "/ips/bypass":
            return [
                {
                    "id": "bypass.id.20",
                    "aliases": ["ip.id.21"],
                    "comment": "[STUCK TEST] IPS bypass 192.0.2.30",
                }
            ]
        if path == "/firewall/hw_settings":
            return {"mode": "src-ip"}
        if path == "/firewall/hw_rules_src_ip":
            return [{"id": "hw.20", "source_ip": "192.0.2.77", "comment": "[STUCK TEST] HW src 192.0.2.77"}]
        if path == "/firewall/hw_rules_dst_ip":
            return [{"id": "hw.21", "destination_ip": "203.0.113.77", "comment": "[STUCK TEST] HW dst 203.0.113.77"}]
        if path == "/firewall/hw_rules_src_dst_ip":
            return [
                {
                    "id": "hw.22",
                    "source_ip": "192.0.2.78",
                    "destination_ip": "203.0.113.78",
                    "comment": "[STUCK TEST] HW pair 192.0.2.78>203.0.113.78",
                }
            ]
        if path in ("/firewall/state", "/content-filter/state", "/ips/state"):
            return {"enabled": True}
        return []


def test_second_apply_is_idempotent_and_performs_no_writes() -> None:
    client = _ExistingFakeClient()
    summary = NgfwTestDataSeeder(
        client,  # type: ignore[arg-type]
        SeedOptions(),
        emit=lambda _: None,
    ).seed(apply=True)

    assert len(summary.reused) == 19
    assert summary.created == []
    assert client.posts == []
    assert client.patches == []
    assert client.deletes == []


class _NoHwFakeClient(_FakeClient):
    """An older NGFW: the hardware-filtering endpoints do not exist (404)."""

    def get(self, path: str, *, params: dict[str, Any] | None = None) -> Any:
        if path == "/firewall/hw_settings" or path in self.hw_rules:
            raise ApiError(f"NGFW не поддерживает документированный endpoint GET {path}")
        return super().get(path, params=params)


def test_missing_hw_endpoints_are_skipped_with_a_warning() -> None:
    client = _NoHwFakeClient()
    summary = NgfwTestDataSeeder(
        client,  # type: ignore[arg-type]
        SeedOptions(test_user_password="St9!safe-test-password"),
        emit=lambda _line: None,
    ).seed(apply=True)

    # Everything except the three hardware rules is still created.
    assert len(summary.created) == 16
    assert not any("/firewall/hw_rules" in item[0] for item in client.posts)
    assert any("Аппаратная фильтрация не поддерживается" in warning for warning in summary.warnings)


class _HwConflictFakeClient(_FakeClient):
    """Our comment exists in the src-ip list but points at a DIFFERENT address."""

    def get(self, path: str, *, params: dict[str, Any] | None = None) -> Any:
        if path == "/firewall/hw_rules_src_ip":
            return [{"id": "hw.9", "source_ip": "192.0.2.99", "comment": "[STUCK TEST] HW src 192.0.2.77"}]
        return super().get(path, params=params)


def test_hw_rule_with_same_comment_but_other_address_is_a_conflict() -> None:
    client = _HwConflictFakeClient()
    with pytest.raises(ConflictError):
        NgfwTestDataSeeder(
            client,  # type: ignore[arg-type]
            SeedOptions(test_user_password="St9!safe-test-password"),
            emit=lambda _line: None,
        ).seed(apply=True)
    # The conflict triggers rollback of everything created before it.
    assert client.deletes != []


def test_hw_rules_are_prefix_owned_and_complete() -> None:
    client = _FakeClient()
    NgfwTestDataSeeder(
        client,  # type: ignore[arg-type]
        SeedOptions(test_user_password="St9!safe-test-password"),
        emit=lambda _line: None,
    ).seed(apply=True)

    hw_posts = {path: body for path, body, _params in client.posts if "/firewall/hw_rules" in path}
    assert set(hw_posts) == {
        "/firewall/hw_rules_src_ip",
        "/firewall/hw_rules_dst_ip",
        "/firewall/hw_rules_src_dst_ip",
    }
    assert hw_posts["/firewall/hw_rules_src_ip"]["source_ip"] == "192.0.2.77"
    assert hw_posts["/firewall/hw_rules_dst_ip"]["destination_ip"] == "203.0.113.77"
    assert hw_posts["/firewall/hw_rules_src_dst_ip"]["source_ip"] == "192.0.2.78"
    assert hw_posts["/firewall/hw_rules_src_dst_ip"]["destination_ip"] == "203.0.113.78"
    assert all(body["comment"].startswith("[STUCK TEST] HW ") for body in hw_posts.values())
    assert all(body["enabled"] is True for body in hw_posts.values())
