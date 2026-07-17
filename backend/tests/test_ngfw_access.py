"""NGFW destination policy tests: fail-closed allowlists and lab escape hatch."""

import socket

import pytest
from pydantic import ValidationError

from app.config import Settings
from app.domain.ngfw_access import (
    enforce_ngfw_access,
    parse_allowed_hosts,
    parse_allowed_networks,
)
from app.errors import StuckError


def test_settings_fail_closed_without_allowlist(monkeypatch):
    monkeypatch.delenv("STUCK_ALLOW_ANY_NGFW", raising=False)
    monkeypatch.delenv("STUCK_ALLOWED_NGFW_HOSTS", raising=False)
    monkeypatch.delenv("STUCK_ALLOWED_NGFW_CIDRS", raising=False)

    with pytest.raises(ValidationError, match="NGFW access is fail-closed"):
        Settings(_env_file=None)


def test_settings_accept_explicit_lab_mode(monkeypatch):
    monkeypatch.setenv("STUCK_ALLOW_ANY_NGFW", "true")

    settings = Settings(_env_file=None)

    assert settings.ngfw_access_mode == "unrestricted"


@pytest.mark.asyncio
async def test_exact_host_and_cidr_are_allowed():
    await enforce_ngfw_access(
        "192.168.100.11",
        port=8443,
        allow_any=False,
        allowed_hosts=parse_allowed_hosts("192.168.100.11"),
        allowed_networks=(),
    )
    await enforce_ngfw_access(
        "192.168.100.11",
        port=8443,
        allow_any=False,
        allowed_hosts=frozenset(),
        allowed_networks=parse_allowed_networks("192.168.100.0/24"),
    )


@pytest.mark.asyncio
async def test_address_outside_allowlist_is_rejected():
    with pytest.raises(StuckError) as caught:
        await enforce_ngfw_access(
            "192.168.100.11",
            port=8443,
            allow_any=False,
            allowed_hosts=parse_allowed_hosts("192.168.200.1"),
            allowed_networks=(),
        )

    assert caught.value.code == "ngfw_host_not_allowed"
    assert caught.value.http_status == 403


@pytest.mark.asyncio
@pytest.mark.parametrize("server", ["127.0.0.1", "169.254.169.254", "224.0.0.1", "0.0.0.0"])
async def test_unsafe_literal_is_rejected_even_in_lab_mode(server):
    with pytest.raises(StuckError) as caught:
        await enforce_ngfw_access(
            server,
            port=8443,
            allow_any=True,
            allowed_hosts=frozenset(),
            allowed_networks=(),
        )

    assert caught.value.code == "ngfw_host_not_allowed"


@pytest.mark.asyncio
async def test_hostname_must_resolve_entirely_inside_allowed_cidrs(monkeypatch):
    def fake_getaddrinfo(host, port, *args, **kwargs):
        assert host == "ngfw.corp.local"
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.20.1.5", port)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.20.1.6", port)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    await enforce_ngfw_access(
        "ngfw.corp.local",
        port=8443,
        allow_any=False,
        allowed_hosts=frozenset(),
        allowed_networks=parse_allowed_networks("10.20.0.0/16"),
    )


@pytest.mark.asyncio
async def test_one_dns_address_outside_cidr_rejects_hostname(monkeypatch):
    def fake_getaddrinfo(host, port, *args, **kwargs):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.20.1.5", port)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.30.1.5", port)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    with pytest.raises(StuckError) as caught:
        await enforce_ngfw_access(
            "ngfw.corp.local",
            port=8443,
            allow_any=False,
            allowed_hosts=frozenset(),
            allowed_networks=parse_allowed_networks("10.20.0.0/16"),
        )

    assert caught.value.code == "ngfw_host_not_allowed"
