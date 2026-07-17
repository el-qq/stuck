"""Lenient pydantic models for NGFW responses.

Goal: detect ``api_changed`` (the outer shape / key fields the trace engine
relies on are missing or of the wrong type) WITHOUT being so strict that a new
harmless field on the NGFW side breaks STUCK. Hence ``extra="allow"`` and mostly
optional fields — we only assert what the engine actually reads.

Parsing is centralized in ``parse`` / ``parse_list`` which convert pydantic
ValidationError into a StuckError(api_changed).
"""

from __future__ import annotations

from typing import Any, TypeVar

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from ..errors import StuckError

T = TypeVar("T", bound=BaseModel)


class _Base(BaseModel):
    model_config = ConfigDict(extra="allow")


class NgfwUser(_Base):
    id: str
    name: str = ""
    login: str = ""
    parent_id: str | None = None
    enabled: bool = True
    domain_type: str = "local"
    domain_name: str = ""
    comment: str = ""


class Alias(_Base):
    id: str
    type: str = ""
    title: str = ""
    value: Any = None
    values: list[Any] | None = None
    start: Any = None
    end: Any = None


class SourceDest(_Base):
    addresses: list[str] = Field(default_factory=list)
    addresses_negate: bool = False


class FirewallRule(_Base):
    id: str
    enabled: bool = True
    protocol: str = "any"
    sources: list[SourceDest] = Field(default_factory=list)
    source_ports: list[str] = Field(default_factory=list)
    incoming_interface: str = ""
    destinations: list[SourceDest] = Field(default_factory=list)
    destination_ports: list[str] = Field(default_factory=list)
    outgoing_interface: str = ""
    hip_profiles: list[str] = Field(default_factory=list)
    dpi_enabled: bool = False
    dpi_profile: str | None = None
    ips_enabled: bool = False
    ips_profile: str | None = None
    timetable: list[str] = Field(default_factory=list)
    comment: str = ""
    action: str = "accept"
    change_destination_address: str | None = None
    change_destination_port: str | None = None
    change_source_address: str | None = None


class PreliminaryRule(_Base):
    """One row from the read-only preliminary-filter CSV export."""

    id: str
    enabled: bool = True
    protocol: str = "any"
    source_address: str | None = None
    source_port: str | None = None
    destination_address: str | None = None
    destination_port: str | None = None
    tcp_flags: str = ""
    blocked_tcp_flags: str = ""
    packet_length: str | None = None
    comment: str = ""


class FirewallSettings(_Base):
    automatic_snat_enabled: bool = False


class InterfaceState(_Base):
    id: str
    l3: list[str] = Field(default_factory=list)
    status: str = "unknown"


class AuthSession(_Base):
    id: str
    user_object_id: str
    subnet: str = ""
    external_ip: str | None = None
    auth_module: str = ""
    blocked_flags: int = 0
    state_flags: int = 0
    node_name: str | None = None


class AuthRule(_Base):
    """Configured IP/MAC authorization rule from ``GET /auth/rules``."""

    id: str
    enabled: bool = True
    ip: str | None = None
    mac: str | None = None
    user_object_id: str
    always_logged: bool = False
    comment: str = ""


class ContentFilterRule(_Base):
    # NGFW returns numeric id here; normalize to str for the contract.
    id: str
    name: str = ""
    comment: str = ""
    aliases: list[str] = Field(default_factory=list)
    categories: list[str] = Field(default_factory=list)
    http_methods: list[str] = Field(default_factory=list)
    content_types: list[str] = Field(default_factory=list)
    access: str = "allow"
    redirect_url: str | None = None
    enabled: bool = True
    timetable: list[str] = Field(default_factory=list)

    @classmethod
    def coerce_id(cls, raw: dict[str, Any]) -> dict[str, Any]:
        raw = dict(raw)
        if isinstance(raw, dict) and "id" in raw and not isinstance(raw["id"], str):
            raw["id"] = str(raw["id"])
        if "aliases" not in raw and isinstance(raw.get("src_aliases"), list):
            raw["aliases"] = [
                str(alias)
                for block in raw["src_aliases"]
                if isinstance(block, dict) and not block.get("negate", False) and isinstance(block.get("aliases"), list)
                for alias in block["aliases"]
            ]
        return raw


class ShaperRule(_Base):
    """One speed-limit rule from the NGFW shaper UI API."""

    id: str
    name: str = ""
    comment: str = ""
    aliases: list[str] = Field(default_factory=list)
    apply_to: str = "group"
    speed_value: float = 0
    enabled: bool = True
    parent_id: str = ""

    @classmethod
    def coerce_id(cls, raw: dict[str, Any]) -> dict[str, Any]:
        raw = dict(raw)
        if "id" in raw and not isinstance(raw["id"], str):
            raw["id"] = str(raw["id"])
        return raw


class IpsBypass(_Base):
    id: str
    aliases: list[str] = Field(default_factory=list)
    comment: str = ""
    enabled: bool = True


class StateFlag(_Base):
    enabled: bool = False


class Categorize(_Base):
    all: list[str] = Field(default_factory=list)
    sky: list[str] = Field(default_factory=list)
    normalizedUrl: str = ""


# --- Parsing helpers ---------------------------------------------------------


def _api_changed(what: str, exc: Exception) -> StuckError:
    return StuckError(
        "api_changed",
        f"NGFW response for '{what}' does not match expected schema",
        details={"where": what, "reason": str(exc)[:400]},
    )


def parse(model: type[T], data: Any, *, what: str) -> T:
    try:
        return model.model_validate(data)
    except ValidationError as exc:
        raise _api_changed(what, exc) from exc


def parse_list(model: type[T], data: Any, *, what: str) -> list[T]:
    if not isinstance(data, list):
        raise _api_changed(what, TypeError(f"expected list, got {type(data).__name__}"))
    out: list[T] = []
    for item in data:
        try:
            if model is ContentFilterRule and isinstance(item, dict):
                item = ContentFilterRule.coerce_id(item)
            elif model is ShaperRule and isinstance(item, dict):
                item = ShaperRule.coerce_id(item)
            out.append(model.model_validate(item))
        except ValidationError as exc:
            raise _api_changed(what, exc) from exc
    return out
