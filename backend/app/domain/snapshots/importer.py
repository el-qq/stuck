"""Import of a rules-export document (``stuck.rules/v2``) as a snapshot.

docs/source/snapshots.md, развилка h: the administrator uploads the JSON that
``GET /api/rules/export`` produced and STUCK turns it back into a
``RulesSnapshot``-shaped object usable as one side of a diff. Principles:

- strict envelope, tolerant elements (h.3): the outer document must carry
  ``format`` (exactly ``stuck.rules/v2``), a ``snapshot`` object, ISO
  ``exported_at``/``rules_updated_at`` and ``binding.server``; inside the
  collections the same lenient pydantic schemas as for live NGFW responses
  apply — unknown element fields are ignored, wrong types of required fields
  are rejected;
- the size limit is checked BEFORE parsing (h.4 case 3);
- a per-user slice (``filtered_by_user_id != null``) is not comparable with a
  full snapshot and is rejected (h.4 case 6);
- string values are length-capped so hostile documents cannot smuggle huge
  blobs into UI-rendered fields (h.4 case 10);
- NGFW is never called; the resulting snapshot is marked as coming from the
  anonymized export by the caller (``rule_snapshots.create_imported``).

Error mapping (contract, развилка f): ``snapshot_import_too_large`` (413),
``snapshot_import_unsupported_format`` (400, format present but not ours),
``snapshot_import_invalid`` (400, ``details.reason`` in
``json | structure | filtered_export | field_too_long``).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ValidationError

from ...errors import StuckError
from ...ngfw import schemas as S
from ..binding_pool import RulesSnapshot

SUPPORTED_FORMAT = "stuck.rules/v2"

# Body limit for the import request: a real installation's export is a few MB
# with indent=2; 20 MiB gives a 2-4x margin without risking process memory.
IMPORT_MAX_BYTES = 20 * 1024 * 1024

# Longest tolerated string anywhere inside the imported snapshot section
# (ids, alias values, URLs...). UI renders these as text nodes; the cap only
# guards against absurd payloads, not legitimate exports.
MAX_STRING_LENGTH = 512


@dataclass
class ImportedDocument:
    """Parsed, validated import: the snapshot plus non-secret file metadata."""

    snapshot: RulesSnapshot
    exported_at: str
    server: str
    foreign_server: bool


def _invalid(reason: str) -> StuckError:
    return StuckError(
        "snapshot_import_invalid",
        f"The pasted document is not a valid {SUPPORTED_FORMAT} export ({reason})",
        details={"reason": reason},
    )


def _unsupported(fmt: Any) -> StuckError:
    return StuckError(
        "snapshot_import_unsupported_format",
        "Only rules exports in the stuck.rules/v2 format can be imported",
        details={"format": fmt if isinstance(fmt, str) else None},
    )


def check_size(num_bytes: int) -> None:
    """Reject oversized bodies BEFORE any JSON parsing (h.4 case 3)."""
    if num_bytes > IMPORT_MAX_BYTES:
        raise StuckError(
            "snapshot_import_too_large",
            "The import body exceeds the size limit",
            details={"limit_bytes": IMPORT_MAX_BYTES},
        )


def parse_json_document(raw: str) -> Any:
    """Parse a pasted/uploaded file body; truncated copy-paste → reason 'json'."""
    try:
        return json.loads(raw)
    except ValueError as exc:
        raise _invalid("json") from exc


def _parse_iso(value: Any) -> float:
    """Strict envelope timestamps: an ISO-8601 UTC string → unix seconds."""
    if not isinstance(value, str) or not value or len(value) > 64:
        raise _invalid("structure")
    try:
        return datetime.fromisoformat(value).astimezone(UTC).timestamp()
    except ValueError as exc:
        raise _invalid("structure") from exc


def _check_string_lengths(node: Any) -> None:
    """Cap every string (keys and values) inside the snapshot section."""
    if isinstance(node, str):
        if len(node) > MAX_STRING_LENGTH:
            raise _invalid("field_too_long")
    elif isinstance(node, dict):
        for key, value in node.items():
            _check_string_lengths(key)
            _check_string_lengths(value)
    elif isinstance(node, list):
        for item in node:
            _check_string_lengths(item)


def _section(container: dict[str, Any], key: str, default: Any) -> Any:
    """Missing optional sections of an older v2 export fall back to defaults."""
    value = container.get(key)
    return default if value is None else value


def _parse_list[T: BaseModel](model: type[T], data: Any) -> list[T]:
    """Tolerant element parsing: unknown fields pass, wrong types reject."""
    try:
        return S.parse_list(model, data, what="import")
    except StuckError as exc:  # api_changed from the shared parser
        raise _invalid("structure") from exc


def _parse_one[T: BaseModel](model: type[T], data: Any) -> T:
    try:
        return model.model_validate(data)
    except ValidationError as exc:
        raise _invalid("structure") from exc


def _string_list(data: Any) -> list[str]:
    if not isinstance(data, list) or not all(isinstance(item, str) for item in data):
        raise _invalid("structure")
    return list(data)


def parse_export_document(doc: Any, *, current_server: str) -> ImportedDocument:
    """Validate the pasted export and rebuild a RulesSnapshot from it.

    ``current_server`` is the CURRENT session's server: the file can never
    select another binding — it only informs the ``foreign_server`` flag
    (h.4 case 4; сравнение «прод vs стенд» легально и явно помечается).
    """
    if not isinstance(doc, dict):
        raise _invalid("structure")

    if "format" not in doc:
        raise _invalid("structure")
    if doc["format"] != SUPPORTED_FORMAT:
        raise _unsupported(doc["format"])

    if doc.get("filtered_by_user_id") is not None:
        # A one-user slice would make the whole remaining config a false
        # "removed" — not comparable with a full snapshot (h.4 case 6).
        raise _invalid("filtered_export")

    binding = doc.get("binding")
    if not isinstance(binding, dict) or not isinstance(binding.get("server"), str) or not binding["server"]:
        raise _invalid("structure")
    if len(binding["server"]) > MAX_STRING_LENGTH:
        raise _invalid("field_too_long")

    rules_updated_at = _parse_iso(doc.get("rules_updated_at"))
    exported_at_raw = doc.get("exported_at")
    _parse_iso(exported_at_raw)  # validate; keep the original string as metadata

    exp = doc.get("snapshot")
    if not isinstance(exp, dict):
        raise _invalid("structure")
    _check_string_lengths(exp)

    hardware = _section(exp, "hardware", {})
    if not isinstance(hardware, dict):
        raise _invalid("structure")
    hw_settings_raw = hardware.get("settings")
    content_filter = _section(exp, "content_filter", {})
    speed_limit = _section(exp, "speed_limit", {})
    av_profile = _section(exp, "av_profile", {})
    if not isinstance(content_filter, dict) or not isinstance(speed_limit, dict) or not isinstance(av_profile, dict):
        raise _invalid("structure")
    av_enabled = _section(av_profile, "enabled", False)
    if not isinstance(av_enabled, bool):
        raise _invalid("structure")

    aliases_list = _parse_list(S.Alias, _section(exp, "aliases", []))

    snapshot = RulesSnapshot(
        users=_parse_list(S.NgfwUser, _section(exp, "users", [])),
        aliases={alias.id: alias for alias in aliases_list},
        fw_forward=_parse_list(S.FirewallRule, _section(exp, "firewall_forward", [])),
        fw_input=_parse_list(S.FirewallRule, _section(exp, "firewall_input", [])),
        fw_pre_filter=_parse_list(S.PreliminaryRule, _section(exp, "firewall_pre_filter", [])),
        fw_dnat=_parse_list(S.FirewallRule, _section(exp, "firewall_dnat", [])),
        fw_snat=_parse_list(S.FirewallRule, _section(exp, "firewall_snat", [])),
        fw_settings=_parse_one(S.FirewallSettings, _section(exp, "firewall_settings", {})),
        # hardware.settings: null is VALID and means "feature absent on that
        # NGFW" — the diff must treat the section as incomparable (h.3).
        hw_settings=(_parse_one(S.HwFilterSettings, hw_settings_raw) if hw_settings_raw is not None else None),
        hw_rules_mac=_parse_list(S.HwRuleMac, _section(hardware, "rules_mac", [])),
        hw_rules_src_ip=_parse_list(S.HwRuleSrcIp, _section(hardware, "rules_src_ip", [])),
        hw_rules_dst_ip=_parse_list(S.HwRuleDstIp, _section(hardware, "rules_dst_ip", [])),
        hw_rules_src_dst_ip=_parse_list(S.HwRuleSrcDstIp, _section(hardware, "rules_src_dst_ip", [])),
        lan_networks=_string_list(_section(exp, "lan_networks", [])),
        dns_zones=_parse_list(S.DnsZone, _section(exp, "dns_zones", [])),
        ngfw_addresses=_string_list(_section(exp, "ngfw_addresses", [])),
        fw_state=_parse_one(S.StateFlag, _section(exp, "firewall_state", {})),
        cf_state=_parse_one(S.StateFlag, _section(content_filter, "state", {})),
        cf_rules=_parse_list(S.ContentFilterRule, _section(content_filter, "rules", [])),
        cf_categories=content_filter.get("categories"),
        shaper_state=_parse_one(S.StateFlag, _section(speed_limit, "state", {})),
        shaper_rules=_parse_list(S.ShaperRule, _section(speed_limit, "rules", [])),
        ips_state=_parse_one(S.StateFlag, _section(exp, "ips_state", {})),
        ips_bypass=_parse_list(S.IpsBypass, _section(exp, "ips_bypass", [])),
        av_enabled=av_enabled,
        # loaded_at mirrors when the DATA was read from NGFW, not the import
        # moment — descriptor's rules_updated_at then stays truthful.
        loaded_at=rules_updated_at,
    )

    return ImportedDocument(
        snapshot=snapshot,
        exported_at=exported_at_raw,
        server=binding["server"],
        foreign_server=binding["server"] != current_server,
    )
