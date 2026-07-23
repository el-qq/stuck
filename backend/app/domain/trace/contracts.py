"""Construction of stable trace-stage contract objects."""

from __future__ import annotations

from typing import Any

STAGE_ORDER: tuple[str, ...] = (
    "hw_filter",
    "pre_filter",
    "rate_limit",
    "dns",
    "dnat",
    "content_filter",
    "antivirus",
    "firewall",
    "app_control",
    "ips",
    "snat",
    "destination",
)


def stage(key: str, status: str, detail: dict[str, Any] | None = None) -> dict[str, Any]:
    """Build one public trace stage while omitting unknown optional values."""
    result: dict[str, Any] = {
        "key": key,
        "order": STAGE_ORDER.index(key) + 1,
        "title_key": f"stage.{key}",
        "status": status,
    }
    if detail:
        result["detail"] = {name: value for name, value in detail.items() if value is not None}
    return result


def build_category_names(categories: Any) -> dict[str, str]:
    """Build a best-effort category-id to human-title mapping."""
    names: dict[str, str] = {}

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            category_id = node.get("id")
            title = node.get("title") or node.get("name")
            if isinstance(category_id, (str, int)) and isinstance(title, str):
                names[str(category_id)] = title
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(categories)
    return names
