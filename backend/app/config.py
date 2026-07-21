"""Application configuration.

Values come from (highest priority first):
1. Process environment variables (``STUCK_*``).
2. The conf file (``STUCK_CONF_FILE`` env var, default ``conf/stuck.conf``).
3. Built-in defaults below.

Keys are inventoried in backend/conf/stuck.conf.
"""

from __future__ import annotations

import os
from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from .domain.ngfw_access import parse_allowed_hosts, parse_allowed_networks

# Resolve the default conf file relative to the backend package root so the app
# works regardless of the current working directory (local run or container).
_BACKEND_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DEFAULT_CONF = os.path.join(_BACKEND_ROOT, "conf", "stuck.conf")
_CONF_FILE = os.environ.get("STUCK_CONF_FILE", _DEFAULT_CONF)


class Settings(BaseSettings):
    """Typed application settings loaded from env + conf file."""

    model_config = SettingsConfigDict(
        env_file=_CONF_FILE if os.path.isfile(_CONF_FILE) else None,
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # Optional host lock for the login UI. A non-empty value is exposed to the
    # browser and prevents selecting another host. It is host-only: the NGFW
    # API port is appended from STUCK_NGFW_PORT.
    STUCK_DEFAULT_SERVER: str = ""
    STUCK_NGFW_PORT: int = Field(default=8443, ge=1, le=65535)
    STUCK_ALLOWED_NGFW_HOSTS: str = ""
    STUCK_ALLOWED_NGFW_CIDRS: str = ""
    STUCK_ALLOW_ANY_NGFW: bool = False
    # STUCK session TTL — 10 hours per the tech task / contract (Max-Age 36000).
    # The NGFW-side cookie may still expire earlier; that case is surfaced to
    # the UI as session_expired and does not evict the rules snapshot.
    STUCK_SESSION_TTL_HOURS: float = Field(default=10.0, gt=0)
    # Secure by default. The local HTTP development command overrides this
    # explicitly; Docker is served through the HTTPS reverse proxy.
    STUCK_COOKIE_SECURE: bool = True
    STUCK_COOKIE_SAMESITE: Literal["lax", "strict", "none"] = "lax"
    STUCK_NGFW_VERIFY_TLS: bool = False
    STUCK_NGFW_CA_BUNDLE: str = ""
    STUCK_ALLOWED_ORIGINS: str = "http://localhost:3000"
    STUCK_BACKEND_PORT: int = Field(default=8000, ge=1, le=65535)
    STUCK_TRACE_DEFAULT_PORT: int = Field(default=443, ge=1, le=65535)
    STUCK_NGFW_TIMEOUT_SECONDS: float = Field(default=15.0, gt=0)
    STUCK_LOG_LEVEL: str = "INFO"
    STUCK_LOG_FORMAT: Literal["text", "json"] = "text"
    STUCK_LOG_FILE: str = ""
    # (v2.3) Rules export is available by default. Operators can still disable
    # it explicitly; the endpoint then answers 404 and disappears from the UI.
    STUCK_ENABLE_RULES_EXPORT: bool = True
    # Animated trace-stage reveal is a presentation preference. Operators may
    # turn it off for an immediate, static result view.
    STUCK_ENABLE_TRACE_ANIMATION: bool = True

    @field_validator("STUCK_COOKIE_SAMESITE", "STUCK_LOG_FORMAT", mode="before")
    @classmethod
    def _lowercase(cls, v: object) -> object:
        return v.lower() if isinstance(v, str) else v

    @field_validator("STUCK_LOG_LEVEL", mode="before")
    @classmethod
    def _uppercase_level(cls, v: object) -> object:
        return v.upper() if isinstance(v, str) else v

    @model_validator(mode="after")
    def _validate_ngfw_access_policy(self) -> "Settings":
        hosts = parse_allowed_hosts(self.STUCK_ALLOWED_NGFW_HOSTS)
        networks = parse_allowed_networks(self.STUCK_ALLOWED_NGFW_CIDRS)
        if not self.STUCK_ALLOW_ANY_NGFW and not hosts and not networks:
            raise ValueError(
                "NGFW access is fail-closed: configure STUCK_ALLOWED_NGFW_HOSTS/"
                "STUCK_ALLOWED_NGFW_CIDRS or explicitly set STUCK_ALLOW_ANY_NGFW=true"
            )
        return self

    # --- Derived helpers -------------------------------------------------

    @property
    def session_ttl_seconds(self) -> int:
        return int(self.STUCK_SESSION_TTL_HOURS * 3600)

    @property
    def allowed_origins(self) -> list[str]:
        return [o.strip() for o in self.STUCK_ALLOWED_ORIGINS.split(",") if o.strip()]

    @property
    def allowed_ngfw_hosts(self) -> frozenset[str]:
        return parse_allowed_hosts(self.STUCK_ALLOWED_NGFW_HOSTS)

    @property
    def allowed_ngfw_networks(self):
        return parse_allowed_networks(self.STUCK_ALLOWED_NGFW_CIDRS)

    @property
    def ngfw_access_mode(self) -> str:
        return "unrestricted" if self.STUCK_ALLOW_ANY_NGFW else "allowlist"

    @property
    def ngfw_verify(self) -> bool | str:
        """Value passed to httpx ``verify``: a CA-bundle path, or a bool."""
        if self.STUCK_NGFW_VERIFY_TLS:
            return self.STUCK_NGFW_CA_BUNDLE or True
        return False


@lru_cache
def get_settings() -> Settings:
    return Settings()
