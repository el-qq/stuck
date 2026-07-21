"""Binding pool (v2.1) — per-(admin_login, server) rules state for the process life.

Current invariants (docs/ARCHITECTURE.md and docs/API_CONTRACT.md):
- Key: (admin_login, server-host). Different admins and/or servers are strictly
  isolated — they only ever see their own binding.
- Value: ONLY the rules snapshot and its load timestamp (``rules_updated_at``).
  NGFW cookies are NOT kept here — they live exclusively in the active STUCK
  session (``session_store.Session``) and die with it.
- Lifetime: the pool SURVIVES logout; it is reset only by a backend restart or
  (per-binding, snapshot reload) by ``POST /api/rules/refresh``. There is no TTL.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any

from ..ngfw import schemas as S


@dataclass
class RulesSnapshot:
    users: list[S.NgfwUser]
    aliases: dict[str, S.Alias]
    fw_forward: list[S.FirewallRule]
    fw_input: list[S.FirewallRule]
    fw_state: S.StateFlag
    cf_state: S.StateFlag
    cf_rules: list[S.ContentFilterRule]
    cf_categories: Any
    ips_state: S.StateFlag
    ips_bypass: list[S.IpsBypass]
    av_enabled: bool
    fw_pre_filter: list[S.PreliminaryRule] = field(default_factory=list)
    fw_dnat: list[S.FirewallRule] = field(default_factory=list)
    fw_snat: list[S.FirewallRule] = field(default_factory=list)
    fw_settings: S.FirewallSettings = field(default_factory=S.FirewallSettings)
    ngfw_addresses: list[str] = field(default_factory=list)
    shaper_state: S.StateFlag = field(default_factory=S.StateFlag)
    shaper_rules: list[S.ShaperRule] = field(default_factory=list)
    loaded_at: float = field(default_factory=time.time)

    @classmethod
    def from_raw(cls, raw: dict[str, Any]) -> "RulesSnapshot":
        return cls(**raw)

    def counts(self) -> dict[str, int]:
        return {
            "users": len(self.users),
            "firewall_forward": len(self.fw_forward),
            "firewall_input": len(self.fw_input),
            "firewall_pre_filter": len(self.fw_pre_filter),
            "firewall_dnat": len(self.fw_dnat),
            "firewall_snat": len(self.fw_snat),
            "content_filter_rules": len(self.cf_rules),
            "speed_limit_rules": len(self.shaper_rules),
            "ips_bypass": len(self.ips_bypass),
            "aliases": len(self.aliases),
        }


@dataclass
class Binding:
    """One (admin_login, server) entry: snapshot + timestamp. No secrets."""

    admin_login: str
    server: str
    snapshot: RulesSnapshot | None = None

    @property
    def rules_updated_at(self) -> float | None:
        """Unix timestamp of the last snapshot load, or None if never loaded."""
        return self.snapshot.loaded_at if self.snapshot is not None else None


class BindingPool:
    """In-memory pool of bindings; lives until process restart."""

    def __init__(self) -> None:
        self._by_key: dict[tuple[str, str], Binding] = {}
        # Synchronization metadata, not part of a binding's cached data. Each
        # lock is scoped to one admin+server pair so unrelated pairs proceed
        # independently.
        self._load_locks: dict[tuple[str, str], asyncio.Lock] = {}

    @staticmethod
    def _key(admin_login: str, server: str) -> tuple[str, str]:
        return (admin_login, server)

    def get(self, admin_login: str, server: str) -> Binding | None:
        return self._by_key.get(self._key(admin_login, server))

    def ensure(self, admin_login: str, server: str) -> tuple[Binding, bool]:
        """Return the binding, creating an empty one if absent.

        Returns (binding, created) where created=True for a brand-new binding.
        """
        key = self._key(admin_login, server)
        binding = self._by_key.get(key)
        if binding is None:
            binding = Binding(admin_login=admin_login, server=server)
            self._by_key[key] = binding
            self._load_locks[key] = asyncio.Lock()
            return binding, True
        return binding, False

    def discard(self, admin_login: str, server: str) -> None:
        """Remove a cached pair when its current role cannot use STUCK.

        A former administrator must not retain a process-local rules snapshot
        after signing in with a known insufficient role.  Locks are only
        synchronization metadata and can be discarded with the binding.
        """

        key = self._key(admin_login, server)
        self._by_key.pop(key, None)
        self._load_locks.pop(key, None)

    def set_snapshot(self, binding: Binding, snapshot: RulesSnapshot) -> None:
        binding.snapshot = snapshot

    def has_snapshot(self, admin_login: str, server: str) -> bool:
        binding = self.get(admin_login, server)
        return binding is not None and binding.snapshot is not None

    def load_lock(self, binding: Binding) -> asyncio.Lock:
        """Return the lock guarding snapshot loads for this exact binding."""
        key = self._key(binding.admin_login, binding.server)
        return self._load_locks.setdefault(key, asyncio.Lock())
