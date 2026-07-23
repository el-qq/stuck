"use client";

import React, { useMemo } from "react";
import { useI18n } from "@/i18n";
import { NgfwUser, DomainType } from "@/lib/types";

const DOMAIN_TYPES: DomainType[] = ["local", "ad", "ald", "freeipa", "radius", "device"];

interface Props {
  users: NgfwUser[];
  loading: boolean;
  errorText: string | null;
  query: string;
  onQueryChange: (v: string) => void;
  domainFilter: "all" | DomainType;
  onDomainFilterChange: (v: "all" | DomainType) => void;
  selectedUserId: string | null;
  onSelect: (id: string) => void;
}

export function UserPicker({ users, loading, errorText, query, onQueryChange, domainFilter, onDomainFilterChange, selectedUserId, onSelect }: Props) {
  const { t } = useI18n();

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return users
      .filter((u) => domainFilter === "all" || u.domain_type === domainFilter)
      .filter((u) => !q || u.name.toLowerCase().includes(q) || u.login.toLowerCase().includes(q))
      .slice(0, 30);
  }, [users, query, domainFilter]);

  return (
    <div
      className="user-picker"
      style={{
        display: "flex",
        flexDirection: "column",
        gap: 10,
        marginBottom: 14,
        background: "var(--panel2)",
        border: "1px solid var(--line)",
        borderRadius: "var(--radius-md)",
        padding: 12,
      }}
    >
      <div className="user-picker__filters">
        <input
          className="form-control"
          value={query}
          onChange={(e) => onQueryChange(e.target.value)}
          placeholder={t("check.userSearchPlaceholder")}
          style={{
            border: "1px solid var(--line)",
            background: "var(--panel)",
            color: "var(--text)",
            borderRadius: "var(--radius-sm)",
            padding: "9px 10px",
            fontSize: 13,
          }}
        />
        <select
          className="form-control"
          value={domainFilter}
          onChange={(e) => onDomainFilterChange(e.target.value as "all" | DomainType)}
          style={{
            border: "1px solid var(--line)",
            background: "var(--panel)",
            color: "var(--text)",
            borderRadius: "var(--radius-sm)",
            padding: "9px 8px",
            fontSize: 13,
          }}
        >
          <option value="all">{t("check.groupAll")}</option>
          {DOMAIN_TYPES.map((d) => (
            <option key={d} value={d}>
              {d}
            </option>
          ))}
        </select>
      </div>

      {errorText && <div style={{ fontSize: 12, color: "var(--bad)", padding: "2px 2px" }}>{errorText}</div>}

      <div style={{ display: "flex", flexDirection: "column", gap: 4, maxHeight: 220, overflow: "auto" }}>
        {loading && <div style={{ fontSize: 12.5, color: "var(--muted)", padding: "8px 4px" }}>{t("common.loading")}</div>}
        {!loading &&
          filtered.map((u) => {
            const selected = selectedUserId === u.id;
            return (
              <button
                key={u.id}
                type="button"
                onClick={() => onSelect(u.id)}
                className="pick-row user-picker__row"
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  gap: 10,
                  padding: "8px 10px",
                  borderRadius: "var(--radius-sm)",
                  cursor: "pointer",
                  textAlign: "left",
                  border: `1px solid ${selected ? "var(--accent)" : "transparent"}`,
                  background: selected ? "var(--accent-soft)" : "var(--panel)",
                  color: "var(--text)",
                  width: "100%",
                  opacity: u.enabled ? 1 : 0.6,
                }}
              >
                <span className="user-picker__identity">
                  <span className="breakable" style={{ fontWeight: 600, fontSize: 13 }}>
                    {u.name}
                  </span>
                  <span className="mono breakable" style={{ fontSize: 11.5, color: "var(--muted)" }}>
                    {u.login}
                  </span>
                </span>
                <span
                  style={{
                    fontSize: 11,
                    color: "var(--muted)",
                    background: "var(--panel2)",
                    border: "1px solid var(--line)",
                    borderRadius: 999,
                    padding: "3px 9px",
                    whiteSpace: "nowrap",
                  }}
                >
                  {u.domain_type}
                </span>
              </button>
            );
          })}
        {!loading && filtered.length === 0 && !errorText && (
          <div style={{ fontSize: 12.5, color: "var(--muted)", padding: "8px 4px" }}>{t("check.noUsersFound")}</div>
        )}
      </div>
    </div>
  );
}
