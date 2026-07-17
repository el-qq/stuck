"use client";

import React, { useEffect, useState } from "react";
import { useI18n } from "@/i18n";
import { useSession } from "@/contexts/SessionContext";
import { useApiErrorMessage } from "@/hooks/useApiErrorMessage";
import * as api from "@/lib/api";
import { toApiError } from "@/lib/errors";
import { NgfwUser, DomainType, UserSourceAddress } from "@/lib/types";
import { getRecentUrls, pushRecentUrl } from "@/lib/storage";
import { UserPicker } from "./UserPicker";

export interface TraceSubmitPayload {
  url: string;
  userId?: string;
  sourceIp?: string;
}

interface Props {
  rulesLoaded: boolean;
  submitting: boolean;
  /** Iteration 3 (#9): bumped after a successful POST /api/rules/refresh —
   *  invalidates the local users cache so the picker re-fetches GET /api/users. */
  usersVersion: number;
  onSubmit: (payload: TraceSubmitPayload) => void;
}

export function TraceForm({ rulesLoaded, submitting, usersVersion, onSubmit }: Props) {
  const { t } = useI18n();
  const session = useSession();
  const errorMessage = useApiErrorMessage();

  const [address, setAddress] = useState("");
  const [mode, setMode] = useState<"all" | "user">("all");
  const [users, setUsers] = useState<NgfwUser[]>([]);
  const [usersLoading, setUsersLoading] = useState(false);
  const [usersError, setUsersError] = useState<string | null>(null);
  const [usersFetched, setUsersFetched] = useState(false);
  const [userQuery, setUserQuery] = useState("");
  const [domainFilter, setDomainFilter] = useState<"all" | DomainType>("all");
  const [selectedUserId, setSelectedUserId] = useState<string | null>(null);
  const [sourceAddresses, setSourceAddresses] = useState<UserSourceAddress[]>([]);
  const [sourceAddressesLoading, setSourceAddressesLoading] = useState(false);
  const [sourceAddressesError, setSourceAddressesError] = useState<string | null>(null);
  const [selectedSourceIp, setSelectedSourceIp] = useState<string | null>(null);
  // Recent entered addresses are persisted by the bounded storage helper.
  const [recentUrls, setRecentUrls] = useState<string[]>([]);

  useEffect(() => {
    setRecentUrls(getRecentUrls());
  }, []);

  // Iteration 3 (#9): rules refresh invalidates the cached users list.
  useEffect(() => {
    if (usersVersion > 0) setUsersFetched(false);
  }, [usersVersion]);

  useEffect(() => {
    if (mode !== "user" || usersFetched || !rulesLoaded) return;
    let cancelled = false;
    setUsersLoading(true);
    setUsersError(null);
    api
      .getUsers()
      .then((res) => {
        if (cancelled) return;
        setUsers(res.users);
        setUsersFetched(true);
      })
      .catch((e: unknown) => {
        if (cancelled) return;
        const apiErr = toApiError(e);
        if (!session.handleAuthError(apiErr)) {
          setUsersError(errorMessage(apiErr));
        }
      })
      .finally(() => {
        if (!cancelled) setUsersLoading(false);
      });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mode, usersFetched, rulesLoaded]);

  useEffect(() => {
    if (mode !== "user" || !selectedUserId) {
      setSourceAddresses([]);
      setSelectedSourceIp(null);
      setSourceAddressesError(null);
      return;
    }
    let cancelled = false;
    setSourceAddresses([]);
    setSelectedSourceIp(null);
    setSourceAddressesLoading(true);
    setSourceAddressesError(null);
    api
      .getUserSourceAddresses(selectedUserId)
      .then((res) => {
        if (cancelled) return;
        setSourceAddresses(res.addresses);
        setSelectedSourceIp(res.addresses.length === 1 ? res.addresses[0]!.ip : null);
      })
      .catch((e: unknown) => {
        if (cancelled) return;
        const apiErr = toApiError(e);
        if (!session.handleAuthError(apiErr)) {
          setSourceAddressesError(errorMessage(apiErr));
        }
      })
      .finally(() => {
        if (!cancelled) setSourceAddressesLoading(false);
      });
    return () => {
      cancelled = true;
    };
    // The callbacks come from stable providers; the selected user is the fetch key.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mode, selectedUserId, usersVersion]);

  const selectedUser = users.find((u) => u.id === selectedUserId) ?? null;
  const sourceAddressReady = !sourceAddressesError && (sourceAddresses.length === 0 || !!selectedSourceIp);
  const canCheck =
    rulesLoaded && address.trim().length > 0 && (mode === "all" || (!!selectedUser && sourceAddressReady)) && !sourceAddressesLoading && !submitting;

  function handleSubmit() {
    if (!canCheck) return;
    // Remember entered addresses (deduplicated, newest first, bounded in storage.ts).
    setRecentUrls(pushRecentUrl(address));
    onSubmit({
      url: address.trim(),
      userId: mode === "user" ? (selectedUser?.id ?? undefined) : undefined,
      sourceIp: mode === "user" ? (selectedSourceIp ?? undefined) : undefined,
    });
  }

  return (
    <div
      className="check-panel"
      style={{
        background: "var(--panel)",
        border: "1px solid var(--line)",
        borderRadius: "var(--radius-lg)",
        boxShadow: "var(--shadow)",
        padding: 22,
      }}
    >
      <div style={{ fontSize: 15, fontWeight: 700, marginBottom: 16 }}>{t("check.panelTitle")}</div>

      <div style={{ display: "flex", flexDirection: "column", gap: 6, marginBottom: 10 }}>
        <div style={{ fontSize: 12.5, fontWeight: 600, color: "var(--muted)" }}>{t("check.addressLabel")}</div>
        <input
          value={address}
          onChange={(e) => setAddress(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") handleSubmit();
          }}
          placeholder={t("check.addressPlaceholder")}
          className="form-control mono"
          style={{
            border: "1px solid var(--line)",
            background: "var(--panel2)",
            color: "var(--text)",
            borderRadius: "var(--radius-sm)",
            padding: "11px 12px",
            fontSize: 14.5,
          }}
        />
      </div>

      {recentUrls.length > 0 && (
        <div className="example-chip-list">
          {recentUrls.map((url) => (
            <button
              key={url}
              type="button"
              className="example-chip mono"
              onClick={() => setAddress(url)}
              style={{ borderRadius: 999, padding: "4px 10px", fontSize: 12 }}
            >
              {url}
            </button>
          ))}
        </div>
      )}

      <div style={{ fontSize: 12.5, fontWeight: 600, color: "var(--muted)", marginBottom: 6 }}>{t("check.scenarioLabel")}</div>
      <div
        className="segmented-control"
        style={{
          display: "grid",
          gridTemplateColumns: "1fr 1fr",
          border: "1px solid var(--line)",
          borderRadius: "var(--radius-sm)",
          overflow: "hidden",
          marginBottom: 14,
        }}
      >
        <button type="button" className="seg-btn" onClick={() => setMode("all")} style={segStyle(mode === "all")}>
          {t("check.modeAll")}
        </button>
        <button type="button" className="seg-btn" onClick={() => setMode("user")} style={segStyle(mode === "user")}>
          {t("check.modeUser")}
        </button>
      </div>

      {mode === "user" && (
        <>
          <UserPicker
            users={users}
            loading={usersLoading}
            errorText={usersError}
            query={userQuery}
            onQueryChange={setUserQuery}
            domainFilter={domainFilter}
            onDomainFilterChange={setDomainFilter}
            selectedUserId={selectedUserId}
            onSelect={setSelectedUserId}
          />
          {selectedUser && (
            <div className="source-address-picker">
              <div className="source-address-picker__label">{t("check.sourceIpLabel")}</div>
              {sourceAddressesLoading && <div className="source-address-picker__message">{t("check.sourceIpLoading")}</div>}
              {!sourceAddressesLoading && sourceAddressesError && (
                <div className="source-address-picker__message source-address-picker__message--error">{sourceAddressesError}</div>
              )}
              {!sourceAddressesLoading && !sourceAddressesError && sourceAddresses.length === 0 && (
                <div className="source-address-picker__message source-address-picker__message--warning">{t("check.sourceIpEmpty")}</div>
              )}
              {!sourceAddressesLoading && sourceAddresses.length > 0 && (
                <div className="source-address-picker__options" role="radiogroup" aria-label={t("check.sourceIpLabel")}>
                  {sourceAddresses.map((source) => {
                    const selected = selectedSourceIp === source.ip;
                    return (
                      <button
                        key={source.ip}
                        type="button"
                        role="radio"
                        aria-checked={selected}
                        className="source-address-picker__option mono"
                        onClick={() => setSelectedSourceIp(source.ip)}
                        data-selected={selected ? "true" : "false"}
                        title={source.node_name ?? source.subnet}
                      >
                        <span>{source.ip}</span>
                        <span className="source-address-picker__origin">
                          {source.active && source.assigned
                            ? t("check.sourceIpActiveAssigned")
                            : source.assigned
                              ? t("check.sourceIpAssigned")
                              : t("check.sourceIpActive")}
                        </span>
                      </button>
                    );
                  })}
                </div>
              )}
              {sourceAddresses.length > 1 && !selectedSourceIp && <div className="source-address-picker__hint">{t("check.sourceIpChoose")}</div>}
            </div>
          )}
        </>
      )}

      <button
        type="button"
        onClick={handleSubmit}
        disabled={!canCheck}
        className={`check-submit${canCheck ? " btn-primary" : ""}`}
        style={{
          width: "100%",
          border: "none",
          borderRadius: "var(--radius-sm)",
          padding: 13,
          fontSize: 14.5,
          fontWeight: 700,
          background: canCheck ? undefined : "var(--skip-soft)",
          color: canCheck ? undefined : "var(--skip)",
          cursor: canCheck ? "pointer" : "not-allowed",
        }}
      >
        {submitting ? t("check.submitting") : mode === "user" && selectedUser ? t("check.submitAs", { name: selectedUser.name }) : t("check.submit")}
      </button>

      {!rulesLoaded && (
        <div
          style={{
            marginTop: 10,
            fontSize: 12.5,
            color: "var(--warn)",
            background: "var(--warn-soft)",
            borderRadius: "var(--radius-sm)",
            padding: "10px 12px",
            lineHeight: 1.45,
          }}
        >
          {t("check.noRulesWarning")}
        </div>
      )}

      <div
        style={{
          marginTop: 16,
          background: "var(--panel2)",
          border: "1px solid var(--line)",
          borderRadius: "var(--radius-md)",
          padding: "16px 18px",
          fontSize: 12.5,
          color: "var(--muted)",
          lineHeight: 1.55,
        }}
      >
        <div style={{ fontWeight: 700, color: "var(--text)", marginBottom: 6, fontSize: 13 }}>{t("check.orderTitle")}</div>
        {t("check.orderText")}
      </div>
    </div>
  );
}

function segStyle(active: boolean): React.CSSProperties {
  return {
    padding: "9px 6px",
    fontSize: 12.5,
    fontWeight: 600,
    background: active ? "var(--accent)" : "var(--panel)",
    color: active ? "var(--accent-contrast)" : "var(--muted)",
  };
}
