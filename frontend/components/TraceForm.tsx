"use client";

import React, { useEffect, useState } from "react";
import { useI18n } from "@/i18n";
import { PipelineOrder } from "./PipelineOrder";
import { useSession } from "@/contexts/SessionContext";
import { useApiErrorMessage } from "@/hooks/useApiErrorMessage";
import * as api from "@/lib/api";
import { toApiError } from "@/lib/errors";
import { NgfwUser, DomainType, UserSourceAddress } from "@/lib/types";
import { getRecentUrls, pushRecentUrl } from "@/lib/storage";
import { SERVICE_PRESETS, parseTarget, clampPort } from "@/lib/servicePresets";
import { UserPicker } from "./UserPicker";

export interface TraceSubmitPayload {
  url: string;
  userId?: string;
  sourceIp?: string;
}

interface Props {
  rulesLoaded: boolean;
  /** False when the backend has identified a known insufficient NGFW role. */
  traceAllowed: boolean;
  submitting: boolean;
  /** Iteration 3 (#9): bumped after a successful POST /api/rules/refresh —
   *  invalidates the local users cache so the picker re-fetches GET /api/users. */
  usersVersion: number;
  onSubmit: (payload: TraceSubmitPayload) => void;
}

export function TraceForm({ rulesLoaded, traceAllowed, submitting, usersVersion, onSubmit }: Props) {
  const { t } = useI18n();
  const session = useSession();
  const errorMessage = useApiErrorMessage();

  const [address, setAddress] = useState("");
  // Destination port lives apart from the address: null means "backend default".
  const [port, setPort] = useState<number | null>(null);
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
    traceAllowed &&
    rulesLoaded &&
    address.trim().length > 0 &&
    (mode === "all" || (!!selectedUser && sourceAddressReady)) &&
    !sourceAddressesLoading &&
    !submitting;

  // A colon typed straight into the address wins over the port block; otherwise
  // the block's value is used. The block only ever writes a host-only address.
  const parsedAddress = parseTarget(address);
  const previewHost = parsedAddress.host || address.trim();
  const effectivePort = parsedAddress.port ?? port;
  const targetPreview = previewHost ? (effectivePort ? `${previewHost}:${effectivePort}` : previewHost) : "";
  const matchedPreset = effectivePort === null ? null : (SERVICE_PRESETS.find((p) => p.port === effectivePort) ?? null);
  const portTitle = effectivePort === null ? t("check.portDefault") : matchedPreset ? matchedPreset.name : t("check.servicePortHint", { port: effectivePort });

  function handleSubmit() {
    if (!canCheck) return;
    const host = previewHost;
    const finalPort = effectivePort;
    const url = finalPort ? `${host}:${finalPort}` : host;
    // Fold a colon typed into the address back into the separate fields.
    setAddress(host);
    setPort(finalPort);
    // Remember entered addresses (deduplicated, newest first, bounded in storage.ts).
    setRecentUrls(pushRecentUrl(url));
    onSubmit({
      url,
      userId: mode === "user" ? (selectedUser?.id ?? undefined) : undefined,
      sourceIp: mode === "user" ? (selectedSourceIp ?? undefined) : undefined,
    });
  }

  /** Replace the target from pasted text or a recent chip: host to the address,
   *  port to the block (a missing port clears it — it is a brand-new target). */
  function applyTarget(raw: string) {
    const parsed = parseTarget(raw);
    setAddress(parsed.host || raw.trim());
    setPort(parsed.port);
  }

  /** On blur, only fold a colon typed into the address into the block; never
   *  clear a port already chosen in the port field. */
  function normalizeAddressOnBlur() {
    const parsed = parseTarget(address);
    if (parsed.port !== null) setPort(parsed.port);
    if (parsed.host && parsed.host !== address) setAddress(parsed.host);
  }

  /** The port field is a combobox: type any number or pick a named preset from
   *  the datalist. Non-digits are ignored; empty means the backend default. */
  function handlePortInput(raw: string) {
    setAddress(previewHost);
    const digits = raw.replace(/\D/g, "");
    setPort(digits === "" ? null : clampPort(Number(digits)));
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

      {/* Address and port share one row; the port control shows only the service
          name, revealing the actual number through its hover title. */}
      <div style={{ display: "flex", flexWrap: "wrap", gap: 12, alignItems: "flex-end", marginBottom: 10 }}>
        <div style={{ flex: "1 1 200px", minWidth: 0, display: "flex", flexDirection: "column", gap: 6 }}>
          <div style={{ fontSize: 12.5, fontWeight: 600, color: "var(--muted)" }}>{t("check.addressLabel")}</div>
          <input
            value={address}
            title={targetPreview || undefined}
            onChange={(e) => setAddress(e.target.value)}
            onBlur={normalizeAddressOnBlur}
            onPaste={(e) => {
              const text = e.clipboardData.getData("text");
              if (!text.trim()) return;
              e.preventDefault();
              applyTarget(text);
            }}
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
              // Two-line height; the single-line value is clipped with an ellipsis
              // and the full target stays available through the hover title.
              minHeight: 52,
              textOverflow: "ellipsis",
            }}
          />
        </div>

        <div style={{ flex: "0 0 auto", display: "flex", flexDirection: "column", gap: 6 }}>
          <label htmlFor="port-input" style={{ fontSize: 12.5, fontWeight: 600, color: "var(--muted)" }}>
            {t("check.portLabel")}
          </label>
          {/* One combobox: type any port or pick a named preset from the list. */}
          <input
            id="port-input"
            list="port-presets"
            inputMode="numeric"
            value={port ?? ""}
            onChange={(e) => handlePortInput(e.target.value)}
            title={portTitle}
            placeholder={t("check.portDefault")}
            className="form-control mono"
            style={{
              border: "1px solid var(--line)",
              background: "var(--panel2)",
              color: "var(--text)",
              borderRadius: "var(--radius-sm)",
              padding: "11px 12px",
              fontSize: 13.5,
              minHeight: 52,
              width: 132,
            }}
          />
          <datalist id="port-presets">
            {SERVICE_PRESETS.map((preset) => (
              <option key={preset.name} value={preset.port} label={preset.name} />
            ))}
          </datalist>
        </div>
      </div>

      {recentUrls.length > 0 && (
        <div className="example-chip-list" style={{ marginBottom: 14 }}>
          {recentUrls.map((url) => (
            <button
              key={url}
              type="button"
              className="example-chip mono"
              title={url}
              onClick={() => applyTarget(url)}
              style={{
                borderRadius: 999,
                padding: "4px 10px",
                fontSize: 12,
                maxWidth: "100%",
                overflow: "hidden",
                textOverflow: "ellipsis",
                whiteSpace: "nowrap",
              }}
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

      {!traceAllowed && (
        <div
          role="alert"
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
          {t("access.traceDisabled")}
        </div>
      )}

      {!traceAllowed
        ? null
        : !rulesLoaded && (
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
        <PipelineOrder />
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
