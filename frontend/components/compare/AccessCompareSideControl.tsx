"use client";

import React, { useState } from "react";
import { useI18n } from "@/i18n";
import { DomainType } from "@/lib/types";
import { SourceAddressPicker } from "../trace/SourceAddressPicker";
import { UserPicker } from "../trace/UserPicker";
import type { AccessCompareSideState, CompareSubjectMode } from "./accessCompareState";

interface Props {
  label: string;
  side: AccessCompareSideState;
}

/** One side's subject input (docs/source/comparison.md §3.b/§3.c): a user
 * (reusing the exact `UserPicker`/`SourceAddressPicker` from the check tab),
 * a raw source IP with no identity, or no specific subject at all. Backend
 * still validates everything (an unknown user, an unassigned/ambiguous IP)
 * — `side.errorText` surfaces that per-side, next to this side only. */
export function AccessCompareSideControl({ label, side }: Props) {
  const { t } = useI18n();
  const [query, setQuery] = useState("");
  const [domainFilter, setDomainFilter] = useState<"all" | DomainType>("all");

  return (
    <div className="access-compare-side">
      <div className="access-compare-side__label">{label}</div>
      <div className="segmented-control access-compare-side__modes" role="group" aria-label={label}>
        {(["none", "user", "ip"] as CompareSubjectMode[]).map((mode) => (
          <button key={mode} type="button" className="seg-btn" aria-pressed={side.mode === mode} onClick={() => side.setMode(mode)}>
            {mode === "none" ? t("compare.modeNone") : mode === "user" ? t("compare.modeUser") : t("compare.modeIp")}
          </button>
        ))}
      </div>

      {side.mode === "user" && (
        <>
          <UserPicker
            users={side.subjects.users}
            loading={side.subjects.usersLoading}
            errorText={side.subjects.usersError}
            query={query}
            onQueryChange={setQuery}
            domainFilter={domainFilter}
            onDomainFilterChange={setDomainFilter}
            selectedUserId={side.subjects.selectedUserId}
            onSelect={side.subjects.setSelectedUserId}
          />
          {side.subjects.selectedUser && (
            <SourceAddressPicker
              addresses={side.subjects.sourceAddresses}
              loading={side.subjects.sourceAddressesLoading}
              errorText={side.subjects.sourceAddressesError}
              selectedIp={side.subjects.selectedSourceIp}
              onSelect={side.subjects.setSelectedSourceIp}
            />
          )}
        </>
      )}

      {side.mode === "ip" && (
        <div className="access-compare-side__manual-ip">
          <label className="access-compare-side__manual-ip-label" htmlFor={`compare-ip-${label}`}>
            {t("compare.manualIpLabel")}
          </label>
          <input
            id={`compare-ip-${label}`}
            className="form-control mono"
            value={side.manualIp}
            onChange={(event) => side.setManualIp(event.target.value)}
            placeholder={t("compare.manualIpPlaceholder")}
          />
        </div>
      )}

      {side.errorText && (
        <div role="alert" className="access-compare-side__error">
          {side.errorText}
        </div>
      )}
    </div>
  );
}
