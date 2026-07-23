"use client";

import React from "react";
import { useI18n } from "@/i18n";
import { UserSourceAddress } from "@/lib/types";

interface Props {
  addresses: UserSourceAddress[];
  loading: boolean;
  errorText: string | null;
  selectedIp: string | null;
  onSelect: (ip: string) => void;
}

/** Render the explicit source-IP choice required when a user has several IPs. */
export function SourceAddressPicker({ addresses, loading, errorText, selectedIp, onSelect }: Props) {
  const { t } = useI18n();

  return (
    <div className="source-address-picker">
      <div className="source-address-picker__label">{t("check.sourceIpLabel")}</div>
      {loading && <div className="source-address-picker__message">{t("check.sourceIpLoading")}</div>}
      {!loading && errorText && <div className="source-address-picker__message source-address-picker__message--error">{errorText}</div>}
      {!loading && !errorText && addresses.length === 0 && (
        <div className="source-address-picker__message source-address-picker__message--warning">{t("check.sourceIpEmpty")}</div>
      )}
      {!loading && addresses.length > 0 && (
        <div className="source-address-picker__options" role="radiogroup" aria-label={t("check.sourceIpLabel")}>
          {addresses.map((source) => {
            const selected = selectedIp === source.ip;
            return (
              <button
                key={source.ip}
                type="button"
                role="radio"
                aria-checked={selected}
                className="source-address-picker__option mono"
                onClick={() => onSelect(source.ip)}
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
      {addresses.length > 1 && !selectedIp && <div className="source-address-picker__hint">{t("check.sourceIpChoose")}</div>}
    </div>
  );
}
