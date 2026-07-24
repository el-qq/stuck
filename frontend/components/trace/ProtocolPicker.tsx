"use client";

import React from "react";
import { useI18n } from "@/i18n";
import { Protocol } from "@/lib/types";
import { PROTOCOL_OPTIONS, protocolDisplayLabel } from "@/lib/protocol";

interface Props {
  value: Protocol;
  onChange: (protocol: Protocol) => void;
  /** Defaults to the shared "Protocol" label (`compare.protocolLabel`) — the
   *  same text works for both the trace and access-compare forms. */
  label?: string;
}

/**
 * Reusable 8-way NGFW firewall protocol selector, shared by the trace
 * ("Проверка трафика") and access-compare forms. A button grid rather than an
 * 8-wide segmented control — a single row of 8 does not fit a narrow control
 * panel (320px mobile), so it wraps into a 4x2 grid instead.
 */
export function ProtocolPicker({ value, onChange, label }: Props) {
  const { t } = useI18n();
  const groupLabel = label ?? t("compare.protocolLabel");

  return (
    <div className="protocol-picker">
      <div className="protocol-picker__label">{groupLabel}</div>
      <div className="protocol-picker__options" role="group" aria-label={groupLabel}>
        {PROTOCOL_OPTIONS.map((proto) => (
          <button key={proto} type="button" className="seg-btn mono" aria-pressed={value === proto} onClick={() => onChange(proto)}>
            {protocolDisplayLabel(proto, t)}
          </button>
        ))}
      </div>
    </div>
  );
}
