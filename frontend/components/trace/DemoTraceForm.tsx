"use client";

import React, { useEffect, useMemo, useState } from "react";
import { useI18n } from "@/i18n";
import type { TraceTargetController } from "@/hooks/useTraceTarget";
import type { TraceMode, TraceSubjectsState } from "@/hooks/useTraceSubjects";
import { clampPort, parseTarget } from "@/lib/servicePresets";
import { DEMO_SOURCE_ADDRESSES, DEMO_TARGETS, DEMO_USERS } from "@/lib/demoData";
import type { TraceSubmitPayload } from "./TraceForm";
import { TraceCheckPanel } from "./TraceCheckPanel";

interface Props {
  submitting: boolean;
  onSubmit: (payload: TraceSubmitPayload) => void;
}

/** Offline adapter for the exact same trace controls used after sign-in. It
 * has no API/session imports: all subjects and source IPs are static fixtures. */
export function DemoTraceForm({ submitting, onSubmit }: Props) {
  const [mode, setMode] = useState<TraceMode>("all");
  const target = useDemoTraceTarget();
  const subjects = useDemoTraceSubjects(mode);

  return (
    <TraceCheckPanel
      rulesLoaded
      traceAllowed
      submitting={submitting}
      mode={mode}
      onModeChange={setMode}
      target={target}
      subjects={subjects}
      onSubmit={onSubmit}
    />
  );
}

function useDemoTraceTarget(): TraceTargetController {
  const [address, setAddress] = useState(DEMO_TARGETS[0]!.host);
  const [port, setPort] = useState<number | null>(DEMO_TARGETS[0]!.dst_port);
  const parsedAddress = parseTarget(address);
  const previewHost = parsedAddress.host || address.trim();
  const effectivePort = parsedAddress.port ?? port;
  const targetPreview = previewHost ? (effectivePort ? `${previewHost}:${effectivePort}` : previewHost) : "";

  function applyTarget(raw: string) {
    const parsed = parseTarget(raw);
    setAddress(parsed.host || raw.trim());
    setPort(parsed.port);
  }

  function normalizeAddressOnBlur() {
    const parsed = parseTarget(address);
    if (parsed.port !== null) setPort(parsed.port);
    if (parsed.host && parsed.host !== address) setAddress(parsed.host);
  }

  function handlePortInput(raw: string) {
    setAddress(previewHost);
    const digits = raw.replace(/\D/g, "");
    setPort(digits === "" ? null : clampPort(Number(digits)));
  }

  function submitTarget() {
    const value = effectivePort ? `${previewHost}:${effectivePort}` : previewHost;
    setAddress(previewHost);
    setPort(effectivePort);
    return value;
  }

  return {
    address,
    port,
    recentUrls: DEMO_TARGETS.map((target) => target.address),
    previewHost,
    effectivePort,
    targetPreview,
    setAddress,
    applyTarget,
    normalizeAddressOnBlur,
    handlePortInput,
    submitTarget,
  };
}

function useDemoTraceSubjects(mode: TraceMode): TraceSubjectsState {
  const [selectedUserId, setSelectedUserId] = useState<string | null>(null);
  const [selectedSourceIp, setSelectedSourceIp] = useState<string | null>(null);
  const selectedUser = DEMO_USERS.find((user) => user.id === selectedUserId) ?? null;
  const sourceAddresses = useMemo(() => (selectedUser ? (DEMO_SOURCE_ADDRESSES[selectedUser.id] ?? []) : []), [selectedUser]);

  useEffect(() => {
    if (mode !== "user" || sourceAddresses.length !== 1) {
      setSelectedSourceIp(null);
      return;
    }
    setSelectedSourceIp(sourceAddresses[0]!.ip);
  }, [mode, selectedUserId, sourceAddresses]);

  return {
    users: DEMO_USERS,
    usersLoading: false,
    usersError: null,
    selectedUserId,
    setSelectedUserId,
    selectedUser,
    sourceAddresses,
    sourceAddressesLoading: false,
    sourceAddressesError: null,
    selectedSourceIp,
    setSelectedSourceIp,
  };
}
