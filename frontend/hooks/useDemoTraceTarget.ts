"use client";

import { useState } from "react";
import type { TraceTargetController } from "./useTraceTarget";
import { clampPort, parseTarget } from "@/lib/servicePresets";
import { DEMO_TARGETS } from "@/lib/demoData";

interface Options {
  /** Defaults to the first demo target (`success.com:443`) — the same
   *  starting point the check tab has always used. */
  initialHost?: string;
  initialPort?: number;
  /** One-click example chips. Defaults to both known demo targets. */
  recentUrls?: string[];
}

/**
 * Offline adapter for `TraceTargetController`: the same host/port
 * normalization rules the live `useTraceTarget` applies, over a fixed local
 * example list instead of localStorage history. Shared by the check tab and
 * the access-compare tab's demo adapters so both offer identical target
 * controls with only their starting value differing.
 */
export function useDemoTraceTarget({
  initialHost = DEMO_TARGETS[0]!.host,
  initialPort = DEMO_TARGETS[0]!.dst_port,
  recentUrls = DEMO_TARGETS.map((target) => target.address),
}: Options = {}): TraceTargetController {
  const [address, setAddress] = useState(initialHost);
  const [port, setPort] = useState<number | null>(initialPort);
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
    recentUrls,
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
