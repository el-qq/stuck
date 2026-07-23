"use client";

import { useEffect, useState } from "react";
import { getRecentUrls, pushRecentUrl } from "@/lib/storage";
import { clampPort, parseTarget } from "@/lib/servicePresets";

/** State and normalization rules for the host/port part of a trace request.
 *
 * The UI may collect a target in two fields, by pasting ``host:port`` or from a
 * recent-target chip. Keeping all conversions here ensures each entry path
 * follows the same rule: a port typed into the address wins over the port box.
 */
export interface TraceTargetController {
  address: string;
  port: number | null;
  recentUrls: string[];
  previewHost: string;
  effectivePort: number | null;
  targetPreview: string;
  setAddress: (address: string) => void;
  applyTarget: (raw: string) => void;
  normalizeAddressOnBlur: () => void;
  handlePortInput: (raw: string) => void;
  submitTarget: () => string;
}

export function useTraceTarget(): TraceTargetController {
  const [address, setAddress] = useState("");
  // Null deliberately means "use the backend's configured default port".
  const [port, setPort] = useState<number | null>(null);
  const [recentUrls, setRecentUrls] = useState<string[]>([]);

  useEffect(() => {
    setRecentUrls(getRecentUrls());
  }, []);

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
    // The port control always writes a host-only target, so the next address
    // edit is unambiguous and does not retain a stale pasted ``:port`` suffix.
    setAddress(previewHost);
    const digits = raw.replace(/\D/g, "");
    setPort(digits === "" ? null : clampPort(Number(digits)));
  }

  function submitTarget(): string {
    const url = effectivePort ? `${previewHost}:${effectivePort}` : previewHost;
    setAddress(previewHost);
    setPort(effectivePort);
    setRecentUrls(pushRecentUrl(url));
    return url;
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
