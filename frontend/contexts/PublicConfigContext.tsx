"use client";

import React, { createContext, useContext, useEffect, useMemo, useState } from "react";
import * as api from "@/lib/api";

interface PublicConfigContextValue {
  /** Defaults to true to preserve the historical UI when an older backend or
   * a temporarily unavailable bootstrap endpoint does not provide the flag. */
  traceAnimationEnabled: boolean;
}

const PublicConfigContext = createContext<PublicConfigContextValue>({ traceAnimationEnabled: true });

export function PublicConfigProvider({ children }: { children: React.ReactNode }) {
  const [traceAnimationEnabled, setTraceAnimationEnabled] = useState(true);

  useEffect(() => {
    let cancelled = false;
    void api
      .getPublicConfig()
      .then((config) => {
        if (!cancelled && typeof config.trace_animation_enabled === "boolean") {
          setTraceAnimationEnabled(config.trace_animation_enabled);
        }
      })
      .catch(() => {
        // Keep the enabled default when bootstrapping configuration is not
        // available. A trace result must never be blocked on this metadata.
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const value = useMemo(() => ({ traceAnimationEnabled }), [traceAnimationEnabled]);
  return <PublicConfigContext.Provider value={value}>{children}</PublicConfigContext.Provider>;
}

export function usePublicConfig(): PublicConfigContextValue {
  return useContext(PublicConfigContext);
}
