"use client";

import React, { createContext, useCallback, useContext, useMemo, useRef, useState } from "react";

export type ToastTone = "info" | "error" | "success";

export interface Toast {
  id: number;
  tone: ToastTone;
  text: string;
}

interface ToastContextValue {
  toasts: Toast[];
  show: (text: string, tone?: ToastTone) => void;
  dismiss: (id: number) => void;
}

const ToastContext = createContext<ToastContextValue | null>(null);

const AUTO_DISMISS_MS = 5000;

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const counter = useRef(0);

  const dismiss = useCallback((id: number) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const show = useCallback(
    (text: string, tone: ToastTone = "info") => {
      const id = ++counter.current;
      setToasts((prev) => [...prev, { id, tone, text }]);
      setTimeout(() => dismiss(id), AUTO_DISMISS_MS);
    },
    [dismiss],
  );

  const value = useMemo(() => ({ toasts, show, dismiss }), [toasts, show, dismiss]);

  return <ToastContext.Provider value={value}>{children}</ToastContext.Provider>;
}

export function useToast(): ToastContextValue {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error("useToast must be used within ToastProvider");
  return ctx;
}
