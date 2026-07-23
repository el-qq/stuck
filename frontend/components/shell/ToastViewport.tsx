"use client";

import React from "react";
import { useToast } from "@/contexts/ToastContext";

const TONE_VAR: Record<string, string> = {
  info: "var(--accent)",
  error: "var(--bad)",
  success: "var(--ok)",
};

export function ToastViewport() {
  const { toasts, dismiss } = useToast();
  if (toasts.length === 0) return null;

  return (
    <div
      className="toast-viewport"
      style={{
        position: "fixed",
        top: 16,
        right: 16,
        zIndex: 200,
        display: "flex",
        flexDirection: "column",
        gap: 8,
        maxWidth: 360,
      }}
    >
      {toasts.map((toast) => (
        <div
          key={toast.id}
          role="status"
          onClick={() => dismiss(toast.id)}
          style={{
            background: "var(--panel)",
            border: `1px solid var(--line)`,
            borderLeft: `3px solid ${TONE_VAR[toast.tone] ?? "var(--accent)"}`,
            color: "var(--text)",
            borderRadius: "var(--radius-sm)",
            boxShadow: "var(--shadow)",
            padding: "12px 14px",
            fontSize: 13.5,
            cursor: "pointer",
            animation: "fadeUp .3s ease both",
          }}
        >
          {toast.text}
        </div>
      ))}
    </div>
  );
}
