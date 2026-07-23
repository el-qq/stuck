import React from "react";

export const warnBlockStyle: React.CSSProperties = {
  fontSize: 12.5,
  color: "var(--warn)",
  background: "var(--warn-soft)",
  borderRadius: "var(--radius-sm)",
  padding: "10px 12px",
  marginBottom: 14,
  lineHeight: 1.45,
};

export const fieldLabelStyle: React.CSSProperties = {
  display: "flex",
  flexDirection: "column",
  gap: 6,
  fontSize: 12.5,
  fontWeight: 600,
  color: "var(--muted)",
};

export const inputStyle: React.CSSProperties = {
  border: "1px solid var(--line)",
  background: "var(--panel2)",
  color: "var(--text)",
  borderRadius: "var(--radius-sm)",
  padding: "10px 12px",
  fontSize: 14,
  width: "100%",
};

export const errStyle: React.CSSProperties = {
  fontSize: 11.5,
  color: "var(--bad)",
  fontWeight: 600,
};

export const submitButtonStyle: React.CSSProperties = {
  marginTop: 8,
  borderRadius: "var(--radius-sm)",
  padding: 12,
  fontSize: 14.5,
  fontWeight: 600,
};

export const demoButtonStyle: React.CSSProperties = {
  borderRadius: "var(--radius-sm)",
  padding: 11,
  fontSize: 14,
  fontWeight: 600,
};
