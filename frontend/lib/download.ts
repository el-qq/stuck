/**
 * Triggers a browser download of a Blob via a temporary object URL and a
 * synthetic <a download> click. Client-only.
 */
export function downloadBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  try {
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.rel = "noopener";
    document.body.appendChild(a);
    a.click();
    a.remove();
  } finally {
    // Revoke on the next tick so the download has a chance to start.
    setTimeout(() => URL.revokeObjectURL(url), 0);
  }
}

/** Fallback export filename: rules-<server>-<timestamp>.json. */
export function defaultRulesExportFilename(server: string): string {
  const safeServer = server.replace(/[^a-zA-Z0-9._-]/g, "_") || "ngfw";
  const ts = new Date().toISOString().replace(/[:.]/g, "-");
  return `rules-${safeServer}-${ts}.json`;
}
