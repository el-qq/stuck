/**
 * Service presets (feature #5). A preset is a well-known destination port the
 * user can pick from a dropdown instead of typing a number. The port is a
 * separate value from the address; the address field holds only the host.
 */
export const SERVICE_PRESETS = [
  { name: "HTTPS", port: 443 },
  { name: "RDP", port: 3389 },
  { name: "SMTP", port: 25 },
] as const;

/** A destination port is valid only inside the TCP/UDP range. */
export function clampPort(value: number): number | null {
  return Number.isInteger(value) && value >= 1 && value <= 65535 ? value : null;
}

/**
 * Smartly reduce a pasted or typed target to its host and destination port.
 * A full URL keeps only the host (scheme, credentials, path, query and
 * fragment are dropped); a bare `host:port` is split on the colon. Returns a
 * null port when none is present or the port is out of range.
 */
export function parseTarget(raw: string): { host: string; port: number | null } {
  const trimmed = raw.trim();
  if (!trimmed) return { host: "", port: null };

  const hasScheme = /^[a-zA-Z][\w+.-]*:\/\//.test(trimmed);
  try {
    const url = new URL(hasScheme ? trimmed : `http://${trimmed}`);
    if (url.hostname) {
      return { host: url.hostname, port: url.port ? clampPort(Number(url.port)) : null };
    }
  } catch {
    // Not URL-shaped; fall back to manual host:port splitting below.
  }

  // Strip any path/query/fragment, then split a trailing numeric :port.
  const authority = trimmed.split(/[/?#]/)[0]!;
  const colon = authority.lastIndexOf(":");
  if (colon > 0 && /^\d+$/.test(authority.slice(colon + 1))) {
    return { host: authority.slice(0, colon), port: clampPort(Number(authority.slice(colon + 1))) };
  }
  return { host: authority, port: null };
}
