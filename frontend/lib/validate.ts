/**
 * Contract v2 (§3.1, invariant 6): `server` is ONLY an IPv4 address or a
 * hostname (RFC 1123) — no scheme, no port, no path. The backend appends the
 * NGFW port itself (conf STUCK_NGFW_PORT, default 8443).
 */
export function isValidServerFormat(value: string): boolean {
  const v = value.trim();
  if (!v || v.length > 253) return false;
  // Reject scheme/port/path/credentials/query/spaces outright.
  if (/[\s:/@?#\\]/.test(v)) return false;
  // IPv4: each octet 0-255.
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v)) {
    return v.split(".").every((octet) => Number(octet) <= 255);
  }
  // Hostname per RFC 1123: labels of alnum/hyphen, no leading/trailing hyphen.
  return v.split(".").every((label) => /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/.test(label));
}
