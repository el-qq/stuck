/**
 * Small typed helpers over localStorage for non-sensitive UI conveniences
 * such as the last successfully used server and recently entered check
 * addresses. Never store credentials or session material here.
 * All helpers swallow storage errors (private mode, disabled storage).
 */

const LAST_SERVER_KEY = "stuck.lastServer";
const RECENT_URLS_KEY = "stuck.recentUrls";
const RECENT_URLS_MAX = 10;

export function getLastServer(): string | null {
  if (typeof window === "undefined") return null;
  try {
    return window.localStorage.getItem(LAST_SERVER_KEY);
  } catch {
    return null;
  }
}

export function setLastServer(server: string): void {
  try {
    window.localStorage.setItem(LAST_SERVER_KEY, server);
  } catch {
    // ignore
  }
}

export function getRecentUrls(): string[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = window.localStorage.getItem(RECENT_URLS_KEY);
    if (!raw) return [];
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((v): v is string => typeof v === "string").slice(0, RECENT_URLS_MAX);
  } catch {
    return [];
  }
}

/** Prepends the address, dedupes case-sensitively and keeps the newest entries. */
export function pushRecentUrl(url: string): string[] {
  const trimmed = url.trim();
  if (!trimmed) return getRecentUrls();
  const next = [trimmed, ...getRecentUrls().filter((u) => u !== trimmed)].slice(0, RECENT_URLS_MAX);
  try {
    window.localStorage.setItem(RECENT_URLS_KEY, JSON.stringify(next));
  } catch {
    // ignore
  }
  return next;
}
