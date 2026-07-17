import { ApiError, logApiError, normalizeErrorCode } from "./errors";
import {
  ErrorEnvelope,
  HealthResponse,
  LoginRequest,
  LoginResponse,
  PublicConfig,
  RulesRefreshResponse,
  SessionStatus,
  STAGE_ORDER,
  TraceRequest,
  TraceResponse,
  UserSourceAddressesResponse,
  UsersResponse,
} from "./types";

// A browser fetch has no timeout by default. Without one an unavailable or
// half-open reverse proxy leaves the session bootstrap on "Checking…" forever.
const REQUEST_TIMEOUT_MS = 15_000;

/**
 * Thin client for our own backend (docs/API_CONTRACT.md). All calls are
 * same-origin (`/api/*`, proxied by Vite in development and Caddy in Docker) and
 * always sent with credentials so the HttpOnly `stuck_session` cookie is
 * attached automatically. The frontend never reads or stores the cookie
 * itself (see the security invariants in docs/ARCHITECTURE.md).
 */

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function isErrorEnvelope(v: unknown): v is ErrorEnvelope {
  return isPlainObject(v) && isPlainObject(v.error) && typeof v.error.code === "string";
}

async function parseJsonSafe(res: Response): Promise<unknown | null> {
  const text = await res.text();
  if (!text) return null;
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return null;
  }
}

function assertShape(cond: boolean, path: string): void {
  if (!cond) {
    const err = new ApiError("api_changed", `Response from ${path} does not match the expected schema`);
    logApiError(path, err);
    throw err;
  }
}

/**
 * Single funnel for every backend call. All ApiErrors are logged here (and in
 * assertShape above) in the unified "[stuck] api error: ..." format — never
 * per-component, and never including request bodies or credentials.
 */
async function request<T>(path: string, init?: RequestInit): Promise<T> {
  try {
    return await requestInner<T>(path, init);
  } catch (err) {
    if (err instanceof ApiError) logApiError(path, err);
    throw err;
  }
}

async function requestInner<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  const parentSignal = init?.signal;
  const abortFromParent = () => controller.abort();
  if (parentSignal) {
    if (parentSignal.aborted) controller.abort();
    else parentSignal.addEventListener("abort", abortFromParent, { once: true });
  }
  try {
    res = await fetch(path, {
      ...init,
      signal: controller.signal,
      credentials: "include",
      headers: {
        Accept: "application/json",
        ...(init?.body ? { "Content-Type": "application/json" } : {}),
        ...(init?.headers ?? {}),
      },
    });
  } catch {
    // fetch() throws on DNS failure / connection refused / CORS / offline.
    throw new ApiError("server_unreachable", `Network error calling ${path}`);
  } finally {
    clearTimeout(timeout);
    parentSignal?.removeEventListener("abort", abortFromParent);
  }

  if (!res.ok) {
    const body = await parseJsonSafe(res);
    if (isErrorEnvelope(body)) {
      throw new ApiError(normalizeErrorCode(body.error.code), body.error.message || res.statusText, {
        httpStatus: res.status,
        details: body.error.details,
      });
    }
    // Backend responded but not with our error envelope (proxy error page, etc).
    if (res.status >= 500) {
      throw new ApiError("server_unreachable", `Backend returned ${res.status} without an error envelope`, {
        httpStatus: res.status,
      });
    }
    throw new ApiError("internal_error", `Unexpected ${res.status} response from ${path}`, {
      httpStatus: res.status,
    });
  }

  if (res.status === 204) return undefined as T;
  const body = await parseJsonSafe(res);
  if (body === null) {
    throw new ApiError("api_changed", `Could not parse JSON response from ${path}`);
  }
  return body as T;
}

export async function login(payload: LoginRequest): Promise<LoginResponse> {
  const data = await request<LoginResponse>("/api/auth/login", {
    method: "POST",
    body: JSON.stringify(payload),
  });
  assertShape(!!data?.session && typeof data.session.login === "string" && "rules_updated_at" in data.session, "/api/auth/login");
  return data;
}

export async function getPublicConfig(): Promise<PublicConfig> {
  const data = await request<PublicConfig>("/api/config", { method: "GET" });
  assertShape(typeof data?.default_server === "string", "/api/config");
  return data;
}

export async function logout(): Promise<{ ok: true }> {
  return request<{ ok: true }>("/api/auth/logout", { method: "POST" });
}

export async function getSession(): Promise<SessionStatus> {
  const data = await request<SessionStatus>("/api/session", { method: "GET" });
  assertShape(
    typeof data?.login === "string" && typeof data?.server === "string" && typeof data?.expires_at === "string" && "rules_updated_at" in data,
    "/api/session",
  );
  return data;
}

export async function getUsers(search?: string): Promise<UsersResponse> {
  const qs = search && search.trim() ? `?search=${encodeURIComponent(search.trim())}` : "";
  const data = await request<UsersResponse>(`/api/users${qs}`, { method: "GET" });
  assertShape(Array.isArray(data?.users), "/api/users");
  return data;
}

export async function getUserSourceAddresses(userId: string): Promise<UserSourceAddressesResponse> {
  const path = `/api/users/${encodeURIComponent(userId)}/source-addresses`;
  const data = await request<UserSourceAddressesResponse>(path, { method: "GET" });
  assertShape(typeof data?.user_id === "string" && Array.isArray(data?.addresses) && data.addresses.every((address) => typeof address?.ip === "string"), path);
  return data;
}

export async function trace(payload: TraceRequest): Promise<TraceResponse> {
  const data = await request<TraceResponse>("/api/trace", {
    method: "POST",
    body: JSON.stringify(payload),
  });
  assertShape(Array.isArray(data?.stages) && data.stages.length === STAGE_ORDER.length && !!data?.summary, "/api/trace");
  return data;
}

export async function refreshRules(): Promise<RulesRefreshResponse> {
  return request<RulesRefreshResponse>("/api/rules/refresh", { method: "POST" });
}

export async function health(): Promise<HealthResponse> {
  return request<HealthResponse>("/api/health", { method: "GET" });
}

export interface RulesExport {
  blob: Blob;
  /** Filename from Content-Disposition, or null if the header was absent. */
  filename: string | null;
}

/** RFC 5987-ish extraction of a filename from a Content-Disposition header. */
function parseContentDispositionFilename(header: string | null): string | null {
  if (!header) return null;
  const star = /filename\*\s*=\s*(?:UTF-8'')?([^;]+)/i.exec(header);
  if (star && star[1]) {
    try {
      return decodeURIComponent(star[1].trim().replace(/^["']|["']$/g, ""));
    } catch {
      // fall through to the plain form
    }
  }
  const plain = /filename\s*=\s*"?([^";]+)"?/i.exec(header);
  return plain && plain[1] ? plain[1].trim() : null;
}

/**
 * Download the full rules snapshot for the current pair. The
 * response can be large, so it is streamed straight into a Blob for download
 * rather than parsed into app state. Errors are mapped to the same typed
 * ApiError as every other call (session_expired drives the re-login flow).
 */
export async function exportRules(): Promise<RulesExport> {
  const path = "/api/rules/export";
  let res: Response;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    res = await fetch(path, {
      method: "GET",
      signal: controller.signal,
      credentials: "include",
      headers: { Accept: "application/json" },
    });
  } catch {
    const err = new ApiError("server_unreachable", `Network error calling ${path}`);
    logApiError(path, err);
    throw err;
  } finally {
    clearTimeout(timeout);
  }

  if (!res.ok) {
    const body = await parseJsonSafe(res);
    let err: ApiError;
    if (isErrorEnvelope(body)) {
      err = new ApiError(normalizeErrorCode(body.error.code), body.error.message || res.statusText, {
        httpStatus: res.status,
        details: body.error.details,
      });
    } else if (res.status >= 500) {
      err = new ApiError("server_unreachable", `Backend returned ${res.status} without an error envelope`, {
        httpStatus: res.status,
      });
    } else {
      err = new ApiError("internal_error", `Unexpected ${res.status} response from ${path}`, {
        httpStatus: res.status,
      });
    }
    logApiError(path, err);
    throw err;
  }

  const blob = await res.blob();
  const filename = parseContentDispositionFilename(res.headers.get("Content-Disposition"));
  return { blob, filename };
}
