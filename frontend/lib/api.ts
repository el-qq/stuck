import { ApiError, logApiError, normalizeErrorCode } from "./errors";
import {
  ErrorEnvelope,
  AccessProfileRefreshResponse,
  CreateSnapshotRequest,
  CreateSnapshotResponse,
  DeleteSnapshotResponse,
  HealthResponse,
  ImportSnapshotRequest,
  ImportSnapshotResponse,
  LoginRequest,
  LoginOutcome,
  LoginResponse,
  PublicConfig,
  RuleHygieneReport,
  RulesRefreshResponse,
  SessionStatus,
  SessionBootstrap,
  SnapshotOrCurrentId,
  SnapshotDiffResponse,
  SnapshotsListResponse,
  STAGE_ORDER,
  TraceRequest,
  TraceResponse,
  TwoFactorRequiredResponse,
  TwoFactorSubmitResponse,
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

/**
 * Sign in. Resolves to a discriminated {@link LoginOutcome}: either the created
 * session, or a "second factor required" signal (the backend has set the
 * HttpOnly `stuck_2fa` cookie and the caller must show the code form and call
 * {@link submit2fa}). Never returns or stores any secret.
 *
 * NOTE: the mapping below is intentionally thin plumbing so normal login keeps
 * working; the genuinely-new operations ({@link submit2fa}/{@link cancel2fa})
 * and the form UI are the stubbed parts of this feature.
 */
export async function login(payload: LoginRequest): Promise<LoginOutcome> {
  const data = await request<LoginResponse | TwoFactorRequiredResponse>("/api/auth/login", {
    method: "POST",
    body: JSON.stringify(payload),
  });
  if ((data as TwoFactorRequiredResponse).two_factor_required === true) {
    const tfa = data as TwoFactorRequiredResponse;
    assertShape(typeof tfa.expires_at === "string", "/api/auth/login");
    return { twoFactorRequired: true, expiresAt: tfa.expires_at, message: tfa.message ?? null };
  }
  const ok = data as LoginResponse;
  assertShape(!!ok?.session && typeof ok.session.login === "string" && "rules_updated_at" in ok.session, "/api/auth/login");
  return { twoFactorRequired: false, session: ok.session };
}

/**
 * Submit the second-factor code for the in-flight challenge (located by the
 * HttpOnly `stuck_2fa` cookie; the code is never persisted). On success the
 * backend swaps `stuck_2fa` for `stuck_session` and returns the session.
 *
 * A rejected-but-retryable code surfaces as a thrown ApiError with code
 * `second_factor_invalid` and `details.can_retry === true` (keep the form open);
 * a closed/expired challenge throws `second_factor_expired` (return to login).
 *
 * TODO(impl): POST /api/auth/2fa with `{ code }`, assertShape on `session`,
 * return the session. Let the shared `request` funnel raise the typed errors.
 */
export async function submit2fa(code: string): Promise<TwoFactorSubmitResponse> {
  const data = await request<TwoFactorSubmitResponse>("/api/auth/2fa", {
    method: "POST",
    body: JSON.stringify({ code }),
  });
  assertShape(!!data?.session && typeof data.session.login === "string" && "rules_updated_at" in data.session, "/api/auth/2fa");
  return data;
}

/**
 * Cancel the in-flight 2FA challenge (idempotent; mirrors {@link logout}).
 * Always resolves so the UI can return to the login screen.
 *
 * TODO(impl): POST /api/auth/2fa/cancel and return `{ ok: true }`.
 */
export async function cancel2fa(): Promise<{ ok: true }> {
  await request<{ ok: true }>("/api/auth/2fa/cancel", { method: "POST" });
  return { ok: true };
}

export async function getPublicConfig(): Promise<PublicConfig> {
  const data = await request<PublicConfig>("/api/config", { method: "GET" });
  assertShape(typeof data?.default_server === "string", "/api/config");
  return data;
}

export async function logout(): Promise<{ ok: true }> {
  return request<{ ok: true }>("/api/auth/logout", { method: "POST" });
}

export async function getSession(): Promise<SessionBootstrap> {
  const data = await request<SessionStatus & { two_factor_pending?: boolean; expires_at?: string }>("/api/session", { method: "GET" });
  if (data?.two_factor_pending === true) {
    assertShape(typeof data.expires_at === "string", "/api/session");
    return { twoFactorPending: true, expiresAt: data.expires_at };
  }
  assertShape(
    typeof data?.login === "string" &&
      typeof data?.server === "string" &&
      typeof data?.expires_at === "string" &&
      "rules_updated_at" in data &&
      (data.access_profile === undefined ||
        (typeof data.access_profile.role_id === "string" &&
          typeof data.access_profile.role_name === "string" &&
          typeof data.access_profile.trace_allowed === "boolean")),
    "/api/session",
  );
  return data;
}

export async function refreshAccessProfile(): Promise<AccessProfileRefreshResponse> {
  const data = await request<AccessProfileRefreshResponse>("/api/session/access/refresh", { method: "POST" });
  assertShape(
    data?.ok === true &&
      typeof data?.access_profile?.role_id === "string" &&
      typeof data.access_profile.role_name === "string" &&
      typeof data.access_profile.trace_allowed === "boolean",
    "/api/session/access/refresh",
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

/**
 * Static rule-hygiene report for the current pair (shadowed / redundant /
 * unreachable / overly-broad firewall rules). Read-only; ``refresh`` re-pulls
 * the snapshot from NGFW first, like the export. Gated on the backend — a 404
 * surfaces as ApiError(not_found) and the caller hides the panel.
 */
export async function getRuleHygiene(refresh = false): Promise<RuleHygieneReport> {
  const query = refresh ? "?refresh=true" : "";
  return request<RuleHygieneReport>(`/api/rules/hygiene${query}`, { method: "GET" });
}

// --- Rule snapshots and diff (docs/source/snapshots.md, fork f) -------------
// Draft contract — the backend phases (1-4 of the same doc) land in parallel;
// keep this thin plumbing in sync with docs/API_CONTRACT.md once published.

/** Documented body-size limit for `POST /api/rules/snapshots/import` (fork h.3). */
export const SNAPSHOT_IMPORT_MAX_BYTES = 20 * 1024 * 1024;

/** Saved snapshots of the current pair, newest first, plus the effective limit. */
export async function listRuleSnapshots(): Promise<SnapshotsListResponse> {
  const data = await request<SnapshotsListResponse>("/api/rules/snapshots", { method: "GET" });
  assertShape(Array.isArray(data?.snapshots) && typeof data?.limit === "number", "/api/rules/snapshots");
  return data;
}

/** Captures the pair's current rules snapshot as a named/dated point in time. */
export async function createRuleSnapshot(payload: CreateSnapshotRequest = {}): Promise<CreateSnapshotResponse> {
  const data = await request<CreateSnapshotResponse>("/api/rules/snapshots", {
    method: "POST",
    body: JSON.stringify(payload),
  });
  assertShape(data?.ok === true && typeof data?.snapshot?.id === "string", "/api/rules/snapshots");
  return data;
}

/** Idempotent-on-success delete; an unknown/already-deleted id surfaces as `not_found`. */
export async function deleteRuleSnapshot(id: string): Promise<DeleteSnapshotResponse> {
  return request<DeleteSnapshotResponse>(`/api/rules/snapshots/${encodeURIComponent(id)}`, { method: "DELETE" });
}

/**
 * Stores a `stuck.rules/v2` export document (read client-side with
 * `FileReader`, decision №10 — no textarea, no separate multipart endpoint) as
 * an "imported" snapshot of the current pair. NGFW is never contacted for this
 * call (fork h.3).
 */
export async function importRuleSnapshot(payload: ImportSnapshotRequest): Promise<ImportSnapshotResponse> {
  const data = await request<ImportSnapshotResponse>("/api/rules/snapshots/import", {
    method: "POST",
    body: JSON.stringify(payload),
  });
  assertShape(data?.ok === true && typeof data?.snapshot?.id === "string", "/api/rules/snapshots/import");
  return data;
}

/**
 * Structured diff between two sides, each either a saved snapshot id or the
 * literal `"current"` (the pair's live snapshot, lazily loaded like export/
 * hygiene). `a === b` is a valid request (empty diff).
 */
export async function getRuleSnapshotDiff(a: SnapshotOrCurrentId, b: SnapshotOrCurrentId): Promise<SnapshotDiffResponse> {
  const query = `?a=${encodeURIComponent(a)}&b=${encodeURIComponent(b)}`;
  const path = `/api/rules/snapshots/diff${query}`;
  const data = await request<SnapshotDiffResponse>(path, { method: "GET" });
  assertShape(Array.isArray(data?.tables) && Array.isArray(data?.states) && !!data?.summary && !!data?.a && !!data?.b, path);
  return data;
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
