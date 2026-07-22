/**
 * Types mirroring docs/API_CONTRACT.md. Keep in sync with the contract —
 * it is the single source of truth shared with the backend.
 */

export type ErrorCode =
  | "validation_error"
  | "invalid_server_address"
  | "ngfw_host_not_allowed"
  | "invalid_credentials"
  | "second_factor_required"
  | "second_factor_invalid"
  | "second_factor_expired"
  | "insufficient_ngfw_permissions"
  | "not_authenticated"
  | "session_expired"
  | "server_unreachable"
  | "api_changed"
  | "ngfw_error"
  | "not_found"
  | "internal_error";

/** Closed list per contract §2.1 — used to validate/fallback unknown codes from the backend. */
export const KNOWN_ERROR_CODES: readonly ErrorCode[] = [
  "validation_error",
  "invalid_server_address",
  "ngfw_host_not_allowed",
  "invalid_credentials",
  "second_factor_required",
  "second_factor_invalid",
  "second_factor_expired",
  "insufficient_ngfw_permissions",
  "not_authenticated",
  "session_expired",
  "server_unreachable",
  "api_changed",
  "ngfw_error",
  "not_found",
  "internal_error",
];

export interface ErrorEnvelope {
  error: {
    code: string;
    message?: string;
    details?: Record<string, unknown>;
  };
}

export interface LoginRequest {
  login: string;
  password: string;
  server: string;
}

export interface SessionInfo {
  login: string;
  server: string; // v2: normalized host (lowercase, no port)
  expires_at: string;
  /** v2: false when the (login+server) pair already has a rules snapshot in the pool (incl. after logout). */
  first_login: boolean;
  /** v2: when the pair's rules snapshot was last loaded; null if never. */
  rules_updated_at: string | null;
}

/** The small, non-secret access decision derived server-side from NGFW whoami. */
export interface AdminAccessProfile {
  role_id: string;
  role_name: string;
  trace_allowed: boolean;
}

/** Raw success shape of ``POST /api/auth/login`` (session was created). */
export interface LoginResponse {
  ok: true;
  session: SessionInfo;
}

/** Raw shape of ``POST /api/auth/login`` when NGFW demands a second factor.
 *  No session/secret is present; the ``stuck_2fa`` cookie is set HttpOnly. */
export interface TwoFactorRequiredResponse {
  ok: true;
  two_factor_required: true;
  /** ISO-8601 UTC instant the challenge expires (drives the UI countdown). */
  expires_at: string;
  /** Optional NGFW-provided hint shown above the code field; may be absent/empty. */
  message?: string | null;
}

/** Discriminated result of the client ``login()`` wrapper (see lib/api.ts).
 *  The UI branches on ``twoFactorRequired`` to render the code form vs. proceed. */
export type LoginOutcome = { twoFactorRequired: false; session: SessionInfo } | { twoFactorRequired: true; expiresAt: string; message?: string | null };

/** Result of ``submit2fa`` (client wrapper). Success carries the created
 *  session; a rejected-but-retryable code is surfaced via a thrown ApiError
 *  (code ``second_factor_invalid`` with ``details.can_retry``), not here. */
export interface TwoFactorSubmitResponse {
  ok: true;
  session: SessionInfo;
}

export interface SessionStatus {
  authenticated: true;
  login: string;
  server: string; // v2: host without port
  expires_at: string;
  rules_loaded: boolean;
  /** v2: when the pair's rules snapshot was last loaded; null if never. */
  rules_updated_at: string | null;
  /** Optional only for compatibility with an older backend. New backends
   * always verify this before creating the STUCK session. */
  access_profile?: AdminAccessProfile;
  /** Whether the rules-export feature is enabled on the backend.
   *  Optional — older backends omit it; treat absence as false. */
  rules_export_enabled?: boolean;
  /** HTTPS port of the authenticated NGFW, used only for safe admin links.
   *  Optional for compatibility with older backends. */
  ngfw_port?: number;
}

/** `GET /api/session` when there is no session yet but a live 2FA challenge
 *  exists (the page was reloaded between the password and the code). Lets the
 *  browser restore the code form from backend-held state. */
export interface TwoFactorPendingStatus {
  twoFactorPending: true;
  expiresAt: string;
}

/** Discriminated bootstrap result of `getSession()`. */
export type SessionBootstrap = SessionStatus | TwoFactorPendingStatus;

export interface AccessProfileRefreshResponse {
  ok: true;
  access_profile: AdminAccessProfile;
}

export type DomainType = "local" | "ad" | "ald" | "freeipa" | "radius" | "device";

export interface NgfwUser {
  id: string;
  name: string;
  login: string;
  enabled: boolean;
  domain_type: DomainType;
  group_id: string | null;
  comment?: string;
}

export interface UsersResponse {
  users: NgfwUser[];
  /** v2 (was `loaded_at`): when the pair's rules snapshot was fetched. */
  rules_updated_at: string;
  cached: boolean;
}

export type Protocol = "tcp" | "udp";

export interface TraceRequest {
  url: string;
  user_id?: string;
  protocol?: Protocol;
  dst_port?: number;
  source_ip?: string;
}

export interface UserSourceAddress {
  ip: string;
  subnet: string;
  external_ip: string | null;
  auth_module: string;
  node_name: string | null;
  active: boolean;
  assigned: boolean;
}

export interface UserSourceAddressesResponse {
  user_id: string;
  addresses: UserSourceAddress[];
}

export type StageKey =
  "pre_filter" | "rate_limit" | "dns" | "dnat" | "content_filter" | "antivirus" | "firewall" | "app_control" | "ips" | "snat" | "destination";

/** Fixed read-only pipeline order, including packet filtering and NAT. */
export const STAGE_ORDER: readonly StageKey[] = [
  "pre_filter",
  "rate_limit",
  "dns",
  "dnat",
  "content_filter",
  "antivirus",
  "firewall",
  "app_control",
  "ips",
  "snat",
  "destination",
];

export type StageStatus = "pass" | "block" | "limited" | "resolved" | "active" | "applied" | "conditional" | "skip" | "bypass" | "unknown" | "na";

export interface StageDetail {
  rule_id?: string;
  rule_name?: string;
  action?: string;
  matched_category?: string;
  redirect_url?: string;
  reason_key?: string;
  module_enabled?: boolean;
  speed_kbps?: number;
  limit_scope?: "user" | "group" | string;
  resolved_ip?: string;
  firewall_table?: "forward" | "input" | string;
  translated_destination_ip?: string;
  translated_destination_port?: number;
  translated_source_ip?: string;
}

export interface TraceStage {
  key: StageKey;
  order: number;
  title_key: string;
  status: StageStatus;
  detail?: StageDetail;
}

export type Verdict = "allowed" | "blocked" | "conditional" | "partial" | "unknown";

export interface TraceTarget {
  input: string;
  normalized_url: string;
  host: string;
  resolved_ip: string | null;
  source_ip: string | null;
  dst_port: number;
  protocol: Protocol;
  effective_destination_ip: string | null;
  effective_destination_port: number;
}

export interface TraceUser {
  id: string;
  name: string;
  login: string;
}

export interface TraceSummary {
  reached_destination: boolean;
  blocked_at: string | null;
  verdict: Verdict;
}

export interface TraceResponse {
  target: TraceTarget;
  user: TraceUser | null;
  categories: string[];
  stages: TraceStage[];
  summary: TraceSummary;
  /** v2: which rules snapshot the trace was computed on. */
  rules_updated_at: string;
}

export interface RulesRefreshResponse {
  ok: true;
  /** v2 (was `loaded_at`). */
  rules_updated_at: string;
  counts: {
    users: number;
    firewall_forward: number;
    firewall_input: number;
    firewall_pre_filter: number;
    firewall_dnat: number;
    firewall_snat: number;
    content_filter_rules: number;
    speed_limit_rules: number;
    ips_bypass: number;
    aliases: number;
  };
}

export interface HealthResponse {
  status: "ok";
  /** Application version reported by the backend. Optional for compatibility. */
  version?: string;
  /** NGFW port the backend connects to (STUCK_NGFW_PORT). Optional —
   *  older backends do not send it; its absence must NOT raise api_changed. */
  ngfw_port?: number;
  ngfw_access_mode?: "allowlist" | "unrestricted";
  rules_export_enabled?: boolean;
}

/** Non-sensitive values needed before the administrator has a session. */
export interface PublicConfig {
  default_server: string;
  /** Whether trace stages should reveal one by one. Absent on older backends;
   *  the UI preserves the historical enabled default. */
  trace_animation_enabled?: boolean;
}
