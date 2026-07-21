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

export interface LoginResponse {
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
  /** Whether the rules-export feature is enabled on the backend.
   *  Optional — older backends omit it; treat absence as false. */
  rules_export_enabled?: boolean;
  /** HTTPS port of the authenticated NGFW, used only for safe admin links.
   *  Optional for compatibility with older backends. */
  ngfw_port?: number;
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
