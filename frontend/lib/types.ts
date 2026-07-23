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
  | "readonly_admin_required"
  | "not_authenticated"
  | "session_expired"
  | "server_unreachable"
  | "api_changed"
  | "ngfw_error"
  | "not_found"
  | "internal_error"
  // ---- rule snapshots (docs/source/snapshots.md, fork f) ----
  | "snapshot_limit_reached"
  | "snapshot_import_invalid"
  | "snapshot_import_unsupported_format"
  | "snapshot_import_too_large";

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
  "readonly_admin_required",
  "not_authenticated",
  "session_expired",
  "server_unreachable",
  "api_changed",
  "ngfw_error",
  "not_found",
  "internal_error",
  "snapshot_limit_reached",
  "snapshot_import_invalid",
  "snapshot_import_unsupported_format",
  "snapshot_import_too_large",
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
  /** Whether the rule-hygiene panel is enabled on the backend.
   *  Optional — older backends omit it; treat absence as false. */
  rule_hygiene_enabled?: boolean;
  /** Whether the rule-snapshots/diff panel is enabled on the backend
   *  (`STUCK_ENABLE_RULE_SNAPSHOTS`, docs/source/snapshots.md fork f).
   *  Optional — older backends omit it; treat absence as false. */
  rule_snapshots_enabled?: boolean;
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
  "hw_filter" | "pre_filter" | "rate_limit" | "dns" | "dnat" | "content_filter" | "antivirus" | "firewall" | "app_control" | "ips" | "snat" | "destination";

/** Fixed read-only pipeline order: hardware filtering drops at the NIC before
 *  any software stage, then packet filtering and NAT. */
export const STAGE_ORDER: readonly StageKey[] = [
  "hw_filter",
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
  /** Active hardware-filtering mode (hw_filter stage only). */
  hw_mode?: "mac" | "src-ip" | "dst-ip" | "src-and-dst-ip" | null;
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
    /** Optional — older backends do not report hardware-filtering rules. */
    hardware_rules?: number;
    /** Optional — LAN interface networks / local DNS zones (newer backends). */
    lan_networks?: number;
    dns_zones?: number;
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
  /** Mirrors `SessionStatus.rule_snapshots_enabled` for the pre-login/public probe. */
  rule_snapshots_enabled?: boolean;
}

/** Non-sensitive values needed before the administrator has a session. */
export interface PublicConfig {
  default_server: string;
  /** Whether trace stages should reveal one by one. Absent on older backends;
   *  the UI preserves the historical enabled default. */
  trace_animation_enabled?: boolean;
}

// --- Rule hygiene (GET /api/rules/hygiene) ----------------------------------

export type HygieneKind = "shadowed" | "redundant" | "unreachable_after_any" | "overly_broad" | "hw_inactive";
export type HygieneSeverity = "risk" | "warning" | "info";
export type HygieneTier = "certain" | "possible";

/** A reference to one firewall rule inside a hygiene finding. */
export interface HygieneRuleRef {
  id: string;
  name: string | null;
  /** 1-based position in the chain (including disabled rules). */
  position: number;
}

export interface HygieneFinding {
  kind: HygieneKind;
  severity: HygieneSeverity;
  tier: HygieneTier;
  /** Section the rule lives in: a firewall chain or hardware filtering. */
  table: "fw_forward" | "fw_input" | "hw_filter";
  reason_key: string;
  rule: HygieneRuleRef;
  /** Other rules involved (e.g. the shadowing rule, or the rules rendered dead). */
  related: HygieneRuleRef[];
  extra?: { unreachable_count?: number; inactive_count?: number; list_mode?: string; active_mode?: string };
}

export interface HygieneSummary {
  total: number;
  risk: number;
  warning: number;
  info: number;
  possible: number;
}

export interface RuleHygieneReport {
  binding: { admin: string; server: string };
  rules_updated_at: string;
  generated_at: string;
  summary: HygieneSummary;
  findings: HygieneFinding[];
}

// --- Rule snapshots and diff (docs/source/snapshots.md, fork f) -------------
//
// Analyst draft, not yet an implemented backend contract — kept in sync with
// `docs/API_CONTRACT.md` once the backend phases land. Owner decisions В1–В11
// are final (see the doc); this mirrors the API sketch of §3.f exactly.

/** "auto" is deliberately excluded — decision В3: only manual/imported snapshots exist. */
export type SnapshotSource = "manual" | "imported";

/** One row of `GET /api/rules/snapshots` / the result of create or import. */
export interface SnapshotDescriptor {
  /** Opaque, unique within the pair. */
  id: string;
  /** UTC ISO-8601. */
  created_at: string;
  /** When the underlying rules snapshot was actually read from NGFW. */
  rules_updated_at: string;
  comment: string | null;
  source: SnapshotSource;
  /** `RulesSnapshot.counts()` — same shape used by the rules-loading popup. */
  counts: Record<string, number>;
  // ---- only present for source === "imported" ----
  /** `exported_at` from the imported `stuck.rules/v2` document. */
  exported_at?: string;
  /** `binding.server` recorded in the imported document. */
  server?: string;
  /** True when the imported document's server differs from the current pair's. */
  foreign_server?: boolean;
  /** Safe basename of the selected import file; present only for newer
   * imported snapshots and never a client filesystem path. */
  file_name?: string;
}

export interface SnapshotsListResponse {
  binding: { admin: string; server: string };
  /** Effective per-binding limit (`STUCK_SNAPSHOT_LIMIT_PER_BINDING`). */
  limit: number;
  /** Sorted by `created_at` descending. */
  snapshots: SnapshotDescriptor[];
}

export interface CreateSnapshotRequest {
  /** Trimmed, <= 200 chars server-side. */
  comment?: string;
  /** Re-pull the rules snapshot from NGFW before capturing it (like export/hygiene `?refresh=true`). */
  refresh?: boolean;
}

export interface CreateSnapshotResponse {
  ok: true;
  snapshot: SnapshotDescriptor;
}

export interface ImportSnapshotRequest {
  comment?: string;
  /** Browser-provided basename for identifying an imported comparison side.
   * The API validates and stores no path information. */
  file_name?: string;
  /** The parsed JSON document produced by `GET /api/rules/export` (`stuck.rules/v2`). */
  export: unknown;
}

export interface ImportSnapshotResponse {
  ok: true;
  snapshot: SnapshotDescriptor;
}

export interface DeleteSnapshotResponse {
  ok: true;
}

/** Pseudo-id selecting the pair's live snapshot instead of a saved one (fork d, В2). */
export const CURRENT_SNAPSHOT_ID = "current" as const;
export type SnapshotOrCurrentId = string | typeof CURRENT_SNAPSHOT_ID;

/** Ordered rule tables (level 1) plus the object-level tables diffed (level 3, В5). */
export type DiffTable =
  | "fw_pre_filter"
  | "fw_forward"
  | "fw_input"
  | "fw_dnat"
  | "fw_snat"
  | "hw_mac"
  | "hw_src_ip"
  | "hw_dst_ip"
  | "hw_src_dst_ip"
  | "cf_rules"
  | "shaper_rules"
  | "ips_bypass"
  | "aliases"
  | "users"
  /** Trace-relevant network context. These collections have no rule order. */
  | "dns_zones"
  | "lan_networks"
  | "ngfw_addresses";

export type DiffKind = "added" | "removed" | "changed" | "moved";

export interface DiffChangedField {
  field: string;
  from: unknown;
  to: unknown;
}

export interface DiffEntry {
  kind: DiffKind;
  id: string;
  /** Display name for the UI only — never used for export/identity (fork c). */
  name: string | null;
  /** 1-based; null for `added`. */
  position_a: number | null;
  /** 1-based; null for `removed`. */
  position_b: number | null;
  /** Only present for `kind === "changed"`. */
  changed_fields?: DiffChangedField[];
}

export interface DiffTableGroup {
  table: DiffTable;
  entries: DiffEntry[];
}

/** Module/setting toggles (level 2) — keys are an open vocabulary (like `reason_key`);
 *  unknown keys must render tolerantly instead of being dropped. */
export interface DiffStateChange {
  key: string;
  from: unknown;
  to: unknown;
}

export interface DiffSummary {
  added: number;
  removed: number;
  changed: number;
  moved: number;
  states_changed: number;
  tables_changed: number;
}

export type ComparisonMode = "full" | "anonymized";

/** One side ("a" or "b") of a diff response. */
export interface DiffSide {
  id: SnapshotOrCurrentId;
  created_at: string;
  rules_updated_at: string;
  comment: string | null;
  source: SnapshotSource | "current";
  foreign_server?: boolean;
  /** Safe basename for an imported file, if supplied by the backend. */
  file_name?: string;
}

export interface SnapshotDiffResponse {
  binding: { admin: string; server: string };
  a: DiffSide;
  b: DiffSide;
  generated_at: string;
  /** "anonymized" when either side is an imported snapshot — both sides are then
   *  normalized to the anonymized form and display fields/users are limited (fork h). */
  comparison_mode: ComparisonMode;
  summary: DiffSummary;
  /** Only tables with at least one entry — an empty array means "no changes". */
  tables: DiffTableGroup[];
  states: DiffStateChange[];
}
