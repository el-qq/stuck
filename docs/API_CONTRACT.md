# STUCK frontend/backend API contract

This is the living contract for `/api`. It documents current behavior only;
release history belongs in root `CHANGELOG.md`.

All JSON requests use `Content-Type: application/json`. Browser requests use
`credentials: "include"`. Protected endpoints require the HttpOnly
`stuck_session` cookie.

## Error envelope

Every application error has the same shape:

```ts
interface ErrorEnvelope {
  error: {
    code: string;
    message?: string;
    details?: Record<string, unknown>;
  };
}
```

| Code                            | HTTP | Meaning                                                                           |
| ------------------------------- | ---: | --------------------------------------------------------------------------------- |
| `validation_error`              |  400 | Invalid request body or value                                                     |
| `invalid_server_address`        |  400 | Server is not a bare IPv4/hostname                                                |
| `ngfw_host_not_allowed`         |  403 | Host is outside this installation's NGFW policy                                   |
| `invalid_credentials`           |  401 | NGFW rejected administrator credentials                                           |
| `second_factor_required`        |  401 | NGFW requires a second factor STUCK cannot complete (no challenge)                |
| `second_factor_invalid`         |  401 | Rejected 2FA code; `details.can_retry` says whether another try is worth it       |
| `second_factor_expired`         |  401 | The 2FA challenge window closed (TTL) or the pending entry is unknown             |
| `insufficient_ngfw_permissions` |  403 | Current NGFW role cannot run diagnostics; details contain only `role_id`          |
| `readonly_admin_required`       |  403 | Read-only-admin mode rejects a non-read-only role; details contain only `role_id` |
| `not_authenticated`             |  401 | Missing or unknown STUCK session                                                  |
| `session_expired`               |  401 | STUCK or NGFW session can no longer be used                                       |
| `not_found`                     |  404 | Resource or disabled feature is unavailable                                       |
| `server_unreachable`            |  502 | NGFW/network timeout or connection failure                                        |
| `api_changed`                   |  502 | Required NGFW response shape changed                                              |
| `ngfw_error`                    |  502 | Other NGFW failure                                                                |
| `internal_error`                |  500 | Unexpected backend failure; details are hidden                                    |

Frontend locale dictionaries must contain every known error code and tolerate
unknown codes with a generic fallback.

## Public endpoints

### `GET /api/health`

```ts
{
  status: "ok";
  version?: string;
  ngfw_port?: number;
  ngfw_access_mode?: "allowlist" | "unrestricted";
  rules_export_enabled?: boolean;
  rule_hygiene_enabled?: boolean;
}
```

No authentication required. Optional fields keep older clients compatible.

### `GET /api/config`

```ts
{
  default_server: string;
  trace_animation_enabled?: boolean;
}
```

Compatibility endpoint for non-sensitive bootstrap configuration. The current
UI uses a non-empty `default_server` as the selected NGFW host and disables
the server field, so the administrator cannot select another host. An empty
value leaves the field editable and permits the last entered host to be used.
`trace_animation_enabled` controls the trace-stage reveal for both live and
demo results; absence preserves the enabled default for older backends.

## Authentication and session

### `POST /api/auth/login`

```ts
// request
{
  login: string;
  password: string;
  server: string;
}

// response
{
  ok: true;
  session: {
    login: string;
    server: string;
    expires_at: string;
    first_login: boolean;
    rules_updated_at: string | null;
  }
}
```

`server` is a bare IPv4 address or RFC-style hostname without scheme, port or
path. The backend appends the configured NGFW API port. When
`STUCK_DEFAULT_SERVER` is non-empty, `server` must equal that configured host;
a different API request returns `ngfw_host_not_allowed` without an NGFW
request. Login always validates the destination policy before sending
credentials. Exact host/CIDR mismatch or an unsafe destination also returns
`ngfw_host_not_allowed` without an NGFW request.
After the password request and before creating a STUCK session, the backend
performs a server-side `GET /web/whoami` using the provisional NGFW cookies. It
accepts only `login`, `name`, `role_id`, `role_name` and `competence`; the raw
payload and cookies are never returned or logged. A 401/403 at this step is a
2FA diagnostic (`second_factor_required`) and creates no STUCK session. Success
sets `stuck_session`; no NGFW cookie is returned.

When `STUCK_REQUIRE_READONLY_ADMIN` is enabled, a verified role other than the
built-in read-only administrator (`predefined_admin_readonly`) is rejected with
`readonly_admin_required` after the provisional NGFW session is closed; no
STUCK session or cookie is created. The same check applies to
`POST /api/auth/2fa` after the code is confirmed (the pending challenge and
`stuck_2fa` are dropped as well).

When the provisional `whoami` is a 200 profile blocked awaiting a second factor
(`blocked_flags` bit 0, empty `role_id`), login instead returns the 2FA branch
and sets a short-lived HttpOnly `stuck_2fa` cookie (no session, no secret):

```ts
{ ok: true; two_factor_required: true; expires_at: string; message?: string | null }
```

Login never opens the challenge WebSocket, so it always reaches this form even
right after a rejected code — the browser then calls `POST /api/auth/2fa`.

### `POST /api/auth/2fa`

```ts
// request  (the pending challenge is located by the stuck_2fa cookie)
{
  code: string;
}
```

Each attempt drives the NGFW challenge over the single WebSocket held on the
pending entry: STUCK sends `2fa_start`, waits for the challenge, submits the
code and reads the verdict. On the confirmed code it returns the same
`{ ok, session }` as login and swaps `stuck_2fa` for `stuck_session`. A rejected
code returns `second_factor_invalid` (`details.can_retry`) and keeps the pending
entry so the admin can retry. NGFW only issues one challenge at a time; if it
will not start one (a previous challenge still winding down, or the account is
locked), or the TTL expires, STUCK closes the socket, drops the provisional NGFW
session and returns `second_factor_expired`, which also clears `stuck_2fa` and
resets the browser to the login screen. The pending entry is keyed by an
opaque token, so several administrators or devices can authenticate against the
same NGFW host at once. Code and cookies never appear in a response or log.

### `POST /api/auth/2fa/cancel`

Returns `{ ok: true }`, idempotent. Drops the pending challenge, closes the
provisional NGFW session best-effort, and clears `stuck_2fa`.

### `POST /api/auth/logout`

Returns `{ ok: true }` and is idempotent. It deletes the STUCK session and
best-effort closes its NGFW session. The non-secret rules snapshot remains.

### `GET /api/session`

```ts
{
  authenticated: true;
  login: string;
  server: string;
  expires_at: string;
  rules_loaded: boolean;
  rules_updated_at: string | null;
  access_profile: {
    role_id: string;
    role_name: string;
    trace_allowed: boolean;
  };
  rules_export_enabled?: boolean;
  rule_hygiene_enabled?: boolean;
  ngfw_port?: number;
}
```

`access_profile` is the safe, reduced result of the server-side role check.
Only `predefined_admin_write` and `predefined_admin_readonly` have
`trace_allowed: true`. Other known roles remain authenticated so the browser can
show diagnostics and retry, but cannot load a rules snapshot or run a trace.

When there is no session but a live 2FA challenge (only the `stuck_2fa` cookie —
the page was reloaded between the password and the code), the endpoint returns
this instead of `not_authenticated`, so the browser restores the code form from
backend-held state:

```ts
{
  authenticated: false;
  two_factor_pending: true;
  expires_at: string;
}
```

### `POST /api/session/access/refresh`

Rechecks the active administrator's role using the server-side NGFW cookie and
returns the same reduced profile:

```ts
{
  ok: true;
  access_profile: {
    role_id: string;
    role_name: string;
    trace_allowed: boolean;
  }
}
```

When the rechecked role is insufficient, any cached snapshot for that
administrator + host is discarded. A rejected active cookie returns
`session_expired`.

## Users and source addresses

### `GET /api/users?search=<text>`

```ts
{
  users: Array<{
    id: string;
    name: string;
    login: string;
    enabled: boolean;
    domain_type: "local" | "ad" | "ald" | "freeipa" | "radius" | "device";
    group_id: string | null;
    comment?: string;
  }>;
  rules_updated_at: string;
  cached: boolean;
}
```

Search is case-insensitive over name and login. Users always come from the
current authenticated pair's snapshot.

### `GET /api/users/{user_id}/source-addresses`

```ts
{
  user_id: string;
  addresses: Array<{
    ip: string;
    subnet: string;
    external_ip: string | null;
    auth_module: string;
    node_name: string | null;
    active: boolean;
    assigned: boolean;
  }>;
}
```

The backend dynamically merges connected, unblocked authorization sessions
with enabled IP bindings from `/auth/rules`. Equal IPs are deduplicated and can
be both `active` and `assigned`. Data is scoped by `user_object_id`.

## Trace

### `POST /api/trace`

```ts
// request
{
  url: string;
  user_id?: string;
  protocol?: "tcp" | "udp";
  dst_port?: number;
  source_ip?: string;
}
```

When `user_id` is present, `source_ip` must belong to that user's current or
configured addresses. One available address is selected automatically. Several
addresses require an explicit selection. No address is valid and produces a
trace with `source_ip: null`; user/group rules still apply.

`dst_port`, when supplied, overrides an explicit port in `url`.

```ts
type StageKey =
  "hw_filter" | "pre_filter" | "rate_limit" | "dns" | "dnat" | "content_filter" | "antivirus" | "firewall" | "app_control" | "ips" | "snat" | "destination";

type StageStatus = "pass" | "block" | "limited" | "resolved" | "active" | "applied" | "conditional" | "skip" | "bypass" | "unknown" | "na";

interface TraceStage {
  key: StageKey;
  order: number;
  title_key: string;
  status: StageStatus;
  detail?: {
    rule_id?: string;
    rule_name?: string;
    action?: string;
    matched_category?: string;
    redirect_url?: string;
    reason_key?: string;
    module_enabled?: boolean;
    speed_kbps?: number;
    limit_scope?: string;
    resolved_ip?: string;
    firewall_table?: string;
    translated_destination_ip?: string;
    translated_destination_port?: number;
    translated_source_ip?: string;
  };
}
```

```ts
// response
{
  target: {
    input: string;
    normalized_url: string;
    host: string;
    resolved_ip: string | null;
    source_ip: string | null;
    dst_port: number;
    protocol: "tcp" | "udp";
    effective_destination_ip: string | null;
    effective_destination_port: number;
  };
  user: { id: string; name: string; login: string } | null;
  categories: string[];
  stages: TraceStage[];
  summary: {
    reached_destination: boolean;
    blocked_at: StageKey | null;
    verdict: "allowed" | "blocked" | "conditional" | "partial" | "unknown";
  };
  rules_updated_at: string;
}
```

`stages` always contains every key in this exact order:

```text
hw_filter, pre_filter, rate_limit, dns, dnat, content_filter,
antivirus, firewall, app_control, ips, snat, destination
```

Status intent:

- `block` is a definite stopping decision; later stages are `na`.
- `unknown` means required read-only context is unavailable.
- `conditional`, `active` and `resolved` are informational uncertainty, not a
  confirmed allow.
- `limited`, `applied` and `bypass` are definite non-blocking transformations.
- `reason_key` is an open localized vocabulary; unknown keys need a fallback.

## Rules lifecycle

### `POST /api/rules/refresh`

Reloads only the current `administrator + host` snapshot through the active
NGFW session.

```ts
{
  ok: true;
  rules_updated_at: string;
  counts: Record<string, number>;
}
```

Count keys describe snapshot collections and are not a stable UI layout.

Snapshot-loading endpoints (`/api/rules/refresh`, users, trace and rules
export) require `access_profile.trace_allowed`. A known insufficient role gets
`403 insufficient_ngfw_permissions` with the safe detail
`{ role_id: string }`; no partial trace is returned. If a snapshot endpoint
itself returns 403, STUCK rechecks the server-side NGFW session with
`GET /web/whoami`: an active profile produces the same permission error,
whereas a rejected profile produces `session_expired`.

### `GET /api/rules/export`

Query parameters:

- `user_id` — optional slice applicable to one user in the current snapshot.
- `refresh=true` — refresh before export.

The feature is controlled by backend configuration. Disabled behaves as 404.
The response is a two-space-indented JSON attachment. It deliberately excludes
administrator login and all user display data (`login`, `name`, comments,
titles and directory names). User and group IDs are replaced by stable opaque
`user-N` / `group-N` values throughout the attachment, so rule links remain
usable without identifying a person.

```ts
{
  format: "stuck.rules/v2";
  exported_at: string;
  rules_updated_at: string;
  binding: { server: string };
  filtered_by_user_id: `user-${number}` | null;
  snapshot: {
    users: Array<{
      id: `user-${number}`;
      parent_id: `group-${number}` | null;
      enabled: boolean;
      domain_type: string;
    }>;
    aliases: object[];
    objects: object[];
    firewall_forward: object[];
    firewall_input: object[];
    firewall_pre_filter: object[];
    firewall_dnat: object[];
    firewall_snat: object[];
    firewall_settings: object;
    hardware: {
      settings: object | null; // { mode: "mac" | ... }; null = feature absent on this NGFW
      rules_mac: object[];
      rules_src_ip: object[];
      rules_dst_ip: object[];
      rules_src_dst_ip: object[];
    };
    firewall_state: object;
    lan_networks: string[]; // bare LAN CIDRs; interface payload is never exported
    dns_zones: object[];
    ngfw_addresses: string[];
    content_filter: { state: object; rules: object[]; categories: unknown };
    speed_limit: { state: object; rules: object[] };
    ips_state: object;
    ips_bypass: object[];
    av_profile: { enabled: boolean };
  };
}
```

The binding is derived exclusively from `stuck_session`; request parameters
cannot select another administrator or server. Exports contain no credentials,
cookies or user-identifying display data.

### `GET /api/rules/hygiene`

Static, read-only structural analysis of the current firewall snapshot. Unlike a
trace (one packet), it reports table-level problems: rules that are shadowed,
redundant, unreachable, or overly broad. Never calls NGFW to write; a pure
function of the snapshot.

Query parameters:

- `refresh=true` — refresh the snapshot before analysing (like the export).

Controlled by backend configuration (`STUCK_ENABLE_RULE_HYGIENE`); disabled
behaves as 404 and the flag is surfaced as `rule_hygiene_enabled` in
`GET /api/health` and `GET /api/session` so the UI hides the panel.

```ts
{
  binding: {
    admin: string;
    server: string;
  }
  rules_updated_at: string;
  generated_at: string;
  summary: {
    total: number;
    risk: number;
    warning: number;
    info: number;
    possible: number;
  }
  findings: Array<{
    kind: "shadowed" | "redundant" | "unreachable_after_any" | "overly_broad" | "hw_inactive";
    severity: "risk" | "warning" | "info";
    // "certain" = coverage is provable; "possible" = plausible but an opaque
    // condition (negated set, multiple blocks, source-port/interface/schedule)
    // prevented a proof. The analysis never over-claims a certain finding.
    tier: "certain" | "possible";
    table: "fw_forward" | "fw_input" | "hw_filter";
    reason_key: string;
    rule: { id: string; name: string | null; position: number };
    related: Array<{ id: string; name: string | null; position: number }>;
    extra?: { unreachable_count?: number; inactive_count?: number; list_mode?: string; active_mode?: string };
  }>;
}
```

Address / port coverage uses literal token-superset containment, so the analysis
can only under-report (e.g. it does not yet treat `10.0.0.0/8` as covering
`10.1.0.0/16`), never over-report. The binding comes only from `stuck_session`.

Hardware filtering is checked too (`table: "hw_filter"`): enabled rules in a
list whose mode is not active are reported once per list as `hw_inactive`
(warning, `extra.list_mode`/`extra.active_mode`), and duplicates inside the
active list are `redundant` (info). When the NGFW does not expose hardware
filtering, the section is skipped entirely.

An `overly_broad` finding (a universal any→any accept) is graded by context:
`risk` when it is the first enabled rule of its chain (all traffic allowed
unconditionally), `info` when enabled drop rules precede it (the deliberate
"deny exceptions, allow the rest" tail), `warning` otherwise (a broad allow
with no exception carved out). Only enabled rules take part in the analysis.

## Contract invariants

1. Protected endpoints are scoped by the server-side STUCK session.
2. Times are UTC ISO-8601 strings.
3. IDs are strings at the STUCK boundary.
4. The browser never reads an NGFW or STUCK session value.
5. Unknown backend error/reason keys must not crash the frontend.
6. Public shape changes require synchronized backend, frontend types, tests and
   this document.
7. `ngfw_access_mode=unrestricted` is an explicit lab warning. Production
   installations should expose `allowlist`.
