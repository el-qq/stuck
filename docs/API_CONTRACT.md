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

| Code                     | HTTP | Meaning                                         |
| ------------------------ | ---: | ----------------------------------------------- |
| `validation_error`       |  400 | Invalid request body or value                   |
| `invalid_server_address` |  400 | Server is not a bare IPv4/hostname              |
| `ngfw_host_not_allowed`  |  403 | Host is outside this installation's NGFW policy |
| `invalid_credentials`    |  401 | NGFW rejected administrator credentials         |
| `second_factor_required` |  401 | NGFW requires unsupported 2FA                   |
| `not_authenticated`      |  401 | Missing or unknown STUCK session                |
| `session_expired`        |  401 | STUCK or NGFW session can no longer be used     |
| `not_found`              |  404 | Resource or disabled feature is unavailable     |
| `server_unreachable`     |  502 | NGFW/network timeout or connection failure      |
| `api_changed`            |  502 | Required NGFW response shape changed            |
| `ngfw_error`             |  502 | Other NGFW failure                              |
| `internal_error`         |  500 | Unexpected backend failure; details are hidden  |

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
UI remembers the last entered host and does not depend on this value.
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
path. The backend appends the configured NGFW API port. Login always validates
the destination policy before sending credentials. Exact host/CIDR mismatch or
an unsafe destination returns `ngfw_host_not_allowed` without an NGFW request.
Success sets `stuck_session`; no NGFW cookie is returned.

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
  rules_export_enabled?: boolean;
}
```

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

```ts
type StageKey = "pre_filter" | "rate_limit" | "dns" | "dnat" | "content_filter" | "antivirus" | "firewall" | "app_control" | "ips" | "snat" | "destination";

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
pre_filter, rate_limit, dns, dnat, content_filter, antivirus,
firewall, app_control, ips, snat, destination
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

### `GET /api/rules/export`

Query parameters:

- `user_id` — optional slice applicable to one user in the current snapshot.
- `refresh=true` — refresh before export.

The feature is controlled by backend configuration. Disabled behaves as 404.
The response is downloaded JSON:

```ts
{
  binding: { admin: string; server: string };
  rules_updated_at: string;
  exported_at: string;
  filtered_by_user_id: string | null;
  snapshot: {
    users: object[];
    aliases: object[];
    objects: object[];
    firewall_forward: object[];
    firewall_input: object[];
    firewall_pre_filter: object[];
    firewall_dnat: object[];
    firewall_snat: object[];
    firewall_settings: object;
    firewall_state: object;
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
cannot select another administrator or server. Exports contain no credentials
or cookies.

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
