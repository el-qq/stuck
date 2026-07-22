# Ideco NGFW API map used by STUCK

Audience: agents changing `backend/app/ngfw/` or trace semantics. This is a
curated mapping, not a copy of the full vendor documentation. Relevant vendor
source files are indexed by `docs/source/toc.yaml`.

## Connection and administrator session

- Base URL: `https://<normalized-host>:<configured-port>`.
- The login form accepts a host only; STUCK appends the configured port.
- Before any NGFW request, STUCK enforces exact-host/CIDR allowlists. Hostnames
  authorized via CIDR must resolve entirely inside the configured networks.
  Loopback, link-local, multicast and unspecified destinations are rejected in
  every mode.
- `POST /web/auth/login` receives `{login, password, rest_path}` and returns
  session cookies through `Set-Cookie`.
- `GET /web/whoami` is a UI-observed, read-only post-login preflight. STUCK
  accepts only its `login`, `name`, `role_id`, `role_name` and `competence`
  fields, then stores a reduced role decision in the STUCK session.
- Every subsequent NGFW call forwards those cookies from backend memory.
- `DELETE /web/auth/login` closes only the session identified by those cookies.
- NGFW's session lifetime is independent of STUCK's configured browser session.
  A rejected NGFW cookie maps to `session_expired` without deleting the cached
  rule snapshot.

### Second-factor (2FA) challenge

A 2FA administrator receives session cookies from `POST /web/auth/login` (200)
like anyone else, but `GET /web/whoami` returns a _blocked_ profile —
`blocked_flags` bit 0 set, empty `role_id`/`role_name` — until the second factor
is completed. STUCK detects this and drives the challenge over a WebSocket:

- `wss://<host>:<port>/web/two_factor/challenge`, authenticated with the same
  provisional cookies. The `wss://` destination passes the same allowlist/CIDR
  fail-closed check as HTTP before it is opened.
- Frames (JSON text): server sends `{"type":"2fa_start","payload":{}}` then
  `{"type":"2fa_challenge","payload":{"message":"<optional hint>"}}`; the client
  replies `{"type":"2fa_challenge","payload":{"2fa_code":"<code>"}}`.
- Terminal frames: `{"type":"2fa_error","payload":{"message":"...",
"can_retry":true|false}}` on a bad code, and
  `{"type":"2fa_success","payload":{}}` on success (confirmed on live NGFW).
- After a success frame (or a clean close), STUCK re-reads `whoami`;
  `blocked_flags == 0` with a real `role_id` is the source of truth for a
  completed login. A `whoami` 401/403 on the provisional cookies (no challenge
  possible) still maps to `second_factor_required`.

## Snapshot endpoints

These calls build one cached `administrator + host` snapshot:

| Purpose                 | NGFW endpoint                                                                                                   | Notes                                                                |
| ----------------------- | --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------- |
| Users                   | `GET /user_backend/users`                                                                                       | User IDs and parent group IDs                                        |
| Objects                 | `GET /aliases/all`                                                                                              | Flattened to `id → alias`                                            |
| Preliminary filter      | `GET /firewall/rules/drop_rules/export`                                                                         | Semicolon CSV, ordered drop rules                                    |
| DNAT                    | `GET /firewall/rules/dnat`                                                                                      | Ordered                                                              |
| FORWARD                 | `GET /firewall/rules/forward`                                                                                   | Ordered                                                              |
| INPUT                   | `GET /firewall/rules/input`                                                                                     | Ordered                                                              |
| SNAT                    | `GET /firewall/rules/snat`                                                                                      | Ordered                                                              |
| Firewall settings/state | `GET /firewall/settings`, `GET /firewall/state`                                                                 | Includes automatic SNAT and module state                             |
| NGFW interface IPs      | `GET /l2manager/connection_state`                                                                               | `l3[]` selects INPUT vs FORWARD                                      |
| Rate limiting           | `GET /api/shaper/state`, `GET /api/shaper/rules/before`, `GET /api/shaper/rules`, `GET /api/shaper/rules/after` | UI-observed read-only API; vendor source subset does not document it |
| Content filter          | `GET /content-filter/state`, `GET /content-filter/rules`, `GET /content-filter/categories`                      | Rules remain ordered                                                 |
| Antivirus               | `GET /av_backend/state`, `GET /av_backend/profiles/default`, `GET /av_backend/profiles`                         | STUCK caches whether the selected default profile is enabled         |
| IPS                     | `GET /ips/state`, `GET /ips/bypass`                                                                             | Bypass plus firewall rule flags                                      |

Snapshot responses are parsed by tolerant Pydantic models: extra fields are
accepted, but a missing or invalid required field becomes `api_changed`.

## Dynamic endpoints

These are read for each relevant trace and are not cached:

| Purpose                   | NGFW endpoint                            | Use                                                      |
| ------------------------- | ---------------------------------------- | -------------------------------------------------------- |
| URL categories            | `GET /content-filter/categorize?url=...` | Category IDs and normalized URL                          |
| Active user addresses     | `GET /monitor_backend/auth_sessions`     | Connected, unblocked sessions scoped by `user_object_id` |
| Configured user addresses | `GET /auth/rules`                        | Enabled IP bindings scoped by `user_object_id`           |

An address present in both user endpoints is returned once with `active=true`
and `assigned=true`. `always_logged` changes the authorization module label but
is not required for an enabled binding to be considered assigned.

## Administrator access preflight

The local administrator-session documentation records the role and competence
shape used by the NGFW UI. After password login, STUCK reads `GET /web/whoami`
with the provisional cookies before issuing its own session. This endpoint is
not present in the supplied REST reference, so it remains explicitly
UI-observed and is guarded by strict mocks. Missing, redirecting or malformed
responses are `api_changed`, never a fallback to another endpoint.

STUCK grants snapshot/trace access only to `predefined_admin_write` and
`predefined_admin_readonly`. Other known roles receive the typed
`insufficient_ngfw_permissions` diagnostic without loading any rules. The
browser receives only role id/name and the boolean decision; it never sees a
cookie, raw payload, endpoint path or competence values.

## Trace pipeline

| Stage               | Read-only evidence                 | Definite result                        | Uncertainty                                                         |
| ------------------- | ---------------------------------- | -------------------------------------- | ------------------------------------------------------------------- |
| Preliminary filter  | ordered CSV export                 | matching row blocks                    | missing source IP or packet-only conditions                         |
| Rate limit          | ordered shaper tables              | matching rule limits                   | unsupported rule condition                                          |
| DNS                 | local resolver                     | resolved target IP                     | NGFW DNS policy has no per-user dry-run                             |
| DNAT                | ordered DNAT rules                 | transform or accept                    | source/interface/schedule/transform unavailable                     |
| Content filter      | dynamic categories + ordered rules | allow, deny, redirect                  | content type or schedule unavailable                                |
| Antivirus           | module + selected default profile  | disabled/active                        | real response body is unavailable                                   |
| Firewall            | INPUT or FORWARD ordered rules     | accept, drop, reject                   | source port, interface, HIP, schedule or default policy unavailable |
| Application control | matched firewall DPI flags         | not applied                            | payload/application signature unavailable                           |
| IPS                 | module, firewall IPS flags, bypass | disabled or bypass                     | signature result unavailable                                        |
| SNAT                | ordered SNAT rules/settings        | transform, accept or automatic active  | source/interface/schedule unavailable                               |
| Destination         | accumulated stages                 | reached only with no block/uncertainty | inherits earlier uncertainty                                        |

## Matching rules

- Source identities include `user.id.*`, the selected parent `group.id.*` and
  `any`.
- Source IP objects are checked against the selected active/assigned IP.
- Destination aliases can represent IPs, ranges, networks, lists or domains.
- Port aliases can represent a single port, range or list.
- Multiple source/destination blocks are AND-combined; values within one block
  are OR-combined, with negation applied after matching.
- Ordered tables return the first definite match. If an earlier rule could
  match only after obtaining unavailable context, return `unknown` immediately.
- An effective destination matching an NGFW interface address selects INPUT;
  all other routed traffic selects FORWARD.
- DNAT changes the address and port used by later stages. SNAT is not applicable
  to INPUT traffic.

## Deliberately unused native checks

NGFW exposes `checks_*`-style firewall verification helpers, but their workflow
creates temporary configuration objects. The STUCK application must not call
them. Local evaluation is less exact but preserves the read-only guarantee.

## Browser links to matched rules

For supported rule-bearing trace stages, STUCK can open the corresponding NGFW
web administration section in a new browser tab. The documented UI hierarchy
maps firewall, content-filter and IPS matches to their respective traffic-rule
sections. The vendor material does not document a stable per-rule browser URL,
so STUCK intentionally opens the section instead of fabricating a rule-row
deep-link. This is a browser navigation only; it does not forward STUCK's
server-side NGFW cookies or make an NGFW API request.

## Error mapping

- transport error or timeout → `server_unreachable`;
- rejected login → `invalid_credentials`;
- rejected established cookie → `session_expired`;
- detected second-factor challenge → `second_factor_required`;
- known insufficient administrator role → `insufficient_ngfw_permissions`;
- required response shape mismatch → `api_changed`;
- other NGFW failure → `ngfw_error`.

Do not expose vendor response bodies if they may contain request data or
credentials. Logs contain endpoint, status and duration after secret masking.

## Vendor source routing

Start with `docs/source/toc.yaml`. Open only the named file for the endpoint
being changed when the optional local vendor corpus is present. If it is absent,
this curated map remains authoritative for STUCK. If implementation depends on
an undocumented UI endpoint, keep that fact explicit here and cover its
expected shape with mocks and a guarded real-NGFW read-only check when available.
