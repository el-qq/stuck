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

| Purpose                 | NGFW endpoint                                                                                                                                                    | Notes                                                                                                                                                                                                                   |
| ----------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Users                   | `GET /user_backend/users`                                                                                                                                        | User IDs and parent group IDs                                                                                                                                                                                           |
| Objects                 | `GET /aliases/all`                                                                                                                                               | Flattened to `id → alias`                                                                                                                                                                                               |
| Hardware filtering      | `GET /firewall/hw_settings`, `GET /firewall/hw_rules_mac`, `GET /firewall/hw_rules_src_ip`, `GET /firewall/hw_rules_dst_ip`, `GET /firewall/hw_rules_src_dst_ip` | OPTIONAL (absent before v22): any 404 → stage reports not-supported. One active mode; exact addresses validated strictly (unknown mode/bad IP → api_changed); matching enabled rule drops at the NIC                    |
| Preliminary filter      | `GET /firewall/rules/drop_rules/export`                                                                                                                          | Semicolon CSV, ordered drop rules                                                                                                                                                                                       |
| DNAT                    | `GET /firewall/rules/dnat`                                                                                                                                       | Ordered                                                                                                                                                                                                                 |
| FORWARD                 | `GET /firewall/rules/forward`                                                                                                                                    | Ordered                                                                                                                                                                                                                 |
| INPUT                   | `GET /firewall/rules/input`                                                                                                                                      | Ordered                                                                                                                                                                                                                 |
| SNAT                    | `GET /firewall/rules/snat`                                                                                                                                       | Ordered                                                                                                                                                                                                                 |
| Firewall settings/state | `GET /firewall/settings`, `GET /firewall/state`                                                                                                                  | Includes automatic SNAT and module state                                                                                                                                                                                |
| NGFW interface IPs      | `GET /l2manager/connection_state`                                                                                                                                | `l3[]` selects INPUT vs FORWARD                                                                                                                                                                                         |
| LAN context             | `GET /l2manager/connection_settings`                                                                                                                             | Only enabled `role=lan` CIDRs are retained. The vendor corpus shows an object while deployed versions may return a list; both are strictly parsed. Raw `config` is discarded because it can contain tunnel credentials. |
| Local DNS zones         | `GET /dns/zones/forward`, `GET /dns/zones/master`                                                                                                                | Enabled local zones are retained by name only. Their answer has no documented read-only lookup endpoint.                                                                                                                |
| Rate limiting           | `GET /api/shaper/state`, `GET /api/shaper/rules/before`, `GET /api/shaper/rules`, `GET /api/shaper/rules/after`                                                  | UI-observed read-only API; vendor source subset does not document it                                                                                                                                                    |
| Content filter          | `GET /content-filter/state`, `GET /content-filter/rules`, `GET /content-filter/categories`                                                                       | Rules remain ordered                                                                                                                                                                                                    |
| Antivirus               | `GET /av_backend/state`, `GET /av_backend/profiles/default`, `GET /av_backend/profiles`                                                                          | STUCK caches whether the selected default profile is enabled                                                                                                                                                            |
| IPS                     | `GET /ips/state`, `GET /ips/bypass`                                                                                                                              | Bypass plus firewall rule flags                                                                                                                                                                                         |

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

| Stage               | Read-only evidence                 | Definite result                                                   | Uncertainty                                                                                            |
| ------------------- | ---------------------------------- | ----------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| Hardware filtering  | active mode's rule list            | matching enabled rule drops at the NIC                            | missing source IP, unresolved destination, MAC mode (no MAC context)                                   |
| Preliminary filter  | ordered CSV export                 | matching row blocks                                               | missing source IP or packet-only conditions                                                            |
| Rate limit          | ordered shaper tables              | matching rule limits                                              | unsupported rule condition                                                                             |
| DNS                 | local resolver + local zones       | resolved target IP outside local NGFW zones                       | NGFW DNS policy has no per-user dry-run; local-zone answer is unavailable                              |
| DNAT                | ordered DNAT rules                 | transform or accept                                               | source/interface/schedule/transform unavailable                                                        |
| Content filter      | dynamic categories + ordered rules | allow, deny, redirect                                             | content type or schedule unavailable                                                                   |
| Antivirus           | module + selected default profile  | disabled/active                                                   | real response body is unavailable                                                                      |
| Firewall            | INPUT or FORWARD ordered rules     | accept, drop, reject; no FORWARD match → documented default ALLOW | source/destination IP, port, interface, HIP or schedule unavailable; INPUT default policy undocumented |
| Application control | matched firewall DPI flags         | not applied                                                       | payload/application signature unavailable                                                              |
| IPS                 | module, firewall IPS flags, bypass | disabled or bypass                                                | signature result unavailable                                                                           |
| SNAT                | ordered SNAT rules/settings        | transform, accept or automatic active                             | source/interface/schedule unavailable                                                                  |
| Destination         | accumulated stages                 | reached only with no block/uncertainty                            | inherits earlier uncertainty                                                                           |

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
- rejected established cookie (401, or failed profile recheck after a 403) →
  `session_expired`;
- 403 from a diagnostic endpoint with a still-valid `whoami` profile →
  `insufficient_ngfw_permissions` (safe `role_id` only);
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

## Default firewall policy (vendor-documented)

`docs/source/docs-ru-ngfw-firewall-tables.md` (snapshot of
https://docs.ideco.ru/v22/ru/ngfw/settings/access-rules/firewall-tables):

> «По умолчанию используется политика РАЗРЕШИТЬ. Если не созданы запрещающие
> правила, все порты и протоколы для пользователей разрешены.»

and, for the inbound direction:

> «Для доступа из внешней сети в локальную необходимо создать и включить
> разрешающее правило FORWARD. Иначе весь трафик … по умолчанию будет
> заблокирован системным правилом в цепочке FORWARD.»

The documented allow subject is a USER, so STUCK applies `fw_default_allow`
when the FORWARD table produced no match AND the subject is provably
user-side: a selected NGFW user, or a source IP inside a LAN interface
network (`/l2manager/connection_settings`, `role=lan`). Everything else stays `unknown` as a MODEL limitation (the vendor page
states the general allow policy for all four tables, but the model cannot use
it safely):

- FORWARD without a selected user — the direction is unprovable, and inbound
  WAN→LAN is blocked by a system tail rule, so a blanket allow could be a
  false pass;
- INPUT — the NGFW's own services are additionally guarded by system rules
  (e.g. the remote-helper SSH rules) that the read-only API does not expose.

The saved snapshots (`docs-ru-ngfw-firewall-overview.md`,
`docs-ru-ngfw-traffic-path.md`, `docs-ru-ngfw-processing-order.md`,
`docs-ru-ngfw-firewall-tables.md`) confirm the engine's stage order for the
transparent-proxy FORWARD scenario — the primary web-traffic path STUCK
models, including hardware filtering running first. Known divergences the
model does NOT reproduce: INPUT rules run BEFORE DNS/proxy when DNS intercept
is on, and the direct-proxy flow passes INPUT, then the proxy, then FORWARD —
the engine picks a single table and always places the firewall stage after
content filter/antivirus.

Local forward and master DNS zones are read from their documented endpoints.
When a target matches one, STUCK reports the matching zone but keeps DNS and
the destination IP `unknown`. It does not query the server's system resolver:
that resolver may not use the NGFW zone, its answer cannot be substituted for
the NGFW answer, and the lookup could disclose a private zone name upstream.

## Conservative handling of incomplete rule data

STUCK does not have a packet dry-run API and must therefore distinguish an
actual non-match from an input it cannot interpret. The following rules are
intentional safeguards, not attempts to reconstruct missing NGFW state:

- **Local DNS zones are checked before local resolution.** A matching forward
  or master zone produces `dns_zone_unresolved`, `resolved_ip: null`, and no
  system-DNS query. Every later stage that needs that destination address
  (hardware filtering, NAT, firewall, IPS) must preserve the uncertainty
  rather than evaluate the system resolver's potentially different answer.
- **Rule objects and port objects are tri-state.** A raw IP/CIDR/port that can
  be parsed may be a definite match or non-match. An absent alias/object or an
  unreadable port object makes the first otherwise applicable ordered rule
  `unknown`; STUCK must never skip it and claim a verdict from a later rule or
  the default policy. Country/continent `list_of_iplists` objects are also
  `unknown`: `/aliases/all` contains their list IDs, but no GeoIP mapping with
  which STUCK could evaluate an address. The trace uses `fw_object_unknown` or
  `fw_port_unknown` to make this distinction visible.
- **Firewall actions are a closed interpretation set.** `accept` is a pass;
  the known denying actions `drop`, `reject`, and `deny` are blocks. Any other
  action is `fw_action_unknown`, not a block or pass. This prevents a future
  NGFW action from being silently misclassified.
- **LAN proof is reduced and validated at the boundary.**
  `/l2manager/connection_settings` is parsed into only enabled `role=lan`
  CIDRs. `enabled` must be a real boolean and every `l3` value a CIDR; an
  unexpected value is `api_changed`, not evidence for `fw_default_allow`.
  The raw `config` object is neither cached nor logged because it can contain
  tunnel credentials.
- **A diagnostic-endpoint 403 is disambiguated once per NGFW client.**
  STUCK performs one safe `whoami` recheck: a rejected profile means
  `session_expired`; an active profile means
  `insufficient_ngfw_permissions`. Concurrent snapshot requests share that
  recheck, so a denied role does not trigger one `whoami` request per endpoint.
