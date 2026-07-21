# STUCK architecture

Audience: developers and LLM agents changing application behavior. This file
describes current boundaries and invariants. HTTP shapes are defined in
`API_CONTRACT.md`; external endpoint details are in `NGFW_API_NOTES.md`.

## System boundary

```text
Browser (React/Vite) ── /api + stuck_session ──> FastAPI backend
                                                   │
                                                   │ HTTPS + NGFW cookies
                                                   ▼
                                            Ideco NGFW Novum
```

The browser never connects to NGFW directly. FastAPI is the trusted proxy that
authenticates the administrator, holds NGFW cookies, loads configuration and
evaluates traces locally.

## Components

### Frontend

- `frontend/components/` contains login, demo, trace and settings UI.
- `frontend/lib/api.ts` is the only backend transport. Requests are same-origin,
  include credentials and use the typed envelope from `API_CONTRACT.md`.
- A matched rule may link to its NGFW administration section. The URL is built
  from the authenticated server and configured NGFW port, opens in a new tab
  with `noopener noreferrer`, and contains no STUCK or NGFW session value.
- A single trace can be downloaded as a browser-generated JSON attachment or
  printed for a ticket. Both use only an allowlisted copy of the already
  received `TraceResponse`; neither action sends another request or exports
  STUCK/NGFW session state.
- `frontend/lib/types.ts` mirrors public response shapes and the fixed stage
  order.
- `frontend/lib/storage.ts` stores only non-sensitive conveniences: the last
  NGFW host and the ten most recent checked addresses.
- `frontend/i18n/` contains complete, key-compatible locale dictionaries.
- IBM Plex WOFF2 files are bundled from exact npm packages at build time; the
  browser has no font-CDN dependency. The OFL text is shipped with the UI.
- Demo mode uses `frontend/lib/demoData.ts` and performs no backend requests.

### Backend

- `app/api/` validates STUCK requests and returns contract shapes.
- `app/ngfw/client.py` owns HTTPS, admin login, cookie forwarding, timeouts and
  NGFW error normalization.
- `app/ngfw/endpoints.py` is the only mapping from application concepts to
  external NGFW paths.
- `app/ngfw/schemas.py` validates required fields while allowing harmless new
  vendor fields.
- `app/domain/session_store.py` stores active STUCK sessions, NGFW cookies and
  the strict, non-secret current-admin role profile.
- `app/domain/binding_pool.py` stores isolated rule snapshots without secrets.
- `app/domain/trace_engine.py` performs deterministic, read-only rule matching.
- `app/logging_setup.py` provides structured logging and centralized masking.

### Lab-data utility

`backend/tools/ngfw_testdata/` is a separate administration program. It is the
only repository component authorized to write NGFW configuration. It must not
be imported or called by the STUCK application.

## State and isolation

Two in-memory stores have intentionally different lifetimes:

| Store         | Key                              | Contains                                                                   | Removed by                                   |
| ------------- | -------------------------------- | -------------------------------------------------------------------------- | -------------------------------------------- |
| Session store | opaque `stuck_session`           | canonical admin login, normalized host, NGFW cookies, role profile, expiry | logout, expiry, restart                      |
| Binding pool  | `(admin login, normalized host)` | rule snapshot and load time                                                | restart; snapshot replaced by manual refresh |

Consequences:

- Logging in always verifies the password against NGFW, even if a snapshot is
  already cached.
- Logout closes the current NGFW session best-effort and deletes its cookies,
  but the pair's non-secret snapshot remains reusable after the next login.
- Different administrators or hosts cannot address each other's snapshots.
- One backend process is the consistency boundary. Multiple workers require a
  shared session/snapshot store before they are safe.

## Data flows

### Login

1. The backend validates `server` as a bare IPv4 address or hostname.
2. It enforces the installation's exact-host/CIDR policy before any outbound
   request. Unsafe special-purpose destinations are always rejected.
3. It authenticates through `POST /web/auth/login` and captures NGFW cookies.
4. Before creating a STUCK session, it reads `GET /web/whoami` with those
   provisional cookies and retains only login/name/role/competence metadata.
   A provisional 401/403 is surfaced as a 2FA requirement; no STUCK session is
   created.
5. It creates an opaque STUCK session under the canonical `whoami` login and
   sets an HttpOnly cookie. Only `predefined_admin_write` and
   `predefined_admin_readonly` can load rules or trace traffic; a known
   insufficient role remains logged in for a clear diagnostic, retry and
   logout.
6. The binding pool is inspected only for an allowed role; rules are loaded
   lazily on first use.

### Snapshot load and refresh

The first users, trace or export request from an allowed role loads the current
pair's snapshot. Known insufficient roles are rejected before a binding is
created; a role refresh that becomes insufficient discards the pair's cached
snapshot.
Concurrent loads for the same pair share a lock; unrelated pairs proceed
independently. Refresh replaces only the current pair's snapshot.

The snapshot contains users, aliases, module states, ordered shaper/content/
firewall rules, preliminary filtering, NAT, interface addresses, antivirus
state and IPS bypass data. Active sessions and `/auth/rules` IP bindings are
dynamic and never cached in the snapshot.

### User trace

1. Resolve the selected user from the current pair's snapshot.
2. Read active sessions and configured IP bindings from NGFW.
3. Validate or select the source IP. No IP is allowed; several IPs require an
   explicit choice.
4. Normalize the target, resolve DNS and categorize the URL dynamically.
5. Evaluate all stages in fixed order and return the complete stage list.

## Trace semantics

```text
pre_filter → rate_limit → dns → dnat → content_filter → antivirus
→ firewall → app_control → ips → snat → destination
```

- Ordered tables stop at the first definite match.
- If an earlier rule might match but required context is unavailable, that
  stage is `unknown`; evaluation must not claim a later allow.
- A `block` stops effective processing; remaining stages are returned as `na`
  so the frontend structure is stable.
- INPUT is selected when the effective destination is an NGFW interface IP;
  otherwise FORWARD is used.
- DNAT changes the effective destination before firewall evaluation. SNAT is
  evaluated after firewall/IPS and is skipped for INPUT traffic.
- Antivirus and IPS payload decisions cannot be reproduced offline. Their
  stages expose module/profile/rule applicability without inventing a verdict.

## Security invariants

- Never serialize passwords, STUCK cookie values or NGFW cookies.
- Only the reduced `role_id`, `role_name` and boolean access decision may leave
  the server. Raw `/web/whoami` data and competence values remain server-side.
- A trace/snapshot is allowed only for the closed role set
  `predefined_admin_write`, `predefined_admin_readonly`; competence strings are
  diagnostic metadata, never an inferred permission grant.
- Never log request bodies containing credentials. Mask sensitive keys and
  cookie-like values centrally.
- Rules export derives the binding only from the authenticated server-side
  session. Request parameters may filter within that snapshot, never select a
  different binding.
- Application NGFW calls are GET/read-only except login/logout session control.
- Production startup is fail-closed unless an exact host/CIDR allowlist is
  configured. `STUCK_ALLOW_ANY_NGFW=true` is an explicit lab mode, logged at
  warning level and exposed to the UI. Loopback, link-local, multicast and
  unspecified destinations remain forbidden.
- The browser stores language, theme, accent, last host and recent targets only.
- Caddy sets HSTS, a same-origin CSP, clickjacking, MIME-sniffing, referrer,
  browser-permission and cross-origin isolation headers. API responses receive
  `Cache-Control: no-store` at the public proxy.

## Configuration and deployment

`backend/conf/stuck.conf` is the canonical configuration inventory. Environment
variables override the file; `STUCK_CONF_FILE` selects another file. Do not
duplicate defaults in documentation.

`STUCK_ENABLE_TRACE_ANIMATION` controls only the presentation of a completed
trace. When true, desktop results reveal stage-by-stage and offer a skip
control; when false, every stage and the verdict appear immediately. The
non-sensitive value is exposed through `GET /api/config`, so it also applies to
the offline demo.

`STUCK_DEFAULT_SERVER` is an optional host-only login lock. A non-empty value
is delivered in the public bootstrap configuration and fixes the server field
in the browser; the login API independently rejects any other host. An empty
value leaves the field editable. As with every `STUCK_*` value, a process
environment variable overrides the configuration file.

NGFW destination controls:

- `STUCK_ALLOWED_NGFW_HOSTS` — comma-separated exact IPv4/hostnames;
- `STUCK_ALLOWED_NGFW_CIDRS` — comma-separated IPv4/IPv6 networks;
- `STUCK_ALLOW_ANY_NGFW` — explicit unrestricted lab mode.

For a hostname authorized only through CIDR, every resolved address must belong
to a configured network. Exact hostnames are trusted as operator-controlled DNS
names. Policy rejection happens before administrator credentials are sent.

Development uses FastAPI and the Vite proxy on separate localhost ports.
`docker-compose.yml` builds the backend and static frontend; Caddy publishes one
HTTPS origin and routes `/api/*` to FastAPI. Secure cookies are enabled in that
deployment.

Python dependency locks are generated with the same release line used by the
backend base image. All container bases use a human-readable exact tag together
with an immutable multi-platform digest. Updating a digest is deliberate so a
release rebuild cannot silently select different upstream bytes.

## Change rules

- Public HTTP change: update `API_CONTRACT.md` and frontend types together.
- NGFW path or mapping change: update `NGFW_API_NOTES.md` and endpoint adapters.
- State/security change: update this file and add isolation tests.
- User-visible change: update root `CHANGELOG.md`.
