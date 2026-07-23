# Secure Traffic Utility & Configuration Kit

[![PR](https://github.com/el-qq/stuck/actions/workflows/pr.yml/badge.svg)](https://github.com/el-qq/stuck/actions/workflows/pr.yml)

[Русский](README_RU.md)

STUCK is a read-only web tool for explaining how a request to a domain, IP
address or `host:port` is processed by Ideco NGFW Novum. It loads the current
NGFW configuration, evaluates the ordered traffic pipeline locally and shows
the first matching rule and the resulting verdict for every stage.

The interface supports checks without a specific user or on behalf of an NGFW
user. User checks combine active authorization sessions with configured IP
bindings. If no source IP is known, identity-based rules are still evaluated
and IP-dependent decisions remain explicitly unknown.

#### Supported interface languages

🇬🇧 English · 🇪🇸 Español · 🇷🇺 Русский · 🇰🇿 Қазақша · 🇲🇾 Bahasa Melayu · 🇫🇷 Français · 🇧🇾 Беларуская · 🇰🇬 Кыргызча · 🇦🇲 Հայերեն

## Demo

[Animated demo of the STUCK cabinet](demo/demo_0.1.0.mp4)

## Key capabilities ✨

- **🔎 Traffic trace** — check a domain, IP address or `host:port`; service and
  port presets shorten common checks. Select an NGFW user and, when available,
  a source IP for user-aware evaluation.
- **🧭 Processing-path view** — follow the ordered decision path, including
  hardware filtering, DNS/NAT, firewall and inspection modules. Unavailable
  packet or policy context is shown as `unknown`, never assumed to pass.
- **🧹 Rule hygiene** — find potentially shadowed, redundant, unreachable and
  overly broad firewall rules. Findings are advisory; STUCK never changes NGFW
  configuration.
- **🔒 Safe exports** — download a single-trace JSON or a formatted rules
  snapshot. Rules exports require confirmation and remove user display data and
  rule comments; trace exports retain the technical user ID.
- **🛡️ Guided access and follow-up** — supports allowed NGFW administrator roles
  and the second-factor code challenge, and links a trace result to the
  relevant NGFW rule section.

## Key properties

- The application backend never changes NGFW configuration.
- NGFW credentials and cookies stay on the backend; the browser receives only
  an opaque HttpOnly STUCK session cookie.
- Rule snapshots are isolated by `administrator + NGFW host` and cached in
  process memory until refresh or restart.
- The UI is React, Vite and TypeScript; the API is FastAPI.
- The responsive UI includes an offline demo, localization and accessible
  reduced-motion behavior.
- A separate opt-in administration utility can seed prefixed lab data. It is
  not used by the read-only application.

## AI-first development

This repository is organized for AI-first development: LLM agents are expected
to be primary implementation and review collaborators. The authoritative entry
point is [AGENTS.md](AGENTS.md); architecture, contracts and the relevant vendor
API subset are kept concise and cross-linked under `docs/`.

Agents and humans should update code, tests, documentation and `CHANGELOG.md`
together. Documentation must describe invariants and behavior, not transient
test totals, dependency versions or completed implementation plans.

## Quick start

Requirements: Python, Node.js, npm and a POSIX shell. Docker is optional.

```bash
npm run setup
npm start
```

Open <http://localhost:3000>. The frontend proxies `/api/*` to the backend.
`Ctrl+C` stops both development services. This command explicitly enables
unrestricted NGFW lab mode and binds the backend to localhost; the login screen
shows a warning.

Production-like deployment requires an operator-defined NGFW allowlist:

```bash
STUCK_ALLOWED_NGFW_HOSTS=ngfw.company.local,192.168.10.1 \
  docker compose up --build
```

Open <https://localhost>. Caddy serves the UI and API on one HTTPS origin.
For a persistent installation, copy `.env.example` to `.env`, replace the
example NGFW values and run Compose normally.

For an isolated lab only, the restriction can be disabled explicitly:

```bash
STUCK_ALLOW_ANY_NGFW=true docker compose up --build
```

## Development commands

| Command                              | Purpose                                                             |
| ------------------------------------ | ------------------------------------------------------------------- |
| `npm run setup`                      | Install the exact locked backend and frontend dependencies          |
| `npm start`                          | Start the backend and Vite development server                       |
| `npm test`                           | Run backend and frontend unit/integration tests                     |
| `npm --prefix frontend run test:e2e` | Run browser tests                                                   |
| `npm --prefix frontend run build`    | Type-check and build the frontend                                   |
| `npm run lint:editorconfig`          | Enforce repository-wide EditorConfig rules                          |
| `npm run format`                     | Auto-format Python, frontend, configuration and documentation files |
| `npm run format:check`               | Verify formatting without modifying files                           |
| `npm run deps:update`                | Update both dependency graphs and verify the result                 |
| `npm run deps:audit`                 | Audit locked Python and npm dependencies for known vulnerabilities  |
| `npm run version:set -- <version>`   | Set the application version consistently                            |
| `npm run version:check`              | Verify version consistency                                          |

Configuration is loaded from [backend/conf/stuck.conf](backend/conf/stuck.conf);
environment variables with the same names take precedence. Complete resolved
dependency graphs live in lock files; direct frontend versions are also exact
in `package.json`, while backend `.in` files remain update inputs.

NGFW access is fail-closed outside `npm start`. Configure one or both:

```env
STUCK_ALLOWED_NGFW_HOSTS=ngfw.company.local,192.168.10.1
STUCK_ALLOWED_NGFW_CIDRS=10.20.0.0/16
```

`STUCK_ALLOW_ANY_NGFW=true` is an explicit lab escape hatch, not a production
setting. Loopback, link-local, multicast and unspecified destinations remain
forbidden in every mode.

## Configuration

Set the values in `backend/conf/stuck.conf` or provide an environment variable
with the same name; environment variables take precedence.

| Parameter                      | Default             | Purpose                                                                                                                                                               |
| ------------------------------ | ------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `STUCK_DEFAULT_SERVER`         | empty               | Optional NGFW host locked in the login form and API; an environment value overrides the configuration file.                                                           |
| `STUCK_NGFW_PORT`              | `8443`              | HTTPS port used to connect to NGFW.                                                                                                                                   |
| `STUCK_ALLOWED_NGFW_HOSTS`     | empty               | Comma-separated exact allowed NGFW hostnames or IPv4 addresses.                                                                                                       |
| `STUCK_ALLOWED_NGFW_CIDRS`     | empty               | Comma-separated allowed IPv4 or IPv6 networks.                                                                                                                        |
| `STUCK_ALLOW_ANY_NGFW`         | `false`             | Explicitly allow any safe NGFW host; laboratory use only.                                                                                                             |
| `STUCK_SESSION_TTL_HOURS`      | `10`                | STUCK browser-session lifetime in hours.                                                                                                                              |
| `STUCK_2FA_TTL_SECONDS`        | `180`               | Lifetime of a second-factor (2FA) challenge — how long the code form stays valid after the password step. Range 30–600.                                               |
| `STUCK_COOKIE_SECURE`          | `true`              | Mark the session cookie as HTTPS-only.                                                                                                                                |
| `STUCK_COOKIE_SAMESITE`        | `lax`               | SameSite policy for the session cookie.                                                                                                                               |
| `STUCK_NGFW_VERIFY_TLS`        | `false`             | Verify the NGFW TLS certificate.                                                                                                                                      |
| `STUCK_NGFW_CA_BUNDLE`         | empty               | CA-bundle path used when TLS verification is enabled.                                                                                                                 |
| `STUCK_ALLOWED_ORIGINS`        | `https://localhost` | Comma-separated CORS origins for development or split deployments.                                                                                                    |
| `STUCK_BACKEND_PORT`           | `8000`              | Port on which the backend listens.                                                                                                                                    |
| `STUCK_TRACE_DEFAULT_PORT`     | `443`               | Destination port assumed when a checked address omits one.                                                                                                            |
| `STUCK_NGFW_TIMEOUT_SECONDS`   | `15`                | Timeout for a single NGFW request, in seconds.                                                                                                                        |
| `STUCK_LOG_LEVEL`              | `INFO`              | Minimum log level: `DEBUG`, `INFO`, `WARNING` or `ERROR`.                                                                                                             |
| `STUCK_LOG_FORMAT`             | `text`              | Log output format: `text` or `json`.                                                                                                                                  |
| `STUCK_LOG_FILE`               | empty               | Log-file path; empty writes logs to standard output.                                                                                                                  |
| `STUCK_ENABLE_RULES_EXPORT`    | `true`              | Make the authenticated rules-snapshot export available.                                                                                                               |
| `STUCK_ENABLE_TRACE_ANIMATION` | `true`              | Reveal desktop trace stages one at a time and show **Skip animation**; set `false` to show the complete result immediately. Also applies to the offline demo.         |
| `STUCK_ENABLE_RULE_HYGIENE`    | `true`              | Enable the read-only rule-hygiene panel (shadowed / redundant / unreachable / overly-broad firewall rules); set `false` to answer 404 and hide it.                    |
| `STUCK_REQUIRE_READONLY_ADMIN` | `false`             | Accept sign-in only from NGFW administrators with the read-only role; any other role is rejected after authentication (including 2FA) with `readonly_admin_required`. |

To lock STUCK to one NGFW host for a local development run:

```bash
STUCK_DEFAULT_SERVER=ngfw.example.local npm start
```

For Docker Compose, set the value in `.env` or pass it with the command:

```bash
STUCK_DEFAULT_SERVER=ngfw.example.local \
  STUCK_ALLOWED_NGFW_HOSTS=ngfw.example.local \
  docker compose up --build
```

The value must be a bare hostname or IPv4 address, without a scheme, port or
path. A non-empty value fixes that server in both the login form and API.

IBM Plex is self-hosted from exact npm packages; the built UI contacts neither
Google Fonts nor another font CDN, and the OFL license is included.

Container bases use both a readable patch tag and an immutable multi-platform
digest. This is the release policy: a rebuild selects the same reviewed image
on every supported architecture, and security updates are explicit git changes.
Major/minor tags receive patches automatically but make rebuilds drift; a patch
tag is clearer but is still registry-mutable. To update an image, inspect the
new digest with `docker buildx imagetools inspect <image>:<tag>`, replace tag and
digest together, then run `docker compose build --pull`.

## CI

Every pull request (and every push to `main`) runs the GitHub Actions pipeline
[.github/workflows/pr.yml](.github/workflows/pr.yml):
`lint` → `backend` + `frontend` (in parallel) → `e2e` + `docker` + `audit`
(in parallel).

- `lint` — ruff (lint and format check), Prettier, EditorConfig and
  `version:check`.
- `backend` — pytest: the application tests plus the `tools/ngfw_testdata`
  suite.
- `frontend` — TypeScript type check and vitest.
- `e2e` — Playwright browser tests (Chromium).
- `docker` — builds both container images.
- `audit` — pip-audit and npm audit; advisory only, it never blocks a PR.

## Optional NGFW test data

The lab-data command writes prefixed users, objects and rules to an NGFW. Read
[docs/NGFW_TESTDATA_CLI.md](docs/NGFW_TESTDATA_CLI.md) before using it. The main
STUCK application remains read-only.

## Documentation

- [AGENTS.md](AGENTS.md) — mandatory repository guidance for LLM agents.
- [README_RU.md](README_RU.md) — краткое руководство на русском языке.
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — components, state and invariants.
- [docs/API_CONTRACT.md](docs/API_CONTRACT.md) — frontend/backend HTTP contract.
- [docs/NGFW_API_NOTES.md](docs/NGFW_API_NOTES.md) — external NGFW endpoints,
  pipeline semantics and known uncertainty.
- [docs/NGFW_TESTDATA_CLI.md](docs/NGFW_TESTDATA_CLI.md) — lab-data utility runbook.
- [CHANGELOG.md](CHANGELOG.md) — user-visible changes by release.

## Known limits

- Sessions and rule snapshots are process-local; a backend restart clears them.
- Antivirus, IPS payload inspection and conditions unavailable from read-only
  APIs cannot be simulated; the UI reports these results as conditional or
  unknown.
- Two-factor administrator login is completed over the NGFW challenge
  WebSocket; STUCK shows a code form after the password step.

## Disclaimer

STUCK is an independent diagnostic aid and is not an official Ideco product.
Its output is an explanation based on available read-only API data, not a
guarantee of actual traffic behavior. Validate important decisions on the
target NGFW and use the write-capable lab-data utility only on systems where
you are authorized to make changes.

The software is distributed **AS IS**, without warranties or conditions of any
kind. To the extent permitted by applicable law, the authors and contributors
are not liable for damage, service interruption, data loss, configuration
changes or other consequences arising from use or inability to use the
software. The Apache License 2.0 in [LICENSE](LICENSE) is authoritative.

## License

Distributed under the Apache License 2.0 on an **AS IS** basis. See
[LICENSE](LICENSE) and [NOTICE](NOTICE). Copyright holder: `el-qq`.
