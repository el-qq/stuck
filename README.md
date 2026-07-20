# Secure Traffic Utility & Configuration Kit

[![PR](https://github.com/el-qq/stuck/actions/workflows/pr.yml/badge.svg)](https://github.com/el-qq/stuck/actions/workflows/pr.yml)

[Русский](README_RU.md)

## Supported interface languages

🇬🇧 English · 🇪🇸 Español · 🇷🇺 Русский · 🇰🇿 Қазақша · 🇲🇾 Bahasa Melayu · 🇫🇷 Français · 🇧🇾 Беларуская · 🇰🇬 Кыргызча · 🇦🇲 Հայերեն

STUCK is a read-only web tool for explaining how a request to a domain, IP
address or `host:port` is processed by Ideco NGFW Novum. It loads the current
NGFW configuration, evaluates the ordered traffic pipeline locally and shows
the first matching rule and the resulting verdict for every stage.

The interface supports checks without a specific user or on behalf of an NGFW
user. User checks combine active authorization sessions with configured IP
bindings. If no source IP is known, identity-based rules are still evaluated
and IP-dependent decisions remain explicitly unknown.

## Demo

[Animated demo of the STUCK cabinet](demo/demo_0.1.0.mp4)

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
- Two-factor administrator login is detected but not completed by STUCK.

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
