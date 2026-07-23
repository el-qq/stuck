# STUCK agent guide

This file is the mandatory entry point for LLM agents working in this
repository. Read it before editing code. Load only the linked document needed
for the current task.

## Mission

STUCK explains, without modifying NGFW configuration, how traffic would move
through Ideco NGFW Novum. The product is a FastAPI backend plus a React/Vite/
TypeScript frontend. An offline demo mirrors the UI without contacting NGFW.

## Non-negotiable invariants

1. The application is read-only. Do not call native `checks_*` or any other
   endpoint that creates or changes NGFW configuration.
2. The only write-capable code is the explicit lab utility under
   `backend/tools/ngfw_testdata/`. Keep it isolated, prefixed, idempotent and
   opt-in.
3. Passwords, NGFW cookies and the `stuck_session` value must never appear in
   API responses, browser storage, exports or logs.
4. NGFW cookies live only in an active backend session. The rules pool contains
   no secrets and is keyed by `(administrator login, normalized NGFW host)`.
5. A logout destroys the STUCK session and its NGFW cookie but leaves the
   pair's rule snapshot cached. Restart clears all in-memory state.
6. The trace pipeline order is fixed:
   `hw_filter → pre_filter → rate_limit → dns → dnat → content_filter →`
   `antivirus → firewall → app_control → ips → snat → destination`.
7. Ordered rule tables use the first possible match. Missing source IP,
   interface, schedule, source port, payload or other required context must
   produce `unknown`; never skip an earlier possible rule to claim a later
   allow.
8. A user source IP must belong to the union of active authorization sessions
   and enabled `/auth/rules` bindings. With no IP, identity/group checks still
   run. Multiple available IPs require an explicit choice.
9. Frontend/backend response shapes and localized error/reason keys stay in
   sync. Update the API contract when a public shape or semantic changes.
10. NGFW destinations are fail-closed. Production uses exact-host/CIDR
    allowlists; unrestricted mode is an explicit localhost/lab exception and
    must remain visible in health, UI and logs.
11. Keep exact dependency versions in lock files, not prose. Do not put test
    totals, temporary plans or completed phase reports in documentation.
12. The production UI is self-contained: fonts and scripts are same-origin,
    Caddy's CSP/security headers must stay compatible with the built assets, and
    externally loaded browser resources require an explicit security review.
13. Python lock files and the backend container use the same Python release
    line. Container bases use exact tags plus multi-platform digests.

## Repository map

- `backend/app/api/` — STUCK HTTP endpoints.
- `backend/app/ngfw/` — NGFW client, endpoint adapters and tolerant schemas.
- `backend/app/domain/` — sessions, isolated rule snapshots and trace engine.
- `backend/tools/ngfw_testdata/` — separate write-capable lab utility.
- `frontend/components/auth/` — login, 2FA and access-diagnostic UI.
- `frontend/components/trace/` — target, subject, pipeline and trace-result UI.
- `frontend/components/rules/` — rules refresh/export and hygiene presentation.
- `frontend/components/shell/` — shared header, tabs, settings and toasts.
- `frontend/components/screens/` — top-level live and demo workspaces.
- `frontend/lib/` — API types/client, local storage and demo data.
- `frontend/i18n/` — all supported locale dictionaries.
- `docs/API_CONTRACT.md` — public frontend/backend API.
- `docs/ARCHITECTURE.md` — system boundaries and state lifecycle.
- `docs/NGFW_API_NOTES.md` — relevant external endpoints and assumptions.
- `docs/source/` — optional locally supplied vendor API corpus; it may be
  absent because installations can exclude it through `.git/info/exclude`.

## Work sequence

1. Inspect the relevant code and one authoritative document; do not infer from
   historical plans because none are kept.
2. Preserve unrelated user changes in a dirty worktree.
3. Make the smallest coherent implementation. Update tests for behavior, not
   implementation details.
4. Update `CHANGELOG.md` only for release-note-worthy user-visible changes or
   when the user explicitly requests it. Update API/architecture docs when
   their contract or invariants change.
5. Run the narrow tests first, then the full applicable checks. Run e2e tests
   only when the change affects browser-observable behavior or e2e coverage.

## Code organization and refactoring

1. Organize production code by one cohesive, independently changeable
   responsibility. Do not accumulate routing, orchestration, state management,
   transport, parsing and presentation in one "utility" or screen file.
2. Keep public boundaries thin and stable: API routers validate/depend on
   request state and delegate; domain/NGFW modules expose focused operations;
   frontend screens compose components and hooks rather than owning every
   effect and field implementation themselves.
3. For frontend work, move reusable or asynchronous state/effects into named
   hooks, and render independently testable controls in focused components.
   Keep browser storage and API access in `frontend/lib/`, never inside a
   presentation component.
4. For backend work, separate lifecycle/workflow logic from HTTP handlers and
   from NGFW transport. Preserve existing public import paths with a small
   facade when a split would otherwise break consumers or tests.
5. Treat roughly 250 lines in a production source file as a mandatory
   architecture-review trigger, not a mechanical limit. If it contains several
   responsibilities or a difficult-to-follow function, split it in the same
   change by domain. A larger cohesive adapter, schema collection or generated
   shape is acceptable only with a clear module docstring and logical sections.
6. Comment non-obvious invariants, security boundaries, ordered evaluation and
   deliberately fail-closed decisions at the code that enforces them. Names and
   small functions should explain ordinary control flow without commentary.
7. Refactoring must retain API contracts and behavior. Do not edit tests merely
   to accommodate a new internal layout; update imports only where a test is an
   intentional consumer of a moved public unit.

## Commands

```bash
npm run setup
npm start
npm test
npm run lint:editorconfig
npm run format:check
npm --prefix frontend run build
npm --prefix frontend run test:e2e
npm run deps:update
npm run deps:audit
npm run version:check
```

Backend tests mock NGFW unless a task explicitly requires a read-only real-NGFW
verification. Never place credentials in command lines, fixtures or files.

## Documentation routing

- Public STUCK endpoint or error change → `docs/API_CONTRACT.md`.
- State, security, cache or component-boundary change → `docs/ARCHITECTURE.md`.
- NGFW endpoint, response mapping or pipeline assumption →
  `docs/NGFW_API_NOTES.md`; consult a local `docs/source/` file when available.
- Lab seeding behavior → `docs/NGFW_TESTDATA_CLI.md`.
- Release-note-worthy user-visible change (or explicit user request) →
  `CHANGELOG.md`.
