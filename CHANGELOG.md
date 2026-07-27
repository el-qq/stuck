# Changelog

All notable user-visible changes are recorded here. The project follows
[Semantic Versioning](https://semver.org/) and the structure of
[Keep a Changelog](https://keepachangelog.com/).

## [0.4.1]

### ✨ Highlights

- **Five new interface languages.** Uzbek, Brazilian Portuguese, Indonesian,
  Vietnamese and Turkish extend coverage to one key market in each of the CIS,
  Latin America, Asia-Pacific and Middle East regions. Spanish moved to a
  neutral Latin American register (es-419): "ingrese"/"revise" instead of the
  peninsular forms, and "firewall" instead of "cortafuegos"

## [0.4.0]: traffic compare and protocols

### ✨ Highlights

- **See why traffic passes for one user but not another.** The new **Traffic
  compare** section traces two subjects — each a user or a source IP, in any
  combination — side by side against the same destination on a single rules
  snapshot. The stage-by-stage diff points to the first stage where access
  clearly differs. Stages that differ only because one side lacks context are
  marked not-comparable, never presented as a proven difference. The section can
  be disabled with `STUCK_ENABLE_ACCESS_COMPARE`
- **Check any firewall protocol.** Traffic check and traffic compare now trace
  as Any (default), AH, ESP, GRE, ICMP, TCP, UDP or TCP/UDP instead of always
  assuming TCP. Matching stays honest: tracing with **Any** against a
  protocol-specific rule reports the stage as unknown rather than guessing a
  verdict that would hold for one protocol only, and port-less protocols (ICMP,
  AH, ESP, GRE) skip rules restricted to specific ports

### 🛠️ Changed

- Sections are grouped by purpose: traffic sections (Traffic check, Traffic
  compare) are visually separated from rules sections (Rule hygiene, Rule
  snapshots), with Traffic compare placed right after Traffic check
- The selected section survives a page reload instead of returning to Traffic
  check
- The offline demo now mirrors the live workspace

## [0.3.0]: rule snapshots

### ✨ Highlights

- **See exactly what changed in the rules.** Save named rule snapshots and
  compare **Before** and **After** in one view. STUCK shows added, removed,
  changed and moved rules, as well as important module-state changes.
- **Compare safely with another export.** Import a rules export as a reference
  point without contacting NGFW. The comparison stays anonymized and clearly
  marks an export from another server.
- **Show STUCK anywhere.** The interactive GitHub Pages demo works entirely
  offline, with no backend, NGFW connection, credentials or session.

## [0.2.0]

### ✨ Added

- Optional read-only-admin sign-in mode (`STUCK_REQUIRE_READONLY_ADMIN`,
  disabled by default). When enabled, only NGFW administrators with the
  read-only role may sign in; any other role is rejected after password (and
  2FA) verification and returned to the sign-in screen with an explanatory
  message.
- Hardware filtering in the traffic trace. STUCK evaluates the active NGFW
  MAC/IP filtering mode before software rules; when MAC context is unavailable,
  the result stays explicit about the uncertainty.
- Rule hygiene report. It highlights potentially shadowed, redundant,
  unreachable and overly broad firewall rules without changing the NGFW
  configuration.
- Two-factor administrator sign-in. STUCK completes the NGFW code challenge
  after password verification.
- Single-trace JSON export. A compact attachment preserves the checked
  scenario and technical user ID while excluding display user data and rule
  comments.
- Service and port presets, plus direct links to the corresponding NGFW rule
  section, for faster common checks and follow-up.

### 🛠️ Changed

- Rules export is now formatted for sharing, asks for confirmation before
  downloading the complete snapshot, and removes user display data and rule
  comments.
- Trace verdicts are more conservative and informative: STUCK takes the
  documented LAN-side default policy and local DNS zones into account, while
  unavailable objects, ports, GeoIP data and unfamiliar rule actions remain
  `unknown` rather than guessed.
- Administrator access diagnostics more clearly distinguish insufficient NGFW
  permissions from an expired session.

## [0.1.1] - 2026-07-20

### Added

- French, Belarusian, Kyrgyz and Armenian interface translations.
- `STUCK_ENABLE_TRACE_ANIMATION` configuration: when enabled, desktop trace
  stages are revealed sequentially with a skip control; when disabled, the
  complete result appears immediately, including in the offline demo.

### Changed

- Updated backend and frontend libraries and their locked dependency graphs.

## [0.1.0] - 2026-07-17

- First Release
