# Changelog

All notable user-visible changes are recorded here. The project follows
[Semantic Versioning](https://semver.org/) and the structure of
[Keep a Changelog](https://keepachangelog.com/).

## Next
- Rule snapshots with diff over time. Administrators can save named
  point-in-time snapshots of the rules of their NGFW pair, import a previously
  exported rules JSON as a snapshot, and compare any two states (including the
  current one) in a dedicated panel: added, removed, changed and moved rules
  plus module state changes. Comparisons involving an imported (anonymized)
  export run in an explicit anonymized mode. Snapshots live in memory until
  backend restart; the panel can be disabled with
  `STUCK_ENABLE_RULE_SNAPSHOTS`.

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
