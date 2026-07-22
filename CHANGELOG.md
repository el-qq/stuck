# Changelog

All notable user-visible changes are recorded here. The project follows
[Semantic Versioning](https://semver.org/) and the structure of
[Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added

- Hardware (NIC-level) filtering as the first trace stage: the source-IP,
  destination-IP and source+destination-IP modes are evaluated against the
  NGFW's active mode; the MAC mode honestly reports `unknown`.

### Changed

- Rules and trace JSON exports now remove user-identifying display data and
  rule comments. Rules export asks for confirmation before downloading.

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
