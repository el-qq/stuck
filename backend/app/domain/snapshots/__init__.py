"""Named rule snapshots and the snapshot diff (docs/source/snapshots.md).

The feature's domain logic lives in this package:

- ``store``    — per-binding in-memory snapshot entries and their lifecycle;
- ``diff``     — the pure diff engine over two ``RulesSnapshot`` objects;
- ``importer`` — validation/parsing of an uploaded ``stuck.rules/v2`` export.

Shared anonymization stays in ``app.domain.anonymize`` — it serves both the
rules export and the diff's anonymized comparison mode.
"""
