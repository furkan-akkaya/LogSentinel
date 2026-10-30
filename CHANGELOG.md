# Changelog

## 1.2.0b1 · 2026-10-30

Local-use beta, published as **LogEssential (formerly LogSentinel)**.

- Include the previously uncommitted v1.2 Detection Lab, Case Notes and dataset context.
- Use one module version for health and OpenAPI; match installed package metadata.
- Preserve package name, repository, database paths, event identities and existing installs.
- Add real browser checks for isolated 299/300-second replay, evidence navigation, note persistence and JSON export.
- Regenerate offline guides from current source and regenerate the measured standalone learning example.
- Include docs, tests, tools and synthetic samples in the source archive.
- Pin and audit the complete runtime dependency set; add draft-release packaging and clean-install verification.
- Verify Docker restart/recreation persistence and an actual upgrade from the previous v1.1.0 image.

Limits: local single user; no authentication/authorization; plaintext records and notes;
no live collection or raw EVTX; mutable Case Notes; no production accuracy claim.

## 1.1.0 · historical source

Initial committed application, five detection rules, local guides, synthetic samples and Docker support.
