# Public beta validation · 30 October 2026

This record supersedes current-release instructions in the historical v1.1/v1.2 validation notes.
Historical results remain dated evidence, not proof for the final beta commit.

| Check | Executed result |
|---|---|
| Python 3.13 on macOS | 139 tests passed, including installed/module/health/OpenAPI version agreement |
| Real engine examples | 85 events, 5 alerts, 27 evidence records; repeat import inserts 0 |
| Detection rules | Existing tests cover five rules, inclusive time boundaries and identity separation |
| Detection Lab | Production-engine replay, 299/300-second boundary, all scenario prefixes and workspace isolation |
| Browser | Chromium: current lab, saved/reopened notes, raw record return, JSON export, original workflows, mobile, stored-XSS check and outage/retry |
| Browser requests/errors | No unexpected external requests or JavaScript errors during checked flows |
| Docker Compose | Build, loopback bind, non-root, isolated lab, events/status/notes retained after restart and recreation |
| Actual old-image upgrade | v1.1.0 image → 1.2.0b1 image on the same isolated named volume; 85 events, settings, status and dedup preserved; new note survived restart |
| Runtime audit | Complete pinned runtime set checked against current pip-audit advisories; no known vulnerabilities reported |

The earlier package module still reported 1.1.0 while health reported 1.2.0.
The beta fixes that discrepancy using one `__version__` source for API metadata.
A stale guide assertion in the Docker smoke test was updated with the visible product name.
Guide manifest checks intentionally fail until generated files match current sources.

The Windows parser tests use supported XML/JSON fixtures; no Windows host execution is claimed.
Docker tests use disposable projects, databases and volumes and remove only those resources.
No real user records were imported for these checks.
No full accessibility audit, penetration test, enterprise throughput test or production precision/recall measurement is claimed.

Clean release-asset installation, final-commit CI and draft checks must pass before publication.
Their exact commit IDs, run URLs and asset digests belong in the publication report and release metadata.
