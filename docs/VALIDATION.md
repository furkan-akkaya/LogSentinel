# Executed validation · v1.1.0

Validation date: **October 28, 2026**. This document records the follow-up session. Earlier results are distinguished from checks rerun here. No remote GitHub Actions execution is claimed.

## Baseline before changes

The original suite was executed in this session: **67 tests passed** on Python 3.13.7. A separate temporary database reproduced **85 inserted events, five alerts, and four hosts**. Evidence counts were 7, 5, 6, 5, and 4 for the five documented rules.

The earlier review's source-validation finding still matched the starting code. XML Provider attributes did not reach validation. Explicitly conflicting Channel/Provider fields could be accepted as Windows Security events.

## Updated automated results

| Environment / check | Actual result in this session |
|---|---|
| macOS 27.0.1 Apple Silicon, Python 3.13.7 | **117 tests passed** |
| macOS 27.0.1 Apple Silicon, Python 3.11.15 | **117 tests passed** |
| Linux ARM64, built Python 3.13.18 Docker image | **117 tests passed** |
| Windows source tests, focused run | **38 tests passed** |
| Chromium 156 / Playwright 1.64.1 | **Updated browser workflow passed** |
| Docker Desktop 4.94.0 / Engine 29.8.2 | **Updated Compose lifecycle passed** |
| Documented examples | **Five results and 27 evidence records matched the actual engine** |
| Ruff undefined/unused-name checks | **Passed** |
| JavaScript syntax / Compose configuration | **Passed** |

The 38 Windows tests are included in the 117-test suite; they are not additional independent tests. Test count is not a security score or detection-accuracy measure.

### Added source-validation coverage

- Correct XML Provider attributes and JSON provider representations.
- Wrong channel, provider name, or GUID; mismatched name/GUID pairs.
- Empty, null, malformed, and contradictory explicit values.
- Missing channel/provider compatibility in both XML and JSON.
- Existing normalized-ID compatibility, including XML/JSON equivalence.
- API regression: five contradictory records yield five rejections, zero inserted events, and zero alerts.
- Partial import: a valid event remains accepted next to a source rejection.

### Added explanation and documentation coverage

- Counts derive from actual evidence; applied thresholds and windows follow settings.
- Windows domain/logon type appear in the effective identity.
- Legacy alert explanations do not rewrite stored bodies.
- Removed and restored alerts return as `new`, reflecting the lack of durable case history.
- Per-account spraying and per-IP distributed attempts remain out of scope in SSH and Windows tests.
- Five scenario snapshots match the real engine and actual raw records.
- Normalized walkthrough records and the SSH case timeline match the same output.
- Offline guide inputs, local links, fragments, source views, and HTTP assets are checked.

## Real browser workflow

The script starts a real Uvicorn process and an isolated temporary database. It does not use the user's working service or database.

1. Load the demo from the empty state and verify 85 events / five alerts.
2. Navigate Dashboard, Log Explorer, and Security Alerts.
3. Filter seven SSH records by source IP and inspect raw/normalized data.
4. Open all five alert types and verify actual thresholds and windows.
5. Verify Windows domain and logon type in the alert view.
6. Expand interpretation using the keyboard and close dialogs with Escape.
7. Check all five alert dialogs at 390px width without horizontal dialog overflow.
8. Verify the sticky close control remains visible after scrolling the dialog.
9. Change investigation status and settings; confirm the displayed SSH threshold changes to six.
10. Reimport the Linux file and verify 50 duplicates.
11. Render a hostile HTML username as text without executing it.
12. Open the offline scenario and walkthrough guides; check mobile page overflow.
13. Simulate an API outage and recover with Retry.
14. Open the local API reference.

The successful workflow had no JavaScript page errors, unexpected script dialogs, or third-party requests. Native HTML dialogs, summaries, labels, headings, and a guide skip link support keyboard use. This is not a full screen-reader or WCAG certification.

Screenshots in `docs/screenshots/` were generated from the isolated synthetic workflow. They contain no user-supplied production logs.

## Real Docker lifecycle

The updated test builds the distributed application in its own Compose project and named volume on an ephemeral loopback port. It verifies v1.1 health, packaged guides, explanation fields, demo, duplicate resistance, and UID `10001`.

It restarts the container, then removes and recreates that container while retaining its test volume. Events and a resolved investigation remain present. The test removes only its own test project and volume afterward.

The Linux test suite also ran in a read-only container with temporary dependency and database storage. The user's working volume was not mounted by either test.

## Working-data precautions

A consistent SQLite backup was taken through SQLite's backup API before deployment work. It is kept in a private working directory outside release outputs. Tests and documentation examples use disposable databases.

No schema change or historical-event reparse is required. Existing valid event IDs remain compatible. Legacy alert explanations are computed on read. The update does not delete historical records or manufacture source provenance for them.

The live service was updated to v1.1.0 and checked through read-only requests. All 85 event rows, five stored alert bodies, investigation statuses, and configuration matched the pre-update snapshot exactly. Five legacy explanations and the packaged guide were available after the update. No demo import or setting change was sent to the working service.

## Reproduce

From a fresh source checkout:

```sh
python -m pip install -r requirements.txt
python -m pip install -e '.[test,browser,docs]'
python tools/build_guides.py
python -m pytest
python -m pytest tests/test_windows_source.py
python tools/verify_examples.py
python -m playwright install chromium
python tests/browser_smoke.py
python tests/docker_smoke.py
```

To refresh screenshots, run `python tests/browser_smoke.py --screenshots docs/screenshots`, then rebuild guides. Screenshots and linked sources are guide inputs; the manifest detects stale snapshots.

## Limits not resolved or verified

- Actual Windows or Intel x86-64 execution; Windows export commands remain untested here.
- Live host collection, arbitrary export formats, or binary EVTX parsing.
- Production throughput, false-positive rates, recall, or complete incident attribution.
- Screen-reader coverage and a full accessibility audit.
- Durable case history, account authentication, or encrypted log storage.
- Remote GitHub CI, public hosting, push, tags, or a GitHub release.

The source check validates supplied declarations. Missing source fields remain accepted for compatibility. Neither accepted declarations nor event hashes establish authentic source activity.
