# Executed validation · v1.2.0

Validation date: **October 29, 2026**. [Earlier v1.1 validation](VALIDATION.md) is retained as a historical record. No remote CI or actual Windows execution is claimed.

## Baseline and compatibility

The initial v1.1 suite passed **117 tests** on the existing macOS Python 3.11 environment. Its demo produced 85 events and five alerts. Before regenerating the example snapshot, all old fields were compared exactly: alerts, evidence, identifiers and parameters were unchanged. Only additive dataset labels were accepted into the snapshot.

The new schema adds a separate notes table. No event reparse or identifier migration is required. Dataset labels are computed, not written into existing rows.

## Executed results

| Check | Result |
|---|---|
| macOS Python 3.11 | 138 tests passed |
| macOS Python 3.13 | 138 tests passed |
| Real Docker Compose lifecycle | Passed: build, isolated lab, restart, recreation, data/status/note persistence |
| Original example verification | Passed: 85 events, five alerts, 27 evidence records |
| JavaScript syntax | Passed for application scripts |
| Targeted desktop browser flows | Passed for isolated lab, alert replay, notes, JSON export and mobile widths |
| Standalone HTML | 280 engine-measured combinations; 299/300-second interaction verified in a browser |

The 21 new test cases are included in 138, not additional to it. Test count is not a security score. The full earlier Playwright script and remote GitHub CI were not executed in this update.

## Checks added in this update

The new [lab and notes tests](../tests/test_lab_notebooks.py) cover:

1. Every synthetic scenario and every replay prefix against the production engine.
2. Inclusive 300-second boundaries, changed thresholds and excluded public-key records.
3. Windows domain/logon-type grouping and account separation.
4. Lab isolation from events, settings, alerts, statuses and notes.
5. Input validation, ambiguous datasets, unknown scenarios and missing alerts.
6. Explicit replay refusal above 200 evidence records.
7. Note persistence after alert removal and process restart.
8. Note replacement without changing alert status or settings.
9. A 250-record alert: 200 raw snapshot records, 50 explicitly omitted records, all 250 IDs retained.
10. Existing-database startup migration without changing events or configuration.
11. Content-based demo labels independent of upload filename.
12. Local origin boundaries and literal storage of hostile-looking note text.

## Browser checks

A separate Uvicorn service on loopback port 8766 uses a disposable test database. The working service on 8765 is excluded from browser mutations.

The actual app was inspected through the desktop browser tools:

- Existing dashboard, five alert explanations and raw evidence were inspected before changes.
- New lab parameters changed the boundary result from one alert at 300 seconds to zero at 299 seconds.
- Event steps expose original raw records and actual engine results.
- An alert opened manual notes; observation, hypothesis and next step were saved and reopened through Case Notes.
- JSON snapshot download completed and contains all three notes and five raw evidence records.
- Raw event inspection returned to its original alert; that alert opened its five-record evidence replay.
- Browser error logs were empty during the checked workflows.
- The standalone HTML produced zero alerts at 299 seconds and one at 300 seconds.
- Escape closed the native detail dialog.
- At 390px width, the page width and body width were both 390px. The notes dialog's content and client widths were both 354px.
- Screenshots were taken from synthetic test data.

This is targeted browser validation. The previous Playwright browser script remains available but was not rerun through this session's browser tools. A full screen-reader or WCAG audit is not claimed.

## Reproduce

```sh
python -m pip install -e '.[test,docs]'
python tools/build_guides.py
python -m pytest
python tools/verify_examples.py
python tests/docker_smoke.py
```

The Compose test uses its own random project, loopback port and volume. It checks health version, guides, demo, isolated lab results, non-root operation and note persistence across restart and recreation. It only removes its own test resources.

## Remaining limits

Replay is evidence-only and limited to 200 records. It is not a full-dataset settings preview or a precision/recall benchmark. Notes are mutable snapshots, not an audit trail. Other imports remain unverified. The application still has no authentication, binary EVTX support, live collection, encryption at rest, or production throughput validation.
