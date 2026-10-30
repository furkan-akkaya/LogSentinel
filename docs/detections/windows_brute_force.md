# Windows repeated logon failures

[Project guide](../INDEX.md) · [How it works](../learning/HOW_IT_WORKS.md)

## Observed behavior

Windows 4625 indicates a failed logon. This rule counts repeated failures within one authentication context. The cause may be a bad credential, account state, or a logon restriction.

This is a **synthetic demo scenario**, not a real incident investigation. All timestamps below are October 26, 2026, in UTC.

![Evidence timeline](../diagrams/windows_brute_force.svg)

## Actual source records

These are the records used by the bundled demo and the real detection engine.

<!-- evidence:start -->
```json
{"System": {"EventID": 4625, "TimeCreated": {"SystemTime": "2026-10-26T10:25:00Z"}, "Computer": "dc-01", "EventRecordID": "10000", "Channel": "Security"}, "EventData": {"TargetUserName": "svc_backup", "TargetDomainName": "LAB", "IpAddress": "192.0.2.86", "LogonType": "10"}}
{"System": {"EventID": 4625, "TimeCreated": {"SystemTime": "2026-10-26T10:25:24Z"}, "Computer": "dc-01", "EventRecordID": "10001", "Channel": "Security"}, "EventData": {"TargetUserName": "svc_backup", "TargetDomainName": "LAB", "IpAddress": "192.0.2.86", "LogonType": "10"}}
{"System": {"EventID": 4625, "TimeCreated": {"SystemTime": "2026-10-26T10:25:48Z"}, "Computer": "dc-01", "EventRecordID": "10002", "Channel": "Security"}, "EventData": {"TargetUserName": "svc_backup", "TargetDomainName": "LAB", "IpAddress": "192.0.2.86", "LogonType": "10"}}
{"System": {"EventID": 4625, "TimeCreated": {"SystemTime": "2026-10-26T10:26:12Z"}, "Computer": "dc-01", "EventRecordID": "10003", "Channel": "Security"}, "EventData": {"TargetUserName": "svc_backup", "TargetDomainName": "LAB", "IpAddress": "192.0.2.86", "LogonType": "10"}}
{"System": {"EventID": 4625, "TimeCreated": {"SystemTime": "2026-10-26T10:26:36Z"}, "Computer": "dc-01", "EventRecordID": "10004", "Channel": "Security"}, "EventData": {"TargetUserName": "svc_backup", "TargetDomainName": "LAB", "IpAddress": "192.0.2.86", "LogonType": "10"}}
{"System": {"EventID": 4625, "TimeCreated": {"SystemTime": "2026-10-26T10:27:00Z"}, "Computer": "dc-01", "EventRecordID": "10005", "Channel": "Security"}, "EventData": {"TargetUserName": "svc_backup", "TargetDomainName": "LAB", "IpAddress": "192.0.2.86", "LogonType": "10"}}
```
<!-- evidence:end -->

The actual demo exports omit Provider. Channel is Security. Missing source fields are accepted for compatibility, not authenticated. Explicit contradictions are rejected. The demo also omits Status/SubStatus, so the failure cause is unknown.

## Normalized fields and correlation identity

| Identity field | Effective matching value |
|---|---|
| `host` | `dc-01` |
| `source_ip` | `192.0.2.86` |
| `user` | `svc_backup` |
| `domain` | `lab` |
| `logon_type` | `10` |

Windows identities use case-folded host, account, and domain values. Linux account and host comparisons retain case. IPs normalize to canonical addresses. Only the fields listed in this scenario's identity form its correlation group.

The first record also carries this metadata:

| Metadata field | Value |
|---|---|
| `event_id` | `4625` |
| `record_id` | `10000` |
| `channel` | `Security` |
| `domain` | `LAB` |
| `logon_type` | `10` |

See the [Microsoft 4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625) and [Microsoft 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624) for source-field interpretation.

## Threshold and event-time window

The rule requires **5 failure records within 300 seconds**. The threshold is first reached at **10:26:36 UTC**. The same bounded episode later holds 6 evidence records. Each additional record does not create a separate alert.

The lower lookback boundary is inclusive. Events exactly 300 seconds apart remain eligible under the default window. At 301 seconds they may no longer form the same qualifying set. A success must be strictly later than its counted failures; an equal timestamp cannot prove ordering.

## Timeline and measured result

| Time · UTC | Normalized event | Event ID prefix |
|---|---|---|
| 10:25:00 | `windows_failure` | `6bb005c60c22` |
| 10:25:24 | `windows_failure` | `9dda10f2d678` |
| 10:25:48 | `windows_failure` | `39466f9b3ef9` |
| 10:26:12 | `windows_failure` | `583a66928f3c` |
| 10:26:36 | `windows_failure` | `5cb8ab31075f` |
| 10:27:00 | `windows_failure` | `b1da7d7db361` |

The following snapshot comes from a fresh temporary database with default settings. Full IDs identify reproducible internal records; they do not authenticate their source.

<!-- result:start -->
```json
{
  "id": "01b531d03e87a53f3999f50c09434b928c018749822c1e72b74382e084e75303",
  "rule": "windows_brute_force",
  "title": "Windows repeated logon failures",
  "severity": "high",
  "first_seen": "2026-10-26T10:25:00.000000Z",
  "last_seen": "2026-10-26T10:27:00.000000Z",
  "evidence_count": 6,
  "failure_count": 6,
  "success_count": 0,
  "identity": {
    "host": "dc-01",
    "source_ip": "192.0.2.86",
    "user": "svc_backup",
    "domain": "lab",
    "logon_type": "10"
  },
  "parameters": {
    "threshold": 5,
    "window_seconds": 300
  }
}
```
<!-- result:end -->

The complete demo produces five alerts. This identity produces the single alert shown above. Severity is a fixed rule label, not a probability of compromise.

## Normal explanations

Stale service credentials, account lockout, or logon restrictions may cause repeated failures.

## What the rule misses

Different domains, logon types, accounts, hosts, or IPs form separate groups. Missing IP/domain/logon type excludes an event from correlation. Spraying and distributed attempts are not aggregated.

Across the SSH and Windows rules, password spraying across accounts and distributed attempts across IPs remain separate groups. A local sudo sequence uses terminal context instead of a network IP. These are deliberate coverage limits, not measured false-negative rates.

## Suggested analyst checks · not automated

1. Inspect Status and SubStatus in the raw record when present.
2. Check account state, expected logon type, and service configuration.
3. Record the remaining uncertainty before taking account or host action.

LogEssential automatically parses, deduplicates, correlates, and links evidence. It does not contact users, query account state, collect session commands, or perform containment.

## ATT&CK interpretation

T1110.001 is a hypothesis for repeated authentication attempts. The rule cannot infer password guessing from EventID alone. Status and SubStatus can help an analyst test that hypothesis. See [T1110.001](https://attack.mitre.org/techniques/T1110/001/) and the broader [ATT&CK technique context](https://attack.mitre.org/techniques/T1110/001/). The mapping describes a behavior to investigate.

## Reproduce without touching your working database

1. Install the project and test extra from the README.
2. Run `python tools/verify_examples.py` from the repository root.
3. Compare this file's result JSON with `docs/examples.json`.
4. Run `python -m pytest tests/test_examples.py tests/test_detection.py`.

The verification tool creates and removes its own temporary database. It validates every source record and the alert snapshot. In the browser, open this rule under **Security Alerts**, then inspect an evidence record.

Code: [parser](../../logsentinel/parsers.py), [correlation](../../logsentinel/detection.py), [storage](../../logsentinel/storage.py), [guidance](../../logsentinel/guidance.py).

Tests: [documented examples](../../tests/test_examples.py), [thresholds and identities](../../tests/test_detection.py), [API and evidence](../../tests/test_api.py), [Windows source checks](../../tests/test_windows_source.py).
