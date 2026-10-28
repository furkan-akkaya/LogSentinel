# Demo walkthrough

1. Start the app with `docker compose up --build -d`.
2. Open http://127.0.0.1:8765.
3. Select **Load demo**. No server or endpoint access is required.
4. Check **85 events**, **5 alerts**, **4 hosts**.
5. Open **Security Alerts** and select a detection.
6. Review the explanation, MITRE mappings, and evidence timeline.
7. Select **Inspect record** to see raw and normalized data.
8. Set an investigation to **investigating** or **resolved**.
9. Open **Log Explorer**, filter source IP `203.0.113.42`, and apply the filter.
10. Check the seven matching SSH failure records.
11. Load the demo again. The application reports 85 duplicates and zero new events.

## Expected default detections

| Scenario | Source | Host / user | Evidence | Severity |
|---|---|---|---|---|
| SSH password guessing | 203.0.113.42 | edge-01 / admin | 7 failures | High |
| SSH success after failures | 198.51.100.24 | app-02 / devops | 4 failures + success | Critical |
| Windows repeated failures | 192.0.2.86 | dc-01 / svc_backup | 6 failures | High |
| Windows success after failures | 203.0.113.77 | ws-finance / j.morgan | 4 failures + success | Critical |
| Repeated sudo failures | Local | app-02 / analyst | 4 PAM failures | Medium |

The SSH and Windows success scenarios have four failures. They trigger the success rule's threshold of three, but do not trigger the separate failure threshold of five. Normal events include routine SSH public-key authentication, Windows network logons, and one isolated failed SSH login followed by success. That isolated failure produces no alert.

The dataset is fixed at October 26, 2026, 08:00–11:41 UTC. Fixed event time makes tests reproducible. Detection has no "now" cutoff, so the demo works regardless of the machine's current date. Documentation IP ranges and private addresses represent synthetic identities.

## Manual import

`samples/linux-auth.log` and `samples/windows-security.json` contain the demo. Import either using **Import logs**. Import `samples/windows-security.xml` after the JSON file to verify cross-format duplicate detection. `samples/normal-auth.log` should produce no alerts in a fresh database. `samples/malformed.log` contains two rejected lines.

Normal-only tests need a fresh database: existing alerts describe previously stored evidence and do not disappear when a benign file is uploaded. For native use, choose a separate `LOGSENTINEL_DB` path. Do not delete a database containing logs you need.

Changing thresholds replays all stored events. An unusually low threshold can alert on legitimate retries. Investigate context before treating an alert as a confirmed incident.
