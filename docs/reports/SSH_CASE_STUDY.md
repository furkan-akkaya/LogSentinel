# Synthetic case study: SSH success after failures

[Project guide](../INDEX.md) · [Scenario and complete raw records](../detections/ssh_success_after_failures.md)

**Scope:** a reproducible synthetic case. This is not a report of a real attack or an investigation performed in a real organization.

![Case timeline](../diagrams/ssh_success_after_failures.svg)

## 1. Incident summary

On October 26, 2026, four failed password authentications preceded one accepted password authentication on `app-02`. Every record names `devops` and source IP `198.51.100.24`.

The 90-second sequence triggers `ssh_success_after_failures`. The alert has critical rule severity and five linked evidence records. The evidence does not establish who logged in or what they did.

## 2. Data source and scope

The source is [the bundled Linux auth sample](../../samples/linux-auth.log), parsed by the same engine used for uploaded files. The analyzed identity contains five SSH records from 10:40:00 to 10:41:30 UTC.

The full demo also includes other hosts and identities. They are separate correlation groups and do not contribute to this case. No endpoint agent, command history, network capture, or external enrichment was used.

## 3. Timeline

| Time · UTC | Observation | Additional raw fields |
|---|---|---|
| 10:40:00 | `ssh_failure` | PID `6000`, source port `52000` |
| 10:40:20 | `ssh_failure` | PID `6001`, source port `52001` |
| 10:40:40 | `ssh_failure` | PID `6002`, source port `52002` |
| 10:41:00 | `ssh_failure` | PID `6003`, source port `52003` |
| 10:41:30 | `ssh_success` | PID `6010`, source port `52010` |

The source ports and PIDs differ. They are event metadata, not session linkage. The correlation key is host + source IP + user.

## 4. Verified observations

1. All five records match `app-02 / 198.51.100.24 / devops`.
2. Four records say `Failed password`; the last says `Accepted password`.
3. The successful record is strictly later than every counted failure.
4. The four failures fit inside the configured 300-second lookback before success.
5. The real engine creates one alert with ID `a93aea77b0912d5f3e91239bd39acaa60d9dbc9c4634d584f109dfcb57a57be5`.
6. The success threshold is **three failures**, so four failures satisfy that rule.
7. The independent SSH failure threshold is **five failures**, so this sequence does not trigger `ssh_brute_force`.

The word critical expresses the rule's review priority. It is not a calculated probability or confirmed-impact label.

## 5. Possible explanations · hypotheses

An unauthorized operator could have guessed a valid password. A legitimate user could also have corrected repeated typing mistakes. An expected script with stale credentials might have been fixed before the successful attempt.

The sample alone cannot distinguish these explanations. Authentication outcomes identify an account and source address, not the person operating them.

## 6. Missing evidence

- Confirmation from the account owner.
- The expected source-IP inventory and access schedule.
- Session identifiers and post-login commands or process activity.
- Host integrity evidence, authorization context, and change records.
- Independent evidence that the file itself represents authentic source activity.

The SHA-256 event IDs identify normalized records for deduplication. They do not fill these evidence gaps.

## 7. Suggested next checks · not performed by LogEssential

1. Confirm whether the account owner expected this login.
2. Compare the address against approved access paths and shared gateways.
3. Collect adjacent SSH/session records and relevant command or process logs from authorized sources.
4. Check credential changes and account policy changes near the sequence.
5. Record which hypothesis each additional source supports before taking containment action.

These are analyst recommendations. The application does not contact users, collect commands, inspect processes, reset credentials, or isolate hosts.

## 8. Measured conclusion

The sample demonstrates **a matching authentication-failure sequence followed by success**. It warrants investigation in a real environment. It does not prove successful password guessing, account takeover, or post-login impact.

[T1110.001](https://attack.mitre.org/techniques/T1110/001/) and [T1078](https://attack.mitre.org/techniques/T1078/) are possible behavioral interpretations. The evidence supports reviewing them, not asserting them as facts.

## Reproduce

1. Run `python tools/verify_examples.py` from the repository root.
2. Run `python -m pytest tests/test_examples.py tests/test_detection.py tests/test_api.py`.
3. In an isolated demo, open **SSH success after failures** under **Security Alerts**.
4. Inspect the five records and compare the matching identity and parameters.

The verifier and tests use their own temporary databases. See [scenario details](../detections/ssh_success_after_failures.md), [engine](../../logsentinel/detection.py), [tests](../../tests/test_examples.py), and [validation results](../VALIDATION.md).
