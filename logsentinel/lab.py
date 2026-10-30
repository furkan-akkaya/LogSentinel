"""Small, isolated event-time experiments using the production detection engine."""

from dataclasses import asdict
from datetime import datetime, timedelta, timezone

from .detection import correlation_key, detect
from .parsers import parse

MAX_REPLAY_EVENTS = 200
SCENARIOS = [
    {
        "id": "ssh_recovery",
        "title": "A login after failures",
        "tag": "SSH · sequence",
        "objective": "Separate the observed authentication sequence from a compromise claim.",
        "question": "Does a successful login after failures prove account takeover?",
        "hint": "Compare what authentication logs record with what they cannot identify.",
        "answer": "No. The same user may have corrected a password. Confirm ownership and inspect session activity before judging intent.",
    },
    {
        "id": "window_edge",
        "title": "One second changes the result",
        "tag": "SSH · time window",
        "objective": "Compare a 299-second window with a 300-second window at the inclusive boundary.",
        "question": "Why can five failures produce no alert with a 299-second window?",
        "hint": "Measure the distance from the first record to the last record.",
        "answer": "These five failures span exactly 300 seconds. A 299-second window excludes the first failure; a 300-second window includes it.",
    },
    {
        "id": "split_identity",
        "title": "Many accounts, no single match",
        "tag": "SSH · blind spot",
        "objective": "See why a per-account rule cannot aggregate password spraying across accounts.",
        "question": "Does zero alerts mean this activity is safe?",
        "hint": "Inspect the user field of each record and the rule's correlation identity.",
        "answer": "No. Each record targets a different account. This rule groups by host, IP and user; cross-account spraying needs a separate rule.",
    },
    {
        "id": "public_keys",
        "title": "Failures that do not count",
        "tag": "SSH · authentication method",
        "objective": "Distinguish public-key failures from password-guessing evidence.",
        "question": "Why does lowering the password threshold not include these failures?",
        "hint": "Inspect the authentication method in the raw records.",
        "answer": "The rule explicitly excludes public-key failures. Multiple offered SSH keys are not password guesses; changing a threshold cannot change eligibility.",
    },
    {
        "id": "windows_context",
        "title": "Same account, different session type",
        "tag": "Windows · identity",
        "objective": "Observe how Windows logon type separates otherwise matching identities.",
        "question": "Why is the type 3 success not joined to type 10 failures?",
        "hint": "Compare all five identity fields, including domain and logon type.",
        "answer": "Type 3 is a network logon; type 10 is remote interactive. The engine keeps these contexts separate, so this success does not complete that failure sequence.",
    },
]


def scenario_events(identifier):
    """Generate documented synthetic records through the actual parsers."""
    if identifier not in {s["id"] for s in SCENARIOS}:
        raise ValueError("Unknown lab scenario")
    if identifier == "windows_context":
        import json

        records = [
            {
                "System": {
                    "EventID": 4625 if i < 4 else 4624,
                    "Computer": "lab-windows",
                    "TimeCreated": f"2026-10-26T12:00:0{i}Z",
                },
                "EventData": {
                    "TargetUserName": "analyst",
                    "TargetDomainName": "LAB",
                    "IpAddress": "192.0.2.20",
                    "LogonType": "10" if i < 4 else "3",
                },
            }
            for i in range(5)
        ]
        parsed = parse(json.dumps(records), "json")
    else:
        offsets = (
            [0, 75, 150, 225, 300] if identifier == "window_edge" else list(range(6))
        )
        records = []
        for i, offset in enumerate(offsets):
            stamp = datetime(2026, 10, 26, 12, tzinfo=timezone.utc) + timedelta(
                seconds=offset
            )
            outcome = (
                "Accepted" if identifier == "ssh_recovery" and i == 5 else "Failed"
            )
            method = "publickey" if identifier == "public_keys" else "password"
            user = f"user{i}" if identifier == "split_identity" else "analyst"
            records.append(
                f"{stamp.isoformat()} lab-ssh sshd[100]: {outcome} {method} for {user} from 192.0.2.10 port {40000 + i} ssh2"
            )
        parsed = parse("\n".join(records), "linux")
    assert not parsed.rejected and not parsed.ignored
    return [
        {**asdict(e), "id": e.id, "filename": "isolated synthetic lab"}
        for e in parsed.events
    ]


def replay(events, parameters):
    """Replay sorted prefixes. Never write events, settings, alerts, or statuses."""
    if len(events) > MAX_REPLAY_EVENTS:
        raise ValueError(
            f"Replay supports at most {MAX_REPLAY_EVENTS} evidence records; this alert is too large"
        )
    ordered = sorted(events, key=lambda e: (e["timestamp"], e["id"]))
    steps, previous = [], {}
    for index, event in enumerate(ordered):
        alerts = detect(ordered[: index + 1], parameters)
        current = {a["id"]: a for a in alerts}
        steps.append(
            {
                "event_id": event["id"],
                "eligible": correlation_key(event) is not None,
                "identity": list(correlation_key(event) or []),
                "alerts_total": len(alerts),
                "triggered": [a for key, a in current.items() if key not in previous],
                "updated": [
                    a
                    for key, a in current.items()
                    if key in previous and a["evidence"] != previous[key]["evidence"]
                ],
            }
        )
        previous = current
    return {
        "events": ordered,
        "steps": steps,
        "alerts": list(previous.values()),
        "settings": parameters,
    }
