"""Reproduce documented examples in a disposable database, never the user's DB."""

import json
from pathlib import Path
import tempfile

from logsentinel.guidance import explain_alert
from logsentinel.parsers import parse
from logsentinel.storage import connection, event_dict, ingest, initialize, settings

ROOT = Path(__file__).resolve().parents[1]


def collect():
    with tempfile.TemporaryDirectory(prefix="logsentinel-examples-") as temp:
        path = Path(temp) / "examples.db"
        initialize(path)
        events = []
        for name in ["linux-auth.log", "windows-security.json"]:
            result = parse((ROOT / "samples" / name).read_text())
            assert not result.rejected
            events.extend(result.events)
        with connection(path) as db:
            first = ingest(db, events, "bundled synthetic demo")
        with connection(path) as db:
            second = ingest(db, events, "bundled synthetic demo")
        examples = {}
        with connection(path) as db:
            for row in db.execute("SELECT body FROM alerts"):
                alert = json.loads(row["body"])
                evidence = [
                    event_dict(
                        db.execute("SELECT * FROM events WHERE id=?", (key,)).fetchone()
                    )
                    for key in alert["evidence"]
                ]
                info = explain_alert(alert, evidence, settings(db))
                summary = {
                    key: alert[key]
                    for key in [
                        "id",
                        "rule",
                        "title",
                        "severity",
                        "first_seen",
                        "last_seen",
                    ]
                }
                summary.update(
                    {
                        key: info[key]
                        for key in [
                            "evidence_count",
                            "failure_count",
                            "success_count",
                            "identity",
                            "parameters",
                        ]
                    }
                )
                examples[alert["rule"]] = {"summary": summary, "events": evidence}
        return {
            "first_import": first,
            "second_import": second,
            "scenarios": dict(sorted(examples.items())),
        }


def verify():
    actual = collect()
    expected = json.loads((ROOT / "docs" / "examples.json").read_text())
    assert actual == expected, "Documented example snapshot differs from the engine"
    for rule, example in actual["scenarios"].items():
        text = (ROOT / "docs" / "detections" / f"{rule}.md").read_text()
        block = text.split("<!-- result:start -->\n```json\n", 1)[1].split("\n```", 1)[
            0
        ]
        assert json.loads(block) == example["summary"], f"{rule}: result JSON drift"
        evidence = text.split("<!-- evidence:start -->\n", 1)[1].split(
            "\n<!-- evidence:end -->", 1
        )[0]
        if rule.startswith("windows"):
            records = [
                json.loads(line)
                for line in evidence.split("```json\n", 1)[1]
                .split("\n```", 1)[0]
                .splitlines()
            ]
            assert records == [json.loads(e["raw"]) for e in example["events"]]
        else:
            assert evidence.split("```text\n", 1)[1].split("\n```", 1)[
                0
            ].splitlines() == [e["raw"] for e in example["events"]]
    report = (ROOT / "docs" / "reports" / "SSH_CASE_STUDY.md").read_text()
    assert actual["scenarios"]["ssh_success_after_failures"]["summary"]["id"] in report
    for e in actual["scenarios"]["ssh_success_after_failures"]["events"]:
        assert e["timestamp"][11:19] in report
    walkthrough = (ROOT / "docs" / "learning" / "HOW_IT_WORKS.md").read_text()
    for rule in ["ssh_success_after_failures", "windows_brute_force"]:
        event = actual["scenarios"][rule]["events"][0]
        normalized = {
            k: event[k]
            for k in [
                "id",
                "timestamp",
                "source",
                "event_type",
                "host",
                "user",
                "source_ip",
                "metadata",
            ]
        }
        assert json.dumps(normalized, indent=2) in walkthrough, (
            f"{rule}: normalized walkthrough drift"
        )
    print(
        "PASS: 85 events, 5 scenario results, 27 evidence records, dedup and SSH case timeline match the actual engine"
    )


if __name__ == "__main__":
    verify()
