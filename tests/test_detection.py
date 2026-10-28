from datetime import datetime, timedelta, timezone
import pytest
from logsentinel.detection import DEFAULTS, detect


def event(number, kind="ssh_failure", second=None, **changes):
    dt = datetime(2026, 10, 26, tzinfo=timezone.utc) + timedelta(
        seconds=number if second is None else second
    )
    value = {
        "id": str(number),
        "timestamp": dt.isoformat(timespec="microseconds").replace("+00:00", "Z"),
        "source": "windows" if kind.startswith("windows") else "linux",
        "event_type": kind,
        "host": "server",
        "user": "alice",
        "source_ip": "192.0.2.1",
        "metadata": {"domain": "LAB", "logon_type": "10", "tty": "pts/1"},
    }
    value.update(changes)
    return value


@pytest.mark.parametrize(
    "kind,count,rule",
    [
        ("ssh_failure", 5, "ssh_brute_force"),
        ("windows_failure", 5, "windows_brute_force"),
        ("sudo_failure", 3, "sudo_failures"),
    ],
)
def test_failure_thresholds(kind, count, rule):
    events = [event(i, kind) for i in range(count)]
    assert detect(events[:-1], DEFAULTS) == []
    result = detect(events, DEFAULTS)
    assert len(result) == 1 and result[0]["rule"] == rule
    assert len(result[0]["evidence"]) == count


@pytest.mark.parametrize("family", ["ssh", "windows"])
def test_success_after_failures(family):
    events = [event(i, f"{family}_failure") for i in range(3)] + [
        event(4, f"{family}_success")
    ]
    result = detect(events, DEFAULTS)
    assert len(result) == 1 and result[0]["rule"] == f"{family}_success_after_failures"
    assert len(result[0]["evidence"]) == 4
    assert "T1078" in result[0]["mitre"]


@pytest.mark.parametrize(
    "field,value", [("host", "other"), ("user", "bob"), ("source_ip", "192.0.2.2")]
)
@pytest.mark.parametrize("family", ["ssh", "windows"])
def test_no_cross_identity_success(field, value, family):
    events = [event(i, f"{family}_failure") for i in range(3)] + [
        event(4, f"{family}_success", **{field: value})
    ]
    assert detect(events, DEFAULTS) == []


@pytest.mark.parametrize(
    "field,value",
    [("domain", "OTHER"), ("logon_type", "3"), ("domain", None), ("logon_type", None)],
)
def test_windows_context_separation(field, value):
    events = [event(i, "windows_failure") for i in range(3)]
    success = event(4, "windows_success")
    success["metadata"][field] = value
    events.append(success)
    assert detect(events, DEFAULTS) == []


def test_missing_ip_not_correlated():
    assert (
        detect(
            [event(i, "windows_failure", source_ip=None) for i in range(9)], DEFAULTS
        )
        == []
    )


def test_windows_account_case_insensitive():
    events = [event(i, "windows_failure") for i in range(3)]
    success = event(4, "windows_success", host="SERVER", user="ALICE")
    success["metadata"]["domain"] = "lab"
    assert len(detect(events + [success], DEFAULTS)) == 1


@pytest.mark.parametrize("seconds,expected", [(300, 1), (301, 0)])
def test_window_boundary(seconds, expected):
    events = [event(0), event(1), event(2), event(3), event(4, second=seconds)]
    assert len(detect(events, DEFAULTS)) == expected


def test_out_of_order_and_stable_ids():
    events = [event(i) for i in range(8)]
    expected = detect(events, DEFAULTS)
    assert detect(list(reversed(events)), DEFAULTS) == expected
    assert len(expected) == 1 and len(expected[0]["evidence"]) == 8
    assert detect(events[:5], DEFAULTS)[0]["id"] == expected[0]["id"]


def test_long_burst_evidence_window():
    events = [event(i, second=i * 60) for i in range(15)]
    for alert in detect(events, DEFAULTS):
        stamps = [
            datetime.fromisoformat(events[int(eid)]["timestamp"].replace("Z", "+00:00"))
            for eid in alert["evidence"]
        ]
        assert (max(stamps) - min(stamps)).total_seconds() <= 300


def test_success_resets_failure_history():
    events = [event(i) for i in range(3)] + [
        event(4, "ssh_success"),
        event(5, "ssh_success"),
    ]
    assert len(detect(events, DEFAULTS)) == 1


def test_equal_time_is_not_after():
    events = [event(i, second=0) for i in range(3)] + [
        event(4, "ssh_success", second=0)
    ]
    assert detect(events, DEFAULTS) == []


def test_equal_time_failures_can_precede_later_success():
    events = [event(i, second=0) for i in range(3)] + [
        event(4, "ssh_success", second=0),
        event(5, "ssh_success", second=1),
    ]
    assert len(detect(events, DEFAULTS)) == 1


def test_success_outside_window():
    events = [event(i) for i in range(3)] + [event(4, "ssh_success", second=400)]
    assert detect(events, DEFAULTS) == []


def test_sudo_summary_and_terminal_separation():
    events = [event(i, "sudo_failure") for i in range(3)]
    events[2]["metadata"]["tty"] = "pts/2"
    assert detect(events, DEFAULTS) == []
    for e in events:
        e["metadata"]["aggregate_summary"] = True
    assert detect(events, DEFAULTS) == []
    for e in events:
        e["metadata"] = {}
    assert detect(events, DEFAULTS) == []


def test_custom_threshold():
    settings = {**DEFAULTS, "ssh_threshold": 2}
    assert len(detect([event(0), event(1)], settings)) == 1


def test_failed_public_keys_are_not_password_guessing():
    events = [event(i) for i in range(8)]
    for e in events:
        e["metadata"]["method"] = "publickey"
    assert detect(events, DEFAULTS) == []


def test_benign_samples(samples):
    from logsentinel.parsers import parse

    events = [
        {**e.__dict__, "id": e.id}
        for e in parse((samples / "normal-auth.log").read_text()).events
    ]
    assert detect(events, DEFAULTS) == []


@pytest.mark.parametrize("split", ["user", "source_ip"])
@pytest.mark.parametrize("family", ["ssh", "windows"])
def test_spraying_and_distributed_failures_are_out_of_scope(split, family):
    events = [
        event(
            i,
            f"{family}_failure",
            **{split: str(i) if split == "user" else f"192.0.2.{i + 1}"},
        )
        for i in range(7)
    ]
    assert detect(events, DEFAULTS) == []
