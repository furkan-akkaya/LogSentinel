import json
import pytest
from logsentinel.parsers import parse, timestamp


def test_linux_demo(samples):
    result = parse((samples / "linux-auth.log").read_text())
    assert len(result.events) == 50
    assert result.rejected == result.ignored == 0
    sudo = next(e for e in result.events if e.event_type == "sudo_failure")
    assert sudo.user == "analyst" and sudo.metadata["target_user"] == "root"


def test_windows_xml_matches_json(samples):
    xml = parse((samples / "windows-security.xml").read_text())
    js = parse((samples / "windows-security.json").read_text())
    assert len(xml.events) == len(js.events) == 35
    assert [e.id for e in xml.events] == [e.id for e in js.events]


@pytest.mark.parametrize(
    "stamp,expected",
    [
        ("2026-10-26T10:00:00+03:00", "2026-10-26T07:00:00.000000Z"),
        ("2026-10-26T08:00:00.1234567Z", "2026-10-26T08:00:00.123456Z"),
        ("2026-10-26T08:00:00", "2026-10-26T08:00:00.000000Z"),
    ],
)
def test_iso_timestamps(stamp, expected):
    assert timestamp(stamp) == expected


def test_yearless_import_context():
    result = parse(
        "Dec 31 23:59:59 host sshd[1]: Failed password for bob from 2001:db8::1 port 22 ssh2",
        year=2024,
        offset="-05:00",
    )
    assert result.events[0].timestamp == "2025-01-01T04:59:59.000000Z"


@pytest.mark.parametrize("offset", ["Europe/Istanbul", "+25:00", "+14:01", "00:00"])
def test_invalid_offsets(offset):
    with pytest.raises(ValueError):
        parse("x", offset=offset)


def test_malformed_and_ignored(samples):
    assert parse((samples / "malformed.log").read_text()).rejected == 2
    result = parse(
        "Oct 26 08:00:00 host cron[123]: running job\nOct 26 08:00:01 host sshd[1]: Connection closed"
    )
    assert result.ignored == 2


def test_ndjson_mixed(samples):
    record = json.loads((samples / "windows-security.json").read_text())[0]
    result = parse(json.dumps(record) + "\n{bad json\n" + json.dumps(record), "json")
    assert len(result.events) == 2 and result.rejected == 1


def test_flat_json_and_missing_fields():
    record = {
        "EventID": 4625,
        "TimeCreated": "2026-10-26T08:00:00Z",
        "Computer": "WS01",
        "TargetUserName": "alice",
        "IpAddress": "::ffff:192.0.2.1",
    }
    e = parse(json.dumps(record)).events[0]
    assert e.host == "ws01" and e.source_ip == "192.0.2.1"
    del record["Computer"]
    assert parse(json.dumps(record)).rejected == 1


def test_windows_named_data(samples):
    record = json.loads((samples / "windows-security.json").read_text())[0]
    baseline = parse(json.dumps(record)).events[0]
    record["EventData"] = {
        "Data": [{"@Name": k, "#text": v} for k, v in record["EventData"].items()]
    }
    assert parse(json.dumps({"Event": record})).events[0].id == baseline.id


@pytest.mark.parametrize(
    "payload",
    [
        '<!DOCTYPE Event [<!ENTITY x SYSTEM "file:///etc/passwd">]><Event>&x;</Event>',
        "<!DOCTYPE Events><Events/>",
        "<Events><Event>",
        "<other/>",
    ],
)
def test_unsafe_or_invalid_xml(payload):
    with pytest.raises(ValueError):
        parse(payload, "xml")


@pytest.mark.parametrize(
    "payload",
    [
        "[]",
        '[null, 42, {}, {"Event":null}]',
        '{"System": []}',
        '{"EventID":4625,"Computer":"host","TimeCreated":"bad"}',
    ],
)
def test_invalid_json_never_crashes(payload):
    assert parse(payload, "json") is not None


def test_input_limits():
    with pytest.raises(ValueError):
        parse("x\n" * 20001)
    assert parse("x" * 65537).rejected == 1
    with pytest.raises(ValueError):
        parse("")
    with pytest.raises(ValueError):
        parse("x", year=1800)


def test_sudo_summary_is_marked():
    e = parse(
        "Oct 26 08:00:00 host sudo: alice : 3 incorrect password attempts ; TTY=pts/1 ; USER=root"
    ).events[0]
    assert e.metadata["aggregate_summary"]


def test_bundled_demo_matches_public_samples(samples):
    from logsentinel.app import ROOT

    for name in ["linux-auth.log", "windows-security.json"]:
        assert (samples / name).read_bytes() == (ROOT / "demo" / name).read_bytes()


def test_sudo_target_is_not_inferred_as_invoking_user():
    e = parse(
        "Oct 26 08:00:00 host sudo[1]: pam_unix(sudo:auth): authentication failure; logname= ruser= tty=/dev/pts/1 user=root"
    ).events[0]
    assert e.user is None and e.metadata["target_user"] == "root"
