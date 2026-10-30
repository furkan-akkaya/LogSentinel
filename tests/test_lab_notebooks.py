"""Behavioral checks for isolated learning, manual notes and truthful data labels."""

import sqlite3

import pytest
from fastapi.testclient import TestClient

from logsentinel.app import create_app
from logsentinel.detection import DEFAULTS, detect
from logsentinel.lab import MAX_REPLAY_EVENTS, SCENARIOS, replay, scenario_events


def run(client, scenario="ssh_recovery", **settings):
    return client.post(
        "/api/lab/replay",
        json={"scenario": scenario, "settings": {**DEFAULTS, **settings}},
    )


@pytest.mark.parametrize(
    "scenario,count",
    [
        ("ssh_recovery", 2),
        ("window_edge", 1),
        ("split_identity", 0),
        ("public_keys", 0),
        ("windows_context", 0),
    ],
)
def test_scenarios_are_real_engine_results_at_every_step(client, scenario, count):
    response = run(client, scenario)
    assert response.status_code == 200
    result = response.json()
    assert len(result["alerts"]) == count
    assert result["scope"]["kind"] == "synthetic_scenario"
    for i, step in enumerate(result["steps"]):
        expected = detect(result["events"][: i + 1], DEFAULTS)
        assert step["alerts_total"] == len(expected)
        assert all(a in expected for a in step["triggered"] + step["updated"])


def test_replay_time_boundary_and_threshold(client):
    assert len(run(client, "window_edge", window_seconds=299).json()["alerts"]) == 0
    assert len(run(client, "window_edge", window_seconds=300).json()["alerts"]) == 1
    assert len(run(client, "window_edge", ssh_threshold=6).json()["alerts"]) == 0
    result = run(client, "ssh_recovery").json()
    assert [len(s["triggered"]) for s in result["steps"]] == [0, 0, 0, 0, 1, 1]
    assert result["baseline"]["settings"] == DEFAULTS


def test_scenarios_expose_exclusions_and_identity(client):
    assert all(not s["eligible"] for s in run(client, "public_keys").json()["steps"])
    data = run(client, "windows_context").json()
    assert data["steps"][0]["identity"][-1] == "10"
    assert data["steps"][-1]["identity"][-1] == "3"
    assert len(client.get("/api/lab").json()["scenarios"]) == len(SCENARIOS)


def test_lab_never_mutates_workspace_even_for_alert_evidence(client):
    client.post("/api/demo")
    alert = client.get("/api/alerts").json()["items"][0]
    client.patch(f"/api/alerts/{alert['id']}", json={"status": "investigating"})
    before = {
        table: client.get(f"/api/{table}").json()
        for table in ["stats", "settings", "alerts", "events", "notebooks"]
    }
    for scenario in SCENARIOS:
        assert run(client, scenario["id"], window_seconds=10).status_code == 200
    response = client.post(
        "/api/lab/replay",
        json={"alert_id": alert["id"], "settings": {**DEFAULTS, "sudo_threshold": 100}},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["scope"]["kind"] == "alert_evidence"
    assert {e["id"] for e in data["events"]} == set(alert["evidence"])
    assert data["alerts"] == []
    after = {table: client.get(f"/api/{table}").json() for table in before}
    assert before == after


@pytest.mark.parametrize(
    "body",
    [
        {"settings": DEFAULTS},
        {"scenario": "no-such", "settings": DEFAULTS},
        {"scenario": "ssh_recovery", "alert_id": "x", "settings": DEFAULTS},
        {"scenario": "ssh_recovery", "settings": {**DEFAULTS, "window_seconds": "300"}},
        {"scenario": "ssh_recovery", "settings": {**DEFAULTS, "ssh_threshold": 1}},
        {"scenario": "ssh_recovery", "settings": DEFAULTS, "unexpected": True},
    ],
)
def test_replay_rejects_ambiguous_or_invalid_input(client, body):
    assert client.post("/api/lab/replay", json=body).status_code == 422


def test_replay_bounded_and_missing_alert(client):
    assert (
        client.post(
            "/api/lab/replay", json={"alert_id": "missing", "settings": DEFAULTS}
        ).status_code
        == 404
    )
    events = scenario_events("ssh_recovery")
    with pytest.raises(ValueError, match="at most 200"):
        replay(events * (MAX_REPLAY_EVENTS // len(events) + 1), DEFAULTS)
    assert replay(list(reversed(events)), DEFAULTS) == replay(events, DEFAULTS)


def test_notebook_survives_removed_alert_and_restart(tmp_path):
    path = tmp_path / "notes.db"
    with TestClient(create_app(path), base_url="http://localhost") as c:
        c.post("/api/demo")
        a = c.get("/api/alerts").json()["items"][0]
        note = {
            "assessment": "undetermined",
            "observation": "Four sudo failures",
            "hypothesis": "A typo is possible",
            "next_step": "Ask the account owner",
        }
        saved = c.put(f"/api/alerts/{a['id']}/notebook", json=note).json()
        assert saved["note"] == note
        assert saved["alert"]["evidence"] == [e["id"] for e in saved["events"]]
        assert saved["evidence_omitted"] == 0
        assert c.get(f"/api/alerts/{a['id']}").json()["notebook"] == saved
        c.put("/api/settings", json={**DEFAULTS, "sudo_threshold": 100})
        assert c.get(f"/api/alerts/{a['id']}").status_code == 404
        assert c.get("/api/notebooks").json()["items"][0]["active"] is False
    with TestClient(create_app(path), base_url="http://localhost") as c:
        assert c.get(f"/api/notebooks/{a['id']}").json() == saved
        c.put("/api/settings", json=DEFAULTS)
        assert c.get("/api/notebooks").json()["items"][0]["active"] is True
        updated = c.put(
            f"/api/alerts/{a['id']}/notebook",
            json={**note, "assessment": "likely_benign"},
        ).json()
        assert updated["note"]["assessment"] == "likely_benign"
        assert len(c.get("/api/notebooks").json()["items"]) == 1
        assert saved["note"]["assessment"] == "undetermined"


def test_notebook_validation_and_local_boundary(client):
    assert client.put("/api/alerts/missing/notebook", json={}).status_code == 404
    assert client.get("/api/notebooks/missing").status_code == 404
    client.post("/api/demo")
    a = client.get("/api/alerts").json()["items"][0]
    endpoint = f"/api/alerts/{a['id']}/notebook"
    for value in [
        {"assessment": "confirmed_compromise"},
        {"observation": "a" * 4001},
        {"observation": 12},
        {"unknown": "field"},
    ]:
        assert client.put(endpoint, json=value).status_code == 422
    assert (
        client.put(
            endpoint, json={}, headers={"Origin": "https://evil.example"}
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/api/lab/replay",
            json={"scenario": "ssh_recovery", "settings": DEFAULTS},
            headers={"Origin": "https://evil.example"},
        ).status_code
        == 403
    )


def test_dataset_content_matches_do_not_depend_on_filename(client, samples):
    assert client.get("/api/stats").json()["dataset"] == {
        "bundled_synthetic_match": 0,
        "unverified_import": 0,
    }
    client.post(
        "/api/import",
        files={
            "file": ("real-production.log", (samples / "linux-auth.log").read_bytes())
        },
    )
    assert client.get("/api/stats").json()["dataset"]["bundled_synthetic_match"] == 50
    content = b"2026-10-26T12:00:00Z other sshd[2]: Failed password for bob from 192.0.2.8 port 22 ssh2"
    client.post("/api/import", files={"file": ("bundled synthetic demo", content)})
    stats = client.get("/api/stats").json()
    assert stats["dataset"] == {"bundled_synthetic_match": 50, "unverified_import": 1}
    event = client.get("/api/events?q=other").json()["items"][0]
    assert event["dataset_kind"] == "unverified_import"
    assert (
        client.get(f"/api/events/{event['id']}").json()["dataset_kind"]
        == "unverified_import"
    )


def test_existing_database_migrates_without_losing_events_or_config(tmp_path):
    path = tmp_path / "legacy.db"
    with TestClient(create_app(path), base_url="http://localhost") as c:
        c.post("/api/demo")
        config = c.get("/api/settings").json()
    with sqlite3.connect(path) as db:
        db.execute("DROP TABLE notebooks")
    with TestClient(create_app(path), base_url="http://localhost") as c:
        assert c.get("/api/stats").json()["events"] == 85
        assert c.get("/api/settings").json() == config
        assert c.get("/api/notebooks").json() == {"items": []}


def test_large_alert_has_explicit_snapshot_limit_and_replay_refusal(client):
    from datetime import datetime, timedelta, timezone

    records = []
    for i in range(250):
        stamp = (
            datetime(2026, 10, 26, tzinfo=timezone.utc) + timedelta(seconds=i)
        ).isoformat()
        records.append(
            f"{stamp} dense sshd[100]: Failed password for alice from 192.0.2.9 port {40000 + i} ssh2"
        )
    result = client.post(
        "/api/import", files={"file": ("dense.log", "\n".join(records))}
    )
    assert result.json()["inserted"] == 250
    alert = client.get("/api/alerts").json()["items"][0]
    assert len(alert["evidence"]) == 250
    assert (
        client.post(
            "/api/lab/replay", json={"alert_id": alert["id"], "settings": DEFAULTS}
        ).status_code
        == 422
    )
    saved = client.put(
        f"/api/alerts/{alert['id']}/notebook", json={"observation": "Dense sequence"}
    ).json()
    assert len(saved["events"]) == 200
    assert saved["evidence_omitted"] == 50
    assert saved["snapshot_policy"] == "first_and_final"
    assert saved["events"][-1]["id"] == alert["evidence"][-1]
    assert [e["id"] for e in saved["events"][:-1]] == alert["evidence"][:199]
    assert saved["alert"]["evidence"] == alert["evidence"]


def test_saving_notes_does_not_change_alert_status_or_parameters(client):
    client.post("/api/demo")
    before = client.get("/api/alerts").json()
    a = before["items"][0]
    config = client.get("/api/settings").json()
    client.put(
        f"/api/alerts/{a['id']}/notebook",
        json={"assessment": "suspicious", "observation": "<script>alert(1)</script>"},
    )
    assert client.get("/api/alerts").json() == before
    assert client.get("/api/settings").json() == config
    assert (
        client.get(f"/api/notebooks/{a['id']}").json()["note"]["observation"]
        == "<script>alert(1)</script>"
    )
