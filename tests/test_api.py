import json
from concurrent.futures import ThreadPoolExecutor
import pytest
from fastapi.testclient import TestClient
from logsentinel.app import create_app, MAX_UPLOAD
from logsentinel.detection import DEFAULTS


def upload(client, path, **data):
    return client.post(
        "/api/import", files={"file": (path.name, path.read_bytes())}, data=data
    )


def test_demo_five_rules_and_dedup(client, samples):
    result = client.post("/api/demo").json()
    assert result["inserted"] == 85 and result["alerts_total"] == 5
    stats = client.get("/api/stats").json()
    assert stats["severity"] == {"critical": 2, "high": 2, "medium": 1}
    assert stats["hosts"] == 4 and sum(v["events"] for v in stats["timeline"]) == 85
    assert sum(v["alerts"] for v in stats["timeline"]) == 5
    ids = {a["id"] for a in client.get("/api/alerts").json()["items"]}
    assert client.post("/api/demo").json()["inserted"] == 0
    assert upload(client, samples / "windows-security.xml").json()["duplicates"] == 35
    assert ids == {a["id"] for a in client.get("/api/alerts").json()["items"]}
    for a in ids:
        detail = client.get("/api/alerts/" + a).json()
        assert [e["id"] for e in detail["events"]] == detail["evidence"]


def test_search_filters_pagination_and_dates(client):
    client.post("/api/demo")
    result = client.get(
        "/api/events",
        params={
            "source": "linux",
            "event_type": "ssh_failure",
            "source_ip": "203.0.113.42",
            "user": "admin",
            "host": "edge-01",
        },
    ).json()
    assert result["total"] == 7
    assert (
        client.get("/api/events", params={"q": "ACCEPTED publickey"}).json()["total"]
        == 33
    )
    assert (
        client.get(
            "/api/events",
            params={
                "start": "2026-10-26T10:10:00Z",
                "end": "2026-10-26T10:11:59Z",
                "source_ip": "203.0.113.42",
            },
        ).json()["total"]
        == 7
    )
    assert client.get("/api/events", params={"q": "' OR 1=1 --"}).json()["total"] == 0
    first = client.get("/api/events?limit=10").json()
    second = client.get("/api/events?limit=10&offset=10").json()
    assert not {e["id"] for e in first["items"]} & {e["id"] for e in second["items"]}
    for path in [
        "/api/events?limit=999",
        "/api/events?start=bad",
        "/api/events?start=2026-10-28&end=2026-10-26",
        "/api/events?offset=-1",
    ]:
        assert client.get(path).status_code == 422


def test_settings_reanalysis_and_validation(client):
    client.post("/api/demo")
    result = client.put(
        "/api/settings",
        json={
            **DEFAULTS,
            "ssh_threshold": 8,
            "windows_threshold": 8,
            "sudo_threshold": 8,
            "success_threshold": 8,
        },
    )
    assert result.json()["alerts_total"] == 0
    assert client.put("/api/settings", json=DEFAULTS).json()["alerts_total"] == 5
    assert (
        client.put("/api/settings", json={**DEFAULTS, "ssh_threshold": 1}).status_code
        == 422
    )
    assert (
        client.put(
            "/api/settings", json={**DEFAULTS, "window_seconds": "300"}
        ).status_code
        == 422
    )


def test_status_and_persistence(tmp_path):
    app = create_app(tmp_path / "persist.db")
    with TestClient(app, base_url="http://localhost") as c:
        c.post("/api/demo")
        identifier = c.get("/api/alerts").json()["items"][0]["id"]
        assert (
            c.patch(
                "/api/alerts/" + identifier, json={"status": "resolved"}
            ).status_code
            == 200
        )
        c.put("/api/settings", json=DEFAULTS)
    with TestClient(
        create_app(tmp_path / "persist.db"), base_url="http://localhost"
    ) as c:
        assert c.get("/api/stats").json()["events"] == 85
        assert c.get("/api/alerts/" + identifier).json()["status"] == "resolved"
        assert c.get("/api/alerts?status=resolved").json()["total"] == 1
        assert c.get("/api/stats").json()["open_alerts"] == 4


def test_bad_inputs_and_partial_import(client, samples):
    assert upload(client, samples / "malformed.log").json()["rejected"] == 2
    assert client.get("/api/stats").json()["events"] == 0
    record = (samples / "linux-auth.log").read_text().splitlines()[0]
    result = client.post(
        "/api/import", files={"file": ("mixed.log", record + "\nbroken")}
    ).json()
    assert result["inserted"] == 1 and result["rejected"] == 1
    assert (
        client.post(
            "/api/import", files={"file": ("file.evtx", b"\xff\xfe")}
        ).status_code
        == 400
    )
    assert (
        client.post("/api/import", files={"file": ("empty.log", b"")}).status_code
        == 400
    )
    assert (
        client.post(
            "/api/import", files={"file": ("large.log", b"x" * (MAX_UPLOAD + 1))}
        ).status_code
        == 413
    )
    assert (
        client.post("/api/import", content=b"x" * (MAX_UPLOAD + 65537)).status_code
        == 413
    )


def test_local_boundaries(client):
    assert (
        client.post("/api/demo", headers={"Origin": "https://evil.example"}).status_code
        == 403
    )
    assert client.post("/api/demo", headers={"Origin": "null"}).status_code == 403
    assert client.get("/api/stats", headers={"Host": "evil.example"}).status_code == 400
    r = client.get("/")
    assert (
        r.status_code == 200
        and "script-src 'self'" in r.headers["Content-Security-Policy"]
    )
    assert client.get("/static/app.js").status_code == 200
    assert client.get("/docs").status_code == 200
    assert client.get("/openapi.json").status_code == 200


@pytest.mark.parametrize("endpoint", ["/api/events/missing", "/api/alerts/missing"])
def test_missing_records(client, endpoint):
    assert client.get(endpoint).status_code == 404


def test_concurrent_duplicate_imports(client):
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: client.post("/api/demo"), range(2)))
    assert all(r.status_code == 200 for r in results)
    assert sum(r.json()["inserted"] for r in results) == 85
    assert client.get("/api/stats").json()["alerts"] == 5


def test_event_cap_rolls_back(client, monkeypatch):
    import logsentinel.storage as storage

    monkeypatch.setattr(storage, "MAX_EVENTS", 10)
    assert client.post("/api/demo").status_code == 400
    assert client.get("/api/stats").json()["events"] == 0
    assert client.get("/api/stats").json()["alerts"] == 0


def test_cross_file_out_of_order_correlation(client, samples):
    records = json.loads((samples / "windows-security.json").read_text())
    scenario = [e for e in records if e["EventData"]["IpAddress"] == "203.0.113.77"]
    success = client.post(
        "/api/import", files={"file": ("success.json", json.dumps(scenario[-1]))}
    ).json()
    assert success["alerts_total"] == 0
    failures = client.post(
        "/api/import",
        files={"file": ("failures.json", json.dumps(list(reversed(scenario[:-1]))))},
    ).json()
    assert failures["alerts_total"] == 1
    assert (
        client.get("/api/alerts").json()["items"][0]["rule"]
        == "windows_success_after_failures"
    )


def test_posix_database_permissions(client):
    import os
    from pathlib import Path

    if os.name != "posix":
        pytest.skip("POSIX permissions only")
    assert Path(client.app.state.db_path).stat().st_mode & 0o777 == 0o600


def test_alert_explanation_uses_real_counts_context_and_parameters(client):
    client.post("/api/demo")
    items = client.get("/api/alerts").json()["items"]
    for item in items:
        a = client.get("/api/alerts/" + item["id"]).json()
        info = a["explanation"]
        assert info["evidence_count"] == len(a["events"])
        assert info["failure_count"] + info["success_count"] == len(a["events"])
        assert info["parameters"] == a["parameters"]
        assert client.get(info["guide_url"]).status_code == 200
        if item["rule"].startswith("windows"):
            assert (
                info["identity"]["domain"] == "lab"
                and info["identity"]["logon_type"] == "10"
            )
    client.put(
        "/api/settings", json={**DEFAULTS, "window_seconds": 180, "ssh_threshold": 6}
    )
    a = next(
        a
        for a in client.get("/api/alerts").json()["items"]
        if a["rule"] == "ssh_brute_force"
    )
    info = client.get("/api/alerts/" + a["id"]).json()["explanation"]
    assert (
        info["parameters"] == {"threshold": 6, "window_seconds": 180}
        and info["failure_count"] == 7
    )


def test_legacy_alert_explanation_without_rewriting_stored_body(client):
    from logsentinel.storage import connection

    client.post("/api/demo")
    with connection(client.app.state.db_path) as db:
        row = db.execute("select id,body from alerts limit 1").fetchone()
        body = json.loads(row["body"])
        body.pop("parameters")
        encoded = json.dumps(body)
        db.execute("update alerts set body=? where id=?", (encoded, row["id"]))
    a = client.get("/api/alerts/" + row["id"]).json()
    assert a["explanation"]["parameters"]["window_seconds"] == 300
    with connection(client.app.state.db_path) as db:
        assert (
            db.execute("select body from alerts where id=?", (row["id"],)).fetchone()[0]
            == encoded
        )


def test_removed_alert_returns_with_new_status(client):
    client.post("/api/demo")
    a = client.get("/api/alerts").json()["items"][0]
    client.patch("/api/alerts/" + a["id"], json={"status": "resolved"})
    client.put(
        "/api/settings",
        json={k: (3600 if k == "window_seconds" else 100) for k in DEFAULTS},
    )
    assert client.get("/api/alerts").json()["total"] == 0
    client.put("/api/settings", json=DEFAULTS)
    assert client.get("/api/alerts/" + a["id"]).json()["status"] == "new"
