"""Single-process local web application. No host log privileges required."""

from contextlib import asynccontextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
from typing import Literal

from fastapi import FastAPI, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .detection import RULES, correlation_key, detect
from .guidance import explain_alert
from .lab import MAX_REPLAY_EVENTS, SCENARIOS, replay, scenario_events
from .parsers import parse, timestamp
from .provenance import dataset_summary
from .storage import connection, event_dict, ingest, initialize, reanalyze, settings

ROOT = Path(__file__).parent
MAX_UPLOAD = 5 * 1024 * 1024
MAX_NOTE_EVIDENCE = 200


class LocalBoundary:
    """Bound request bodies before multipart parsing; reject cross-origin writes."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = dict(scope["headers"])
        mutating = scope["method"] in ("POST", "PUT", "PATCH", "DELETE")
        origin = headers.get(b"origin")
        host = headers.get(b"host", b"").decode()
        if (
            mutating
            and origin
            and origin.decode() != f"{scope.get('scheme', 'http')}://{host}"
        ):
            return await JSONResponse(
                {"detail": "Cross-origin writes are disabled"}, 403
            )(scope, receive, send)
        if mutating:
            chunks, size = [], 0
            while True:
                message = await receive()
                if message["type"] == "http.disconnect":
                    return
                size += len(message.get("body", b""))
                if size > MAX_UPLOAD + 65_536:
                    return await JSONResponse(
                        {"detail": "Request exceeds 5 MiB upload limit"}, 413
                    )(scope, receive, send)
                chunks.append(message.get("body", b""))
                if not message.get("more_body"):
                    break
            delivered = False

            async def replay():
                nonlocal delivered
                if not delivered:
                    delivered = True
                    return {
                        "type": "http.request",
                        "body": b"".join(chunks),
                        "more_body": False,
                    }
                return await receive()

            await self.app(scope, replay, send)
        else:
            await self.app(scope, receive, send)


class RuleSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    ssh_threshold: int = Field(default=5, ge=2, le=100)
    windows_threshold: int = Field(default=5, ge=2, le=100)
    sudo_threshold: int = Field(default=3, ge=2, le=100)
    success_threshold: int = Field(default=3, ge=2, le=100)
    window_seconds: int = Field(default=300, ge=10, le=3600)


class AlertStatus(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["new", "investigating", "resolved"]


class ReplayRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    scenario: str | None = Field(default=None, max_length=80)
    alert_id: str | None = Field(default=None, max_length=64)
    settings: RuleSettings


class AnalystNote(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    assessment: Literal["undetermined", "likely_benign", "suspicious"] = "undetermined"
    observation: str = Field(default="", max_length=4000)
    hypothesis: str = Field(default="", max_length=4000)
    next_step: str = Field(default="", max_length=4000)


def create_app(db_path=None):
    path = str(db_path or os.getenv("LOGSENTINEL_DB", "data/logsentinel.db"))

    @asynccontextmanager
    async def lifespan(app):
        initialize(path)
        yield

    app = FastAPI(
        title="LogSentinel",
        version="1.2.0",
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        telemetry={
            "tracing": False,
            "metrics": False,
            "logs": False,
            "operation_spans": False,
            "auto_configure": False,
        },
    )
    app.state.db_path = path
    app.add_middleware(LocalBoundary)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["localhost", "127.0.0.1"])

    @app.middleware("http")
    async def security_headers(request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        )
        return response

    @app.exception_handler(sqlite3.OperationalError)
    async def storage_error(request, exc):
        return JSONResponse(
            {
                "detail": "Storage unavailable or busy; retry or inspect local database permissions"
            },
            503,
        )

    @app.get("/api/health")
    def health():
        with connection(path) as db:
            db.execute("SELECT count(*) FROM events").fetchone()
        return {"status": "ok", "version": "1.2.0"}

    @app.post("/api/import")
    def import_logs(
        file: UploadFile = File(...),
        format: Literal["auto", "linux", "json", "xml"] = Form("auto"),
        year: int = Form(datetime.now(timezone.utc).year),
        timezone_offset: str = Form("+00:00"),
    ):
        content = file.file.read(MAX_UPLOAD + 1)
        if len(content) > MAX_UPLOAD:
            raise HTTPException(413, "File exceeds 5 MiB")
        try:
            parsed = parse(content.decode("utf-8-sig"), format, year, timezone_offset)
            with connection(path) as db:
                result = ingest(
                    db, parsed.events, Path(file.filename or "upload").name[:200]
                )
        except UnicodeDecodeError:
            raise HTTPException(
                400,
                "Use UTF-8 Linux text, Windows XML or JSON; binary EVTX is unsupported",
            )
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        return {
            **result,
            "rejected": parsed.rejected,
            "ignored": parsed.ignored,
            "errors": parsed.errors,
            "time_context": {"year": year, "timezone_offset": timezone_offset},
        }

    @app.post("/api/demo")
    def demo():
        events, rejected, ignored = [], 0, 0
        for name, fmt in [
            ("linux-auth.log", "linux"),
            ("windows-security.json", "json"),
        ]:
            parsed = parse((ROOT / "demo" / name).read_text(), fmt)
            events.extend(parsed.events)
            rejected += parsed.rejected
            ignored += parsed.ignored
        try:
            with connection(path) as db:
                result = ingest(db, events, "bundled synthetic demo")
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        return {**result, "rejected": rejected, "ignored": ignored, "errors": []}

    @app.get("/api/settings")
    def get_settings():
        with connection(path) as db:
            return {
                "settings": settings(db),
                "rules": [
                    {"id": key, "title": v[0], "severity": v[1], "mitre": v[2]}
                    for key, v in RULES.items()
                ],
            }

    @app.put("/api/settings")
    def put_settings(value: RuleSettings):
        with connection(path) as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                "UPDATE config SET body=? WHERE id=1", (json.dumps(value.model_dump()),)
            )
            count = reanalyze(db)
        return {"settings": value.model_dump(), "alerts_total": count}

    @app.get("/api/events")
    def events(
        q: str = Query("", max_length=200),
        source: Literal["linux", "windows"] | None = None,
        event_type: str = Query("", max_length=80),
        source_ip: str = Query("", max_length=64),
        user: str = Query("", max_length=200),
        host: str = Query("", max_length=200),
        start: str | None = None,
        end: str | None = None,
        limit: int = Query(50, ge=1, le=200),
        offset: int = Query(0, ge=0),
    ):
        clauses, args = [], []
        for field, value in [
            ("source", source),
            ("event_type", event_type),
            ("source_ip", source_ip),
            ("user", user),
            ("host", host),
        ]:
            if value:
                clauses.append(f"{field}=?")
                args.append(value)
        try:
            if start:
                clauses.append("timestamp>=?")
                args.append(timestamp(start))
            if end:
                clauses.append("timestamp<=?")
                args.append(timestamp(end))
            if start and end and timestamp(start) > timestamp(end):
                raise ValueError("Start must precede end")
        except (ValueError, TypeError):
            raise HTTPException(422, "Invalid date range; use ISO 8601")
        if q:
            clauses.append(
                "(instr(lower(raw), lower(?))>0 OR instr(lower(host), lower(?))>0 OR instr(lower(coalesce(user,'')), lower(?))>0)"
            )
            args.extend([q, q, q])
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        with connection(path) as db:
            total = db.execute("SELECT count(*) FROM events" + where, args).fetchone()[
                0
            ]
            rows = db.execute(
                "SELECT * FROM events"
                + where
                + " ORDER BY timestamp DESC,id LIMIT ? OFFSET ?",
                args + [limit, offset],
            )
            items = [event_dict(row) for row in rows]
        return {"total": total, "items": items, "limit": limit, "offset": offset}

    @app.get("/api/events/{identifier}")
    def event_detail(identifier: str):
        with connection(path) as db:
            row = db.execute(
                "SELECT * FROM events WHERE id=?", (identifier,)
            ).fetchone()
            if row is None:
                raise HTTPException(404, "Event not found")
            return event_dict(row)

    @app.get("/api/alerts")
    def alerts(
        severity: Literal["critical", "high", "medium"] | None = None,
        status: Literal["new", "investigating", "resolved"] | None = None,
        limit: int = Query(50, ge=1, le=200),
        offset: int = Query(0, ge=0),
    ):
        with connection(path) as db:
            items = [
                {**json.loads(row["body"]), "status": row["status"]}
                for row in db.execute("SELECT * FROM alerts")
            ]
        items = [
            a
            for a in items
            if (not severity or a["severity"] == severity)
            and (not status or a["status"] == status)
        ]
        items.sort(key=lambda a: (a["last_seen"], a["id"]), reverse=True)
        return {"total": len(items), "items": items[offset : offset + limit]}

    @app.get("/api/alerts/{identifier}")
    def alert_detail(identifier: str):
        with connection(path) as db:
            # One read snapshot keeps legacy alert parameters consistent with
            # their evidence/config even during an overlapping settings update.
            db.execute("BEGIN")
            row = db.execute(
                "SELECT * FROM alerts WHERE id=?", (identifier,)
            ).fetchone()
            if row is None:
                raise HTTPException(404, "Alert not found")
            item = {**json.loads(row["body"]), "status": row["status"]}
            # Separate indexed queries avoid SQLite variable limits for long episodes.
            item["events"] = [
                event_dict(
                    db.execute("SELECT * FROM events WHERE id=?", (eid,)).fetchone()
                )
                for eid in item["evidence"]
            ]
            item["explanation"] = explain_alert(item, item["events"], settings(db))
            item["dataset"] = dataset_summary(item["events"])
            note = db.execute(
                "SELECT body FROM notebooks WHERE alert_id=?", (identifier,)
            ).fetchone()
            item["notebook"] = json.loads(note["body"]) if note else None
            return item

    @app.get("/api/lab")
    def lab_catalog():
        return {"scenarios": SCENARIOS, "max_evidence_records": MAX_REPLAY_EVENTS}

    @app.post("/api/lab/replay")
    def lab_replay(value: ReplayRequest):
        if bool(value.scenario) == bool(value.alert_id):
            raise HTTPException(422, "Choose exactly one scenario or alert_id")
        if value.alert_id:
            with connection(path) as db:
                db.execute("BEGIN")
                row = db.execute(
                    "SELECT body FROM alerts WHERE id=?", (value.alert_id,)
                ).fetchone()
                if row is None:
                    raise HTTPException(404, "Alert not found")
                alert = json.loads(row["body"])
                baseline = settings(db)
                if len(alert["evidence"]) > MAX_REPLAY_EVENTS:
                    raise HTTPException(
                        422,
                        f"Replay supports at most {MAX_REPLAY_EVENTS} evidence records; this alert is too large",
                    )
                events = [
                    event_dict(
                        db.execute("SELECT * FROM events WHERE id=?", (eid,)).fetchone()
                    )
                    for eid in alert["evidence"]
                ]
            scope = {
                "kind": "alert_evidence",
                "alert_id": value.alert_id,
                "title": alert["title"],
                "dataset": dataset_summary(events),
                "limits": "Only this alert's saved evidence is replayed. Other stored events are excluded. This is not a coverage or false-positive measurement.",
            }
        else:
            try:
                events = scenario_events(value.scenario)
            except ValueError as exc:
                raise HTTPException(422, str(exc))
            scope = {
                "kind": "synthetic_scenario",
                "scenario": value.scenario,
                "title": next(
                    s["title"] for s in SCENARIOS if s["id"] == value.scenario
                ),
                "limits": "Synthetic records in an isolated experiment. They are never imported into your workspace.",
            }
            with connection(path) as db:
                baseline = settings(db)
        return {
            **replay(events, value.settings.model_dump()),
            "scope": scope,
            "baseline": {
                "settings": baseline,
                "alerts_total": len(detect(events, baseline)),
            },
        }

    @app.put("/api/alerts/{identifier}/notebook")
    def save_notebook(identifier: str, value: AnalystNote):
        with connection(path) as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT * FROM alerts WHERE id=?", (identifier,)
            ).fetchone()
            if row is None:
                raise HTTPException(404, "Alert not found")
            alert = {**json.loads(row["body"]), "status": row["status"]}
            evidence_ids = alert["evidence"]
            snapshot_ids = (
                evidence_ids
                if len(evidence_ids) <= MAX_NOTE_EVIDENCE
                else evidence_ids[: MAX_NOTE_EVIDENCE - 1] + evidence_ids[-1:]
            )
            events = [
                event_dict(
                    db.execute("SELECT * FROM events WHERE id=?", (eid,)).fetchone()
                )
                for eid in snapshot_ids
            ]
            item = {
                "alert_id": identifier,
                "saved_at": datetime.now(timezone.utc).isoformat(),
                "note": value.model_dump(),
                "alert": alert,
                "events": events,
                "snapshot_policy": "all"
                if len(evidence_ids) <= MAX_NOTE_EVIDENCE
                else "first_and_final",
                "evidence_omitted": max(0, len(alert["evidence"]) - len(events)),
                "scope": "Manual analyst notes and a bounded evidence snapshot. Not a verified verdict or an audit history.",
            }
            db.execute(
                "INSERT INTO notebooks VALUES (?,?) ON CONFLICT(alert_id) DO UPDATE SET body=excluded.body",
                (identifier, json.dumps(item)),
            )
        return item

    @app.get("/api/notebooks")
    def notebooks():
        with connection(path) as db:
            items = []
            for row in db.execute(
                "SELECT notebooks.body, alerts.id AS active_id FROM notebooks LEFT JOIN alerts ON alerts.id=notebooks.alert_id"
            ):
                note = json.loads(row["body"])
                items.append(
                    {
                        "alert_id": note["alert_id"],
                        "title": note["alert"]["title"],
                        "saved_at": note["saved_at"],
                        "assessment": note["note"]["assessment"],
                        "active": row["active_id"] is not None,
                    }
                )
        return {"items": sorted(items, key=lambda n: n["saved_at"], reverse=True)}

    @app.get("/api/notebooks/{identifier}")
    def notebook_detail(identifier: str):
        with connection(path) as db:
            row = db.execute(
                "SELECT body FROM notebooks WHERE alert_id=?", (identifier,)
            ).fetchone()
            if row is None:
                raise HTTPException(404, "Notebook not found")
            return json.loads(row["body"])

    @app.patch("/api/alerts/{identifier}")
    def update_alert(identifier: str, value: AlertStatus):
        with connection(path) as db:
            changed = db.execute(
                "UPDATE alerts SET status=? WHERE id=?", (value.status, identifier)
            ).rowcount
            if not changed:
                raise HTTPException(404, "Alert not found")
        return {"status": value.status}

    @app.get("/api/stats")
    def stats():
        with connection(path) as db:
            db.execute("BEGIN")
            count = db.execute("SELECT count(*) FROM events").fetchone()[0]
            hosts = db.execute("SELECT count(DISTINCT host) FROM events").fetchone()[0]
            latest = db.execute("SELECT max(timestamp) FROM events").fetchone()[0]
            sources = dict(
                db.execute("SELECT source,count(*) FROM events GROUP BY source")
            )
            event_timeline = dict(
                db.execute(
                    "SELECT substr(timestamp,1,13),count(*) FROM events GROUP BY substr(timestamp,1,13) ORDER BY 1"
                )
            )
            alerts = [
                {**json.loads(r["body"]), "status": r["status"]}
                for r in db.execute("SELECT * FROM alerts")
            ]
            gaps = sum(
                correlation_key(event_dict(r)) is None
                for r in db.execute("SELECT * FROM events")
            )
            dataset = dataset_summary(
                [dict(r) for r in db.execute("SELECT id FROM events")]
            )
        severity = {
            key: sum(a["severity"] == key for a in alerts)
            for key in ("critical", "high", "medium")
        }
        alert_timeline = {}
        for a in alerts:
            hour = a["last_seen"][:13]
            alert_timeline[hour] = alert_timeline.get(hour, 0) + 1
        return {
            "events": count,
            "dataset": dataset,
            "alerts": len(alerts),
            "hosts": hosts,
            "latest_event": latest,
            "sources": sources,
            "severity": severity,
            "uncorrelated_events": gaps,
            "open_alerts": sum(a["status"] != "resolved" for a in alerts),
            "timeline": [
                {
                    "hour": h + ":00:00Z",
                    "events": event_timeline.get(h, 0),
                    "alerts": alert_timeline.get(h, 0),
                }
                for h in sorted(set(event_timeline) | set(alert_timeline))
            ],
            "recent_alerts": sorted(alerts, key=lambda a: a["last_seen"], reverse=True)[
                :5
            ],
        }

    app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(ROOT / "static" / "index.html")

    @app.get("/docs", include_in_schema=False)
    def api_docs():
        return FileResponse(ROOT / "static" / "api.html")

    return app


app = create_app()
