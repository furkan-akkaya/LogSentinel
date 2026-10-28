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

from .detection import RULES, correlation_key
from .guidance import explain_alert
from .parsers import parse, timestamp
from .storage import connection, event_dict, ingest, initialize, reanalyze, settings

ROOT = Path(__file__).parent
MAX_UPLOAD = 5 * 1024 * 1024


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


def create_app(db_path=None):
    path = str(db_path or os.getenv("LOGSENTINEL_DB", "data/logsentinel.db"))

    @asynccontextmanager
    async def lifespan(app):
        initialize(path)
        yield

    app = FastAPI(
        title="LogSentinel",
        version="1.1.0",
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
        return {"status": "ok", "version": "1.1.0"}

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
            return item

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
