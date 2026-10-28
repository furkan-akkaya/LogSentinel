"""SQLite persistence; imports and detection updates commit atomically."""

from contextlib import contextmanager
import json
import os
from pathlib import Path
import sqlite3

from .detection import DEFAULTS, detect

MAX_EVENTS = 50_000


@contextmanager
def connection(path):
    db = sqlite3.connect(path, timeout=30)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def initialize(path):
    Path(path).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with connection(path) as db:
        if os.name == "posix":
            os.chmod(path, 0o600)
        db.execute("PRAGMA journal_mode=WAL")
        db.executescript("""
        CREATE TABLE IF NOT EXISTS events (
          id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, source TEXT NOT NULL,
          event_type TEXT NOT NULL, host TEXT NOT NULL, user TEXT, source_ip TEXT,
          raw TEXT NOT NULL, metadata TEXT NOT NULL, filename TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS events_time ON events(timestamp);
        CREATE INDEX IF NOT EXISTS events_type ON events(event_type);
        CREATE TABLE IF NOT EXISTS alerts (
          id TEXT PRIMARY KEY, body TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'new'
        );
        CREATE TABLE IF NOT EXISTS config (id INTEGER PRIMARY KEY CHECK(id=1), body TEXT NOT NULL);
        """)
        db.execute(
            "INSERT OR IGNORE INTO config VALUES (1, ?)", (json.dumps(DEFAULTS),)
        )


def event_dict(row):
    value = dict(row)
    value["metadata"] = json.loads(value["metadata"])
    return value


def settings(db):
    return json.loads(db.execute("SELECT body FROM config WHERE id=1").fetchone()[0])


def reanalyze(db):
    events = [
        event_dict(row)
        for row in db.execute("SELECT * FROM events ORDER BY timestamp,id")
    ]
    alerts = detect(events, settings(db))
    statuses = dict(db.execute("SELECT id,status FROM alerts"))
    db.execute("DELETE FROM alerts")
    db.executemany(
        "INSERT INTO alerts VALUES (?,?,?)",
        [(a["id"], json.dumps(a), statuses.get(a["id"], "new")) for a in alerts],
    )
    return len(alerts)


def ingest(db, events, filename):
    db.execute("BEGIN IMMEDIATE")
    before = db.execute("SELECT count(*) FROM events").fetchone()[0]
    inserted = 0
    for e in events:
        inserted += db.execute(
            "INSERT OR IGNORE INTO events VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                e.id,
                e.timestamp,
                e.source,
                e.event_type,
                e.host,
                e.user,
                e.source_ip,
                e.raw,
                json.dumps(e.metadata),
                filename,
            ),
        ).rowcount
    if before + inserted > MAX_EVENTS:
        raise ValueError(f"Local event limit is {MAX_EVENTS}; use a fresh database")
    count = (
        reanalyze(db)
        if inserted
        else db.execute("SELECT count(*) FROM alerts").fetchone()[0]
    )
    return {
        "inserted": inserted,
        "duplicates": len(events) - inserted,
        "alerts_total": count,
    }
