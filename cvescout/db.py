from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

from flask import current_app, g

SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY,
    address TEXT NOT NULL UNIQUE,
    hostname TEXT NOT NULL DEFAULT '',
    mac TEXT NOT NULL DEFAULT '',
    vendor TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'up',
    last_seen TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ports (
    id INTEGER PRIMARY KEY,
    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    state TEXT NOT NULL,
    service TEXT NOT NULL DEFAULT '',
    product TEXT NOT NULL DEFAULT '',
    version TEXT NOT NULL DEFAULT '',
    extra_info TEXT NOT NULL DEFAULT '',
    cpe TEXT NOT NULL DEFAULT '',
    last_seen TEXT NOT NULL,
    UNIQUE(device_id, port, protocol)
);
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id INTEGER PRIMARY KEY,
    port_id INTEGER NOT NULL REFERENCES ports(id) ON DELETE CASCADE,
    cve_id TEXT NOT NULL,
    source TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'UNKNOWN',
    score REAL,
    summary TEXT NOT NULL DEFAULT '',
    url TEXT NOT NULL DEFAULT '',
    last_seen TEXT NOT NULL,
    UNIQUE(port_id, cve_id)
);
CREATE TABLE IF NOT EXISTS checks (
    id INTEGER PRIMARY KEY,
    vulnerability_id INTEGER NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    username TEXT NOT NULL,
    status TEXT NOT NULL,
    result TEXT NOT NULL DEFAULT '',
    details TEXT NOT NULL DEFAULT '',
    started_at TEXT NOT NULL,
    finished_at TEXT
);
CREATE TABLE IF NOT EXISTS jobs (
    id INTEGER PRIMARY KEY,
    kind TEXT NOT NULL,
    target TEXT NOT NULL DEFAULT '',
    username TEXT NOT NULL,
    status TEXT NOT NULL,
    message TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY,
    created_at TEXT NOT NULL,
    level TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL DEFAULT '',
    message TEXT NOT NULL,
    username TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS cve_cache (
    cpe TEXT PRIMARY KEY,
    payload TEXT NOT NULL,
    fetched_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS domains (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    provider TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'never',
    addresses TEXT NOT NULL DEFAULT '[]',
    dns_summary TEXT NOT NULL DEFAULT '{}',
    tls_summary TEXT NOT NULL DEFAULT '{}',
    http_summary TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    last_scanned TEXT
);
CREATE TABLE IF NOT EXISTS domain_findings (
    id INTEGER PRIMARY KEY,
    domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    finding_key TEXT NOT NULL,
    severity TEXT NOT NULL,
    category TEXT NOT NULL,
    title TEXT NOT NULL,
    detail TEXT NOT NULL,
    evidence TEXT NOT NULL DEFAULT '',
    remediation TEXT NOT NULL DEFAULT '',
    last_seen TEXT NOT NULL,
    UNIQUE(domain_id, finding_key)
);
CREATE TABLE IF NOT EXISTS domain_checks (
    id INTEGER PRIMARY KEY,
    domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    username TEXT NOT NULL,
    status TEXT NOT NULL,
    result TEXT NOT NULL DEFAULT '',
    summary TEXT NOT NULL DEFAULT '',
    details TEXT NOT NULL DEFAULT '{}',
    started_at TEXT NOT NULL,
    finished_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_ports_device ON ports(device_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_port ON vulnerabilities(port_id);
CREATE INDEX IF NOT EXISTS idx_domain_findings_domain ON domain_findings(domain_id);
CREATE INDEX IF NOT EXISTS idx_domain_checks_domain ON domain_checks(domain_id);
CREATE INDEX IF NOT EXISTS idx_events_created ON events(created_at DESC);
"""


# Schema changes are numbered and applied once per database. Add a new entry (never edit an old
# one) when the schema changes; ALTER TABLE steps are safe because each version runs only below it.
# Version 1 is the baseline and stays idempotent for databases created before versioning.
MIGRATIONS: dict[int, str] = {
    1: SCHEMA,
    2: """
    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    """,
    3: """
    ALTER TABLE vulnerabilities ADD COLUMN match_type TEXT NOT NULL DEFAULT 'exact';
    CREATE TABLE IF NOT EXISTS exploit_intel (
        cve_id TEXT PRIMARY KEY,
        kev INTEGER NOT NULL DEFAULT 0,
        epss REAL,
        checked_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cve ON vulnerabilities(cve_id);
    """,
    4: """
    ALTER TABLE vulnerabilities ADD COLUMN first_seen TEXT;
    ALTER TABLE vulnerabilities ADD COLUMN resolved_at TEXT;
    ALTER TABLE domain_findings ADD COLUMN first_seen TEXT;
    ALTER TABLE domain_findings ADD COLUMN resolved_at TEXT;
    UPDATE vulnerabilities SET first_seen = last_seen WHERE first_seen IS NULL;
    UPDATE domain_findings SET first_seen = last_seen WHERE first_seen IS NULL;
    """,
}


def now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def max_version() -> int:
    return max(MIGRATIONS)


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        database = Path(current_app.config["DATABASE"])
        database.parent.mkdir(parents=True, exist_ok=True)
        g.db = sqlite3.connect(database, timeout=30)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
        g.db.execute("PRAGMA journal_mode = WAL")
    return g.db


def close_db(_error=None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def _migrate(db: sqlite3.Connection) -> int:
    version = db.execute("PRAGMA user_version").fetchone()[0]
    for target in sorted(MIGRATIONS):
        if target <= version:
            continue
        db.executescript(MIGRATIONS[target])
        # PRAGMA does not accept bound parameters; the value comes from our own keys.
        db.execute(f"PRAGMA user_version = {int(target)}")
        db.commit()
        version = target
    return version


def init_db() -> None:
    db = get_db()
    _migrate(db)
    timestamp = now()
    db.execute(
        "UPDATE jobs SET status='failed', message='Application restarted', finished_at=? WHERE status IN ('queued','running')",
        (timestamp,),
    )
    db.execute(
        "UPDATE domain_checks SET status='failed', summary='Application restarted', finished_at=? WHERE status IN ('queued','running')",
        (timestamp,),
    )
    db.execute(
        "UPDATE checks SET status='failed', details='Application restarted', finished_at=? WHERE status IN ('queued','running')",
        (timestamp,),
    )
    db.commit()


def log_event(level: str, action: str, message: str, target: str = "", username: str = "") -> None:
    db = get_db()
    db.execute(
        "INSERT INTO events(created_at, level, action, target, message, username) VALUES(?,?,?,?,?,?)",
        (now(), level, action, target, message, username),
    )
    db.commit()


def prune_history(days: int) -> int:
    """Delete finished history older than `days`. Avoids unbounded growth on small storage."""
    if days <= 0:
        return 0
    cutoff = (datetime.now(UTC) - timedelta(days=days)).replace(microsecond=0).isoformat()
    db = get_db()
    removed = 0
    for statement in (
        "DELETE FROM events WHERE created_at < ?",
        "DELETE FROM jobs WHERE status IN ('completed','failed') AND created_at < ?",
        "DELETE FROM checks WHERE status IN ('completed','failed') AND started_at < ?",
        "DELETE FROM domain_checks WHERE status IN ('completed','failed') AND started_at < ?",
    ):
        removed += db.execute(statement, (cutoff,)).rowcount
    db.commit()
    return removed


def init_app(app) -> None:
    app.teardown_appcontext(close_db)
    with app.app_context():
        init_db()
        prune_history(app.config["HISTORY_RETENTION_DAYS"])
