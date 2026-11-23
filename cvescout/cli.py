from __future__ import annotations

import os
import sqlite3
from importlib import resources
from pathlib import Path

import click
from flask import current_app
from werkzeug.security import generate_password_hash

from . import db, domain_scanner, exploit_intel, jobs

UNIT_PLACEHOLDERS = {"__PREFIX__": "/opt/cvescout", "__APP_USER__": "cvescout"}


def register(app) -> None:
    @app.cli.command("init-admin")
    @click.option("--username", prompt=True, default="admin")
    @click.password_option()
    def init_admin(username: str, password: str) -> None:
        """Create or replace an administrator account."""
        database = db.get_db()
        database.execute(
            "INSERT INTO users(username,password_hash,created_at) VALUES(?,?,?) "
            "ON CONFLICT(username) DO UPDATE SET password_hash=excluded.password_hash",
            (username, generate_password_hash(password), db.now()),
        )
        database.commit()
        click.echo(f"Administrator {username!r} ready")

    @app.cli.command("scan")
    @click.option(
        "--kind",
        required=True,
        type=click.Choice(["network", "devices", "ports", "vulnerabilities", "domains", "all"]),
    )
    @click.option("--device", "device_id", type=int, default=None, help="Limit port/vulnerability scan to one device id.")
    @click.option("--domain", "domain_name", default=None, help="Limit a domains scan to one hostname.")
    @click.option("--user", "username", default="cli", show_default=True, help="Name recorded in the audit log.")
    def scan(kind: str, device_id: int | None, domain_name: str | None, username: str) -> None:
        """Run one scan synchronously; suitable for cron or a systemd timer."""
        if kind == "all":
            if device_id is not None or domain_name:
                raise click.UsageError("--device and --domain do not apply to --kind all")
            _scan_all(username)
            return
        if kind == "domains":
            _scan_domains(domain_name, username)
            return
        if domain_name:
            raise click.UsageError("--domain only applies to --kind domains")
        try:
            status, message = jobs.run_scan_now(kind, device_id, username)
        except jobs.JobBusy as exc:
            raise click.ClickException(str(exc)) from exc
        if status != "completed":
            raise click.ClickException(message)
        click.echo(message)

    @app.cli.command("install-units")
    @click.option("--target", default="/etc/systemd/system", show_default=True, help="Directory to write unit files into.")
    @click.option("--prefix", "app_prefix", default=None, help="Install prefix used in the units.")
    @click.option("--user", "app_user", default=None, help="Service account used in the units.")
    def install_units(target: str, app_prefix: str | None, app_user: str | None) -> None:
        """Write the bundled systemd units with the given prefix and service account."""
        values = dict(UNIT_PLACEHOLDERS)
        if app_prefix:
            values["__PREFIX__"] = app_prefix
        if app_user:
            values["__APP_USER__"] = app_user
        destination = Path(target)
        destination.mkdir(parents=True, exist_ok=True)
        written = []
        units = resources.files("cvescout").joinpath("units")
        for unit in sorted(units.iterdir(), key=lambda item: item.name):
            if not unit.name.endswith((".service", ".timer")):
                continue
            text = unit.read_text()
            for placeholder, value in values.items():
                text = text.replace(placeholder, value)
            path = destination / unit.name
            path.write_text(text)
            path.chmod(0o644)
            written.append(path)
        if not written:
            raise click.ClickException("No bundled units found")
        for path in written:
            click.echo(f"Wrote {path}")
        click.echo("Next: systemctl daemon-reload")

    @app.cli.command("refresh-intel")
    def refresh_intel() -> None:
        """Refresh the CISA KEV catalogue and EPSS scores used to rank findings."""
        try:
            counts = exploit_intel.refresh_all(force_kev=True)
        except exploit_intel.IntelError as exc:
            raise click.ClickException(str(exc)) from exc
        click.echo(f"KEV entries stored: {counts['kev'] or 'unchanged'}; EPSS scores updated: {counts['epss']}")

    @app.cli.command("prune-history")
    @click.option("--days", type=int, default=None, help="Override CVESCOUT_HISTORY_DAYS for this run.")
    def prune_history(days: int | None) -> None:
        """Delete finished jobs, checks, and events older than the retention window."""
        keep = current_app.config["HISTORY_RETENTION_DAYS"] if days is None else days
        removed = db.prune_history(keep)
        click.echo(f"Removed {removed} history rows older than {keep} days")

    @app.cli.command("backup")
    @click.option(
        "--dest",
        required=True,
        type=click.Path(file_okay=False, path_type=Path),
        help="Directory to write cvescout.sqlite3 and secret_key into.",
    )
    def backup(dest: Path) -> None:
        """Back up the database online (WAL-safe) plus the session secret."""
        created = not dest.exists()
        dest.mkdir(parents=True, exist_ok=True)
        if created:
            dest.chmod(0o700)
        target = dest / "cvescout.sqlite3"
        source = sqlite3.connect(current_app.config["DATABASE"])
        try:
            backup_conn = sqlite3.connect(target)
            try:
                source.backup(backup_conn)
            finally:
                backup_conn.close()
        finally:
            source.close()
        target.chmod(0o600)
        secret = Path(os.getenv("CVESCOUT_SECRET_FILE", Path(current_app.instance_path) / "secret_key"))
        if secret.exists():
            secret_target = dest / "secret_key"
            secret_target.write_bytes(secret.read_bytes())
            secret_target.chmod(0o600)
        click.echo(f"Backup written to {dest}")


def _scan_domains(domain_name: str | None, username: str) -> None:
    database = db.get_db()
    if domain_name:
        rows = database.execute("SELECT id,name FROM domains WHERE name=?", (domain_scanner.normalize_domain(domain_name),)).fetchall()
        if not rows:
            raise click.ClickException(f"Domain {domain_name!r} is not configured")
    else:
        rows = database.execute("SELECT id,name FROM domains ORDER BY name").fetchall()
    if not rows:
        raise click.ClickException("No public hostnames configured")
    failures = []
    for row in rows:
        try:
            status, message = jobs.run_scan_now("domain", None, username, domain_id=row["id"])
        except jobs.JobBusy as exc:
            click.echo(f"{row['name']}: {exc}")
            failures.append(row["name"])
            continue
        click.echo(message)
        if status != "completed":
            failures.append(row["name"])
    if failures:
        raise click.ClickException(f"Domain scan failed for: {', '.join(failures)}")


def _scan_all(username: str) -> None:
    """Run the full pipeline in order; keep going past a failed stage, report at the end."""
    failures = []
    for kind in ("network", "devices", "ports", "vulnerabilities"):
        try:
            status, message = jobs.run_scan_now(kind, None, username)
        except jobs.JobBusy as exc:
            click.echo(f"{kind}: {exc}")
            failures.append(kind)
            continue
        click.echo(message)
        if status != "completed":
            failures.append(kind)
    if db.get_db().execute("SELECT 1 FROM domains LIMIT 1").fetchone():
        try:
            _scan_domains(None, username)
        except click.ClickException as exc:
            click.echo(f"domains: {exc.message}")
            failures.append("domains")
    else:
        click.echo("No public hostnames configured; skipped domain scans")
    if failures:
        raise click.ClickException(f"Scan pipeline failed for: {', '.join(failures)}")
