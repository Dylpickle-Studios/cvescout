from __future__ import annotations

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
        type=click.Choice(["network", "devices", "ports", "vulnerabilities", "domains"]),
    )
    @click.option("--device", "device_id", type=int, default=None, help="Limit port/vulnerability scan to one device id.")
    @click.option("--domain", "domain_name", default=None, help="Limit a domains scan to one hostname.")
    @click.option("--user", "username", default="cli", show_default=True, help="Name recorded in the audit log.")
    def scan(kind: str, device_id: int | None, domain_name: str | None, username: str) -> None:
        """Run one scan synchronously; suitable for cron or a systemd timer."""
        if kind == "domains":
            _scan_domains(domain_name, username)
            return
        if domain_name:
            raise click.UsageError("--domain only applies to --kind domains")
        status, message = jobs.run_scan_now(kind, device_id, username)
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
        for unit in sorted(resources.files("cvescout").joinpath("units").iterdir()):
            if unit.suffix not in {".service", ".timer"}:
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
        status, message = jobs.run_scan_now("domain", None, username, domain_id=row["id"])
        click.echo(message)
        if status != "completed":
            failures.append(row["name"])
    if failures:
        raise click.ClickException(f"Domain scan failed for: {', '.join(failures)}")
