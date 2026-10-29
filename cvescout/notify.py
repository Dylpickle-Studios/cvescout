"""Notification channels: webhook, ntfy, gotify, and a JSON email API.

Configuration is stored in the `settings` table and edited on the settings page.
Channel URLs are admin-supplied on purpose: self-hosted ntfy and gotify usually live
on the LAN, so private addresses must work. Only the scheme is enforced.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request

from flask import current_app

from .db import get_db, log_event, now
from .version import __version__

CHANNELS = ("webhook", "ntfy", "gotify", "email")

DEFAULTS: dict[str, dict] = {
    "webhook": {"enabled": False, "url": ""},
    "ntfy": {"enabled": False, "url": "", "token": ""},
    "gotify": {"enabled": False, "url": "", "token": ""},
    "email": {"enabled": False, "url": "", "token": "", "from": "", "to": ""},
}
SECRET_FIELDS = ("token",)
REQUIRED_FIELDS = {"webhook": ("url",), "ntfy": ("url",), "gotify": ("url", "token"), "email": ("url", "from", "to")}

# ntfy priorities are 1-5, gotify priorities 0-10.
PRIORITIES = {
    "default": (3, 4),
    "high": (4, 8),
    "low": (2, 2),
}


class NotifyError(RuntimeError):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


def _scrub(text: str, secrets: tuple[str, ...]) -> str:
    for secret in secrets:
        if secret:
            text = text.replace(secret, "<redacted>")
    return text


def load() -> dict[str, dict]:
    stored = {}
    for row in get_db().execute("SELECT key,value FROM settings WHERE key LIKE 'notify.%'"):
        stored[row["key"].removeprefix("notify.")] = json.loads(row["value"])
    return {name: {**DEFAULTS[name], **stored.get(name, {})} for name in CHANNELS}


def save(config: dict[str, dict]) -> None:
    db = get_db()
    timestamp = now()
    for name in CHANNELS:
        db.execute(
            "INSERT INTO settings(key,value,updated_at) VALUES(?,?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at",
            (f"notify.{name}", json.dumps(config[name]), timestamp),
        )
    db.commit()


def from_form(form, current: dict[str, dict] | None = None) -> dict[str, dict]:
    """Build config from the settings form. Blank secret fields keep the stored value."""
    current = current or load()
    config = {}
    for name in CHANNELS:
        values = {"enabled": form.get(f"{name}.enabled") == "yes"}
        for field in DEFAULTS[name]:
            if field == "enabled":
                continue
            supplied = (form.get(f"{name}.{field}") or "").strip()
            if field in SECRET_FIELDS and not supplied:
                supplied = current[name].get(field, "")
            values[field] = supplied
        config[name] = values
    return config


def validate(config: dict[str, dict]) -> list[str]:
    errors = []
    for name in CHANNELS:
        values = config[name]
        if not values.get("enabled"):
            continue
        for field in REQUIRED_FIELDS[name]:
            if not values.get(field):
                errors.append(f"{name}: {field} is required when enabled")
        url = values.get("url", "")
        if url and not url.lower().startswith(("http://", "https://")):
            errors.append(f"{name}: url must start with http:// or https://")
    return errors


def _post(url: str, body: bytes, headers: dict[str, str], secrets: tuple[str, ...] = ()) -> None:
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        opener = urllib.request.build_opener(_NoRedirect())
        with opener.open(request, timeout=current_app.config["NOTIFY_TIMEOUT"]) as response:
            response.read(4096)
    except urllib.error.HTTPError as exc:
        raise NotifyError(_scrub(f"HTTP {exc.code} from {url}", secrets)) from exc
    except OSError as exc:
        raise NotifyError(_scrub(str(exc), secrets)) from exc


def _json_body(payload: dict) -> tuple[bytes, dict[str, str]]:
    return (
        json.dumps(payload).encode(),
        {"Content-Type": "application/json", "User-Agent": f"CVE-Scout/{__version__}"},
    )


def _send_webhook(values: dict, title: str, message: str, priority: str) -> None:
    body, headers = _json_body(
        {"source": "cve-scout", "title": title, "message": message, "priority": priority}
    )
    _post(values["url"], body, headers)


def _send_ntfy(values: dict, title: str, message: str, priority: str) -> None:
    headers = {
        "Title": title.encode("ascii", "replace").decode("ascii"),
        "Priority": str(PRIORITIES.get(priority, PRIORITIES["default"])[0]),
        "User-Agent": f"CVE-Scout/{__version__}",
    }
    if values.get("token"):
        headers["Authorization"] = f"Bearer {values['token']}"
    _post(values["url"], message.encode(), headers, (values.get("token", ""),))


def _send_gotify(values: dict, title: str, message: str, priority: str) -> None:
    token = values["token"]
    url = f"{values['url'].rstrip('/')}/message?{urllib.parse.urlencode({'token': token})}"
    body, headers = _json_body(
        {"title": title, "message": message, "priority": PRIORITIES.get(priority, PRIORITIES["default"])[1]}
    )
    _post(url, body, headers, (token,))


def _send_email(values: dict, title: str, message: str, priority: str) -> None:
    body, headers = _json_body(
        {
            "from": values["from"],
            "to": [address.strip() for address in values["to"].split(",") if address.strip()],
            "subject": title,
            "text": message,
        }
    )
    if values.get("token"):
        headers["Authorization"] = f"Bearer {values['token']}"
    _post(values["url"], body, headers, (values.get("token", ""),))


SENDERS = {
    "webhook": _send_webhook,
    "ntfy": _send_ntfy,
    "gotify": _send_gotify,
    "email": _send_email,
}


def send(channel: str, values: dict, title: str, message: str, priority: str = "default") -> None:
    SENDERS[channel](values, title, message, priority)


def notify(title: str, message: str, priority: str = "default") -> dict[str, str]:
    """Send to every enabled channel. Returns channel -> error for failures; never raises."""
    failures = {}
    for name, values in load().items():
        if not values.get("enabled"):
            continue
        try:
            send(name, values, title, message, priority)
        except NotifyError as exc:
            # Scrub again here: a sender may build a URL containing its own token.
            error = _scrub(str(exc), tuple(values.get(field, "") for field in SECRET_FIELDS))
            failures[name] = error
            log_event("warning", "notify.failed", f"{name} notification failed: {error}", name)
    return failures


def send_test() -> dict[str, str]:
    enabled = [name for name, values in load().items() if values.get("enabled")]
    if not enabled:
        raise NotifyError("Enable at least one notification channel first")
    failures = notify("CVE Scout test", "Notifications are configured correctly.", "default")
    log_event("info", "notify.test", f"Test notification sent; {len(failures)} failed", ",".join(enabled))
    return failures
