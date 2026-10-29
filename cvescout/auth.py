from __future__ import annotations

import hmac
import secrets
import threading
import time
from functools import wraps

from flask import (
    Blueprint,
    abort,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash

from .db import get_db, log_event

bp = Blueprint("auth", __name__)

# shortcut: throttle state is per process, so it resets on restart and does not cover multiple workers.
# Upgrade to a shared store only if the app stops running as one process.
LOGIN_MAX_FAILURES = 5
LOGIN_WINDOW_SECONDS = 15 * 60
_login_failures: dict[str, list[float]] = {}
_login_lock = threading.Lock()


def _login_key(username: str) -> str:
    return f"{request.remote_addr or 'unknown'}|{username.lower()}"


def _throttled(key: str) -> bool:
    cutoff = time.monotonic() - LOGIN_WINDOW_SECONDS
    with _login_lock:
        return len([stamp for stamp in _login_failures.get(key, []) if stamp > cutoff]) >= LOGIN_MAX_FAILURES


def _record_failure(key: str) -> bool:
    """Return True only when this failure first crosses the limit, to avoid log spam."""
    cutoff = time.monotonic() - LOGIN_WINDOW_SECONDS
    with _login_lock:
        if len(_login_failures) > 512:
            for stale in [name for name, stamps in _login_failures.items() if max(stamps, default=0) <= cutoff]:
                del _login_failures[stale]
        recent = [stamp for stamp in _login_failures.get(key, []) if stamp > cutoff]
        recent.append(time.monotonic())
        _login_failures[key] = recent
        return len(recent) == LOGIN_MAX_FAILURES


def _clear_failures(key: str) -> None:
    with _login_lock:
        _login_failures.pop(key, None)


def csrf_token() -> str:
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def verify_csrf() -> None:
    expected = session.get("csrf_token", "")
    supplied = request.form.get("csrf_token", "") or request.headers.get("X-CSRF-Token", "")
    if not expected or not hmac.compare_digest(expected, supplied):
        abort(400, "Invalid CSRF token")


def login_required(view):
    @wraps(view)
    def wrapped(**kwargs):
        if not session.get("user"):
            return redirect(url_for("auth.login", next=request.full_path))
        return view(**kwargs)

    return wrapped


@bp.route("/login", methods=("GET", "POST"))
def login():
    if request.method == "POST":
        verify_csrf()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        key = _login_key(username)
        if _throttled(key):
            flash("Too many failed attempts. Try again later.", "error")
            return render_template("login.html"), 429
        user = get_db().execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if not user or not check_password_hash(user["password_hash"], password):
            log_event("warning", "login", "Failed login", username=username)
            if _record_failure(key):
                log_event("warning", "login.rate_limited", "Login temporarily locked after repeated failures", username=username)
            flash("Invalid username or password", "error")
        else:
            _clear_failures(key)
            session.clear()
            session.permanent = True
            session["user"] = username
            csrf_token()
            log_event("info", "login", "Login successful", username=username)
            return redirect(url_for("main.dashboard"))
    return render_template("login.html")


@bp.post("/logout")
@login_required
def logout():
    verify_csrf()
    username = session.get("user", "")
    session.clear()
    log_event("info", "logout", "Logout successful", username=username)
    return redirect(url_for("auth.login"))
