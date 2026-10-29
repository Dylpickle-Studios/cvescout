"""
Settings routes.
"""
from __future__ import annotations

from flask import (
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from .. import notify
from ..db import log_event
from ..notify import NotifyError
from . import bp


@bp.route("/settings", methods=("GET", "POST"))
def settings():
    if request.method == "POST":
        config = notify.from_form(request.form)
        errors = notify.validate(config)
        if errors:
            for error in errors:
                flash(error, "error")
            return render_template("settings.html", config=config, channels=notify.CHANNELS, secret_fields=notify.SECRET_FIELDS)
        notify.save(config)
        log_event("info", "settings.notifications", "Notification settings saved", username=session["user"])
        flash("Notification settings saved", "success")
        return redirect(url_for("main.settings"))
    return render_template(
        "settings.html",
        config=notify.load(),
        channels=notify.CHANNELS,
        secret_fields=notify.SECRET_FIELDS,
    )

@bp.post("/settings/test")
def test_notifications():
    try:
        failures = notify.send_test()
    except NotifyError as exc:
        flash(str(exc), "error")
        return redirect(url_for("main.settings"))
    if failures:
        for channel, error in failures.items():
            flash(f"{channel}: {error}", "error")
    else:
        flash("Test notification accepted by every enabled channel", "success")
    return redirect(url_for("main.settings"))
