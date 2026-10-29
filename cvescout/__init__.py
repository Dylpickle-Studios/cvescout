from __future__ import annotations

import os
from datetime import timedelta
from pathlib import Path

from flask import Flask, request, session

from . import auth, cli, db
from .config import configured_networks, load_or_create_secret
from .platform import choose as choose_profile
from .version import __version__ as __version__


def create_app(test_config: dict | None = None) -> Flask:
    profile = choose_profile()
    app = Flask(__name__, instance_relative_config=True)
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    app.config.from_mapping(
        SECRET_KEY=load_or_create_secret(app.instance_path),
        DATABASE=str(Path(app.instance_path) / "cvescout.sqlite3"),
        NETWORKS=configured_networks(),
        MAX_NETWORK_HOSTS=int(os.getenv("CVESCOUT_MAX_HOSTS", "1024")),
        NMAP=os.getenv("CVESCOUT_NMAP", "nmap"),
        NMAP_TIMING=profile.timing,
        PORTS=profile.ports,
        WORKERS=profile.workers,
        PROFILE=profile,
        NVD_API=os.getenv("CVESCOUT_NVD_API", "https://services.nvd.nist.gov/rest/json/cves/2.0"),
        NVD_API_KEY=os.getenv("CVESCOUT_NVD_API_KEY", ""),
        NVD_CACHE_HOURS=int(os.getenv("CVESCOUT_NVD_CACHE_HOURS", "24")),
        CVE_SOURCES=[name.strip().lower() for name in os.getenv("CVESCOUT_CVE_SOURCES", "nvd,circl").split(",") if name.strip()],
        CIRCL_API=os.getenv("CVESCOUT_CIRCL_API", "https://vulnerability.circl.lu/api"),
        KEV_URL=os.getenv("CVESCOUT_KEV_URL", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"),
        EPSS_API=os.getenv("CVESCOUT_EPSS_API", "https://api.first.org/data/v1/epss"),
        INTEL_REFRESH_HOURS=int(os.getenv("CVESCOUT_INTEL_HOURS", "24")),
        SCAN_TIMEOUT=int(os.getenv("CVESCOUT_SCAN_TIMEOUT", "900")),
        CHECK_TIMEOUT=int(os.getenv("CVESCOUT_CHECK_TIMEOUT", "120")),
        DOMAIN_CONNECT_TIMEOUT=int(os.getenv("CVESCOUT_DOMAIN_TIMEOUT", "8")),
        DOMAIN_MAX_BYTES=int(os.getenv("CVESCOUT_DOMAIN_MAX_BYTES", "65536")),
        NOTIFY_TIMEOUT=int(os.getenv("CVESCOUT_NOTIFY_TIMEOUT", "10")),
        CLOUDFLARE_API="https://api.cloudflare.com/client/v4",
        CLOUDFLARE_API_TOKEN=os.getenv("CVESCOUT_CLOUDFLARE_API_TOKEN", ""),
        HISTORY_RETENTION_DAYS=int(os.getenv("CVESCOUT_HISTORY_DAYS", "90")),
        PERMANENT_SESSION_LIFETIME=timedelta(hours=int(os.getenv("CVESCOUT_SESSION_HOURS", "12"))),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.getenv("CVESCOUT_HTTPS", "0") == "1",
        MAX_CONTENT_LENGTH=1024 * 1024,
        SEND_FILE_MAX_AGE_DEFAULT=600,
    )
    if test_config:
        app.config.update(test_config)

    db.init_app(app)
    app.register_blueprint(auth.bp)

    from .views import bp as main_bp

    app.register_blueprint(main_bp)
    app.jinja_env.globals["csrf_token"] = auth.csrf_token

    @app.before_request
    def protect_posts():
        if request.method == "POST" and request.endpoint != "auth.login":
            auth.verify_csrf()

    @app.context_processor
    def template_context():
        return {"current_user": session.get("user")}

    @app.after_request
    def security_headers(response):
        response.headers.setdefault("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'none'")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        response.headers.setdefault("X-Frame-Options", "DENY")
        if app.config["SESSION_COOKIE_SECURE"]:
            response.headers.setdefault("Strict-Transport-Security", "max-age=15552000")
        return response

    cli.register(app)

    return app
