"""Server-rendered routes, split by area under one blueprint.

Every route keeps the endpoint namespace `main.*`, so templates and `url_for` calls
are unaffected by the split. Submodules own their routes and import `bp` from here.
"""

from __future__ import annotations

import re
from datetime import date

from flask import Blueprint, Response, request

from ..auth import login_required
from ..db import get_db

bp = Blueprint("main", __name__)

PAGE_SIZE = 50


def _active_jobs(target: str | None = None) -> bool:
    """True when a job is queued or running, so pages can auto-refresh."""
    sql = "SELECT 1 FROM jobs WHERE status IN ('queued','running')"
    params: tuple = ()
    if target is not None:
        sql += " AND target=?"
        params = (target,)
    return get_db().execute(sql + " LIMIT 1", params).fetchone() is not None


def _page() -> int:
    return max(1, request.args.get("page", 1, type=int) or 1)


def paginate(total: int) -> tuple[int, int, int]:
    """Clamp the requested page into range: (page, pages, offset)."""
    pages = max(1, -(-total // PAGE_SIZE))
    page = min(_page(), pages)
    return page, pages, (page - 1) * PAGE_SIZE


def download(body: str, mimetype: str, name: str) -> Response:
    """Attachment response; the filename gets a date prefix and safe characters only."""
    safe = re.sub(r"[^A-Za-z0-9._-]", "-", name)
    filename = f"cvescout-{date.today().isoformat()}-{safe}"
    return Response(
        body,
        mimetype=mimetype,
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@bp.before_request
@login_required
def require_login():
    return None


# Imported last: each module registers its routes on `bp` as a side effect.
from . import devices, domains, reports, system  # noqa: F401  (registers routes)
from . import settings as settings_routes  # noqa: F401  (registers routes)
