from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("cvescout")
except PackageNotFoundError:  # running from a source tree without an install
    __version__ = "0"
