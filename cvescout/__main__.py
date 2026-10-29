from __future__ import annotations

import os

from . import create_app


def main() -> None:
    app = create_app()
    app.run(host=os.getenv("CVESCOUT_HOST", "127.0.0.1"), port=int(os.getenv("CVESCOUT_PORT", "5000")))


if __name__ == "__main__":
    main()
