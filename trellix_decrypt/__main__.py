"""Entrypoint: ``python -m trellix_decrypt`` / ``trellix-decrypt`` [--check]."""

from __future__ import annotations

import sys


def main() -> None:
    if "--check" in sys.argv[1:]:
        from .check import run_check
        raise SystemExit(run_check())

    import uvicorn

    from .app import build

    app, settings = build()
    uvicorn.run(app, host=settings.web_host, port=settings.web_port)


if __name__ == "__main__":
    main()
