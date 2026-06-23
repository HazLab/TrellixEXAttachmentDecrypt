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
    # log_config=None: don't let uvicorn install its own isolated loggers, so its
    # access log (every HTTP request) propagates to the root handlers configured in
    # build() — i.e. it lands in the log file too, not just the console.
    uvicorn.run(app, host=settings.web_host, port=settings.web_port, log_config=None)


if __name__ == "__main__":
    main()
