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
    from .tls import serving
    _, port, ssl_kwargs = serving(settings)  # http on web_port, or https on https_port
    # log_config=None: don't let uvicorn install its own isolated loggers, so its
    # access log (every HTTP request) propagates to the root handlers configured in
    # build() — i.e. it lands in the log file too, not just the console.
    uvicorn.run(app, host=settings.web_host, port=port, log_config=None, **ssl_kwargs)


if __name__ == "__main__":
    main()
