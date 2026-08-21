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
    from .tls import active_paths
    cert, key = active_paths(settings)
    ssl_kwargs = {}
    if cert and key:  # native HTTPS (else plain HTTP behind a reverse proxy)
        ssl_kwargs = {"ssl_certfile": cert, "ssl_keyfile": key}
        if settings.tls_key_password:
            ssl_kwargs["ssl_keyfile_password"] = settings.tls_key_password
    # log_config=None: don't let uvicorn install its own isolated loggers, so its
    # access log (every HTTP request) propagates to the root handlers configured in
    # build() — i.e. it lands in the log file too, not just the console.
    uvicorn.run(app, host=settings.web_host, port=settings.web_port, log_config=None, **ssl_kwargs)


if __name__ == "__main__":
    main()
