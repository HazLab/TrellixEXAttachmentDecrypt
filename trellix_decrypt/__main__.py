"""Entrypoint: ``python -m trellix_decrypt`` / ``trellix-decrypt``."""

from __future__ import annotations


def main() -> None:
    import uvicorn

    from .app import build

    app, settings = build()
    uvicorn.run(app, host=settings.web_host, port=settings.web_port)


if __name__ == "__main__":
    main()
