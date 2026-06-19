"""Web layer: public recipient form + webhook, and the auth-gated admin UI."""

from .server import create_app

__all__ = ["create_app"]
