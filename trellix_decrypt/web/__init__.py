# Trellix EX Attachment Decrypt
# Developed by Hazem Aljawhari. Copyright (c) 2026 Hazem Aljawhari. MIT License.

"""Web layer: public recipient form + webhook, and the auth-gated admin UI."""

from .server import create_app

__all__ = ["create_app"]
