# Trellix EX Attachment Decrypt
# Developed by Hazem Aljawhari

"""Fernet helper keyed by the deployment SECRET_KEY (used for settings secrets
and the transiently-stored attachment password)."""

from __future__ import annotations

import base64
import hashlib
import hmac

from cryptography.fernet import Fernet


def fernet(secret_key: str) -> Fernet:
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256((secret_key or "").encode()).digest()))


def constant_time_equals(a: str | None, b: str | None) -> bool:
    """Timing-safe string comparison. Compares UTF-8 bytes, so non-ASCII input is a
    plain mismatch instead of the TypeError ``hmac.compare_digest`` raises on str."""
    return hmac.compare_digest((a or "").encode("utf-8"), (b or "").encode("utf-8"))
