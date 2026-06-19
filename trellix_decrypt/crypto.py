"""Fernet helper keyed by the deployment SECRET_KEY (used for settings secrets
and the transiently-stored attachment password)."""

from __future__ import annotations

import base64
import hashlib

from cryptography.fernet import Fernet


def fernet(secret_key: str) -> Fernet:
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256((secret_key or "").encode()).digest()))
