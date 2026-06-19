"""Shared-password session auth for the admin UI (dashboard + settings).

The recipient password form (/p/*), the webhook, and /healthz stay public; only
the admin surfaces are gated. A signed, TTL-limited cookie holds the session.
"""

from __future__ import annotations

import hmac

from fastapi import Request
from fastapi.responses import RedirectResponse
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

COOKIE = "ui_session"
SESSION_TTL = 12 * 60 * 60  # seconds
_SALT = "ui-session"


def _serializer(secret_key: str) -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(secret_key, salt=_SALT)


def issue_session(secret_key: str) -> str:
    return _serializer(secret_key).dumps("admin")


def check_password(env, password: str) -> bool:
    """True only if a UI password is configured and matches (constant-time)."""
    return bool(env.ui_password) and hmac.compare_digest(password, env.ui_password)


def is_authenticated(request: Request, secret_key: str) -> bool:
    token = request.cookies.get(COOKIE)
    if not token:
        return False
    try:
        _serializer(secret_key).loads(token, max_age=SESSION_TTL)
        return True
    except (BadSignature, SignatureExpired):
        return False


def login_redirect() -> RedirectResponse:
    return RedirectResponse("/login", status_code=303)
