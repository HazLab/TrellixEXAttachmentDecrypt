# Trellix EX Attachment Decrypt
# Developed by Hazem Aljawhari

"""Shared-password session auth for the admin UI (dashboard + settings).

The recipient password form (/p/*), the webhook, and /healthz stay public; only
the admin surfaces are gated. A signed, TTL-limited cookie holds the session.

Each session carries a random id and a fingerprint of the admin password it was
issued under, so that:
- **changing the admin password** invalidates every existing session, and
- **logging out** revokes that session server-side (process-local: the revocation
  list lives in memory, so a restart forgets it — the cookie's own TTL still applies).

First-run **setup mode** (no admin password yet) is gated by a one-time setup token
printed in the server log, so whoever merely reaches the port first can't claim the
installation.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time

from fastapi import Request
from fastapi.responses import RedirectResponse
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from ..crypto import constant_time_equals

COOKIE = "ui_session"
SETUP_COOKIE = "setup_token"
SESSION_TTL = 12 * 60 * 60  # seconds
_SALT = "ui-session"

#: Revoked session ids -> the time their cookie would have expired anyway.
_revoked: dict[str, float] = {}


def _serializer(secret_key: str) -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(secret_key, salt=_SALT)


def _password_fingerprint(secret_key: str, ui_password: str) -> str:
    return hmac.new(secret_key.encode(), (ui_password or "").encode(), hashlib.sha256).hexdigest()[:32]


def issue_session(secret_key: str, ui_password: str = "") -> str:
    payload = {"sid": secrets.token_urlsafe(16), "pw": _password_fingerprint(secret_key, ui_password)}
    return _serializer(secret_key).dumps(payload)


def check_password(env, password: str) -> bool:
    """True only if a UI password is configured and matches (constant-time)."""
    return bool(env.ui_password) and constant_time_equals(password, env.ui_password)


def _session(request: Request, secret_key: str) -> dict | None:
    token = request.cookies.get(COOKIE)
    if not token:
        return None
    try:
        data = _serializer(secret_key).loads(token, max_age=SESSION_TTL)
    except (BadSignature, SignatureExpired):
        return None
    return data if isinstance(data, dict) else None  # pre-upgrade cookies: sign in again


def is_authenticated(request: Request, secret_key: str, ui_password: str = "") -> bool:
    data = _session(request, secret_key)
    if not data or not ui_password or data.get("sid") in _revoked:
        return False
    return constant_time_equals(data.get("pw"), _password_fingerprint(secret_key, ui_password))


def revoke_session(request: Request, secret_key: str) -> None:
    """Invalidate the caller's session (logout), and drop revocations that have aged out."""
    now = time.time()
    for sid in [s for s, expiry in _revoked.items() if expiry <= now]:
        del _revoked[sid]
    data = _session(request, secret_key)
    if data and data.get("sid"):
        _revoked[data["sid"]] = now + SESSION_TTL


def is_https(request: Request, trust_forwarded: bool = False) -> bool:
    """Was this request made over HTTPS (directly, or via a trusted TLS-terminating proxy)?"""
    if request.url.scheme == "https":
        return True
    return trust_forwarded and request.headers.get("x-forwarded-proto", "").lower() == "https"


def has_setup_token(request: Request, setup_token: str) -> bool:
    """Does the caller hold the one-time setup token (cookie set by the setup link)?"""
    return bool(setup_token) and constant_time_equals(request.cookies.get(SETUP_COOKIE), setup_token)


def login_redirect() -> RedirectResponse:
    return RedirectResponse("/login", status_code=303)
