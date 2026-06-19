"""Alert ingestion: a pluggable source interface and the HTTP webhook router.

The pure alert parser lives in ``domain`` (parse_alert / iter_alerts) so it can
be shared with the EX client without dragging in a web framework. Syslog or
other transports can implement ``AlertSource`` later without touching parsing.
"""

from __future__ import annotations

import base64
import binascii
import hmac
from abc import ABC, abstractmethod

from fastapi import APIRouter, HTTPException, Request

from .domain import iter_alerts, parse_alert


class AlertSource(ABC):
    """A transport that yields normalized AlertEvents to the FlowEngine."""

    @abstractmethod
    async def start(self) -> None: ...


def _basic_credentials(request: Request):
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("basic "):
        return None
    try:
        user, _, pwd = base64.b64decode(header[6:]).decode().partition(":")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    return user, pwd


def build_webhook_router(ctx) -> APIRouter:
    """Public EX alert webhook. EX's HTTP notification authenticates with HTTP
    Basic auth; an optional source-IP allowlist adds a second gate. Settings are
    read from ctx at request time so credential changes apply without a restart.
    """
    router = APIRouter()

    @router.post("/webhook/ex-alert")
    async def receive_alert(request: Request):
        s = ctx.engine.settings
        has_creds = bool(s.webhook_username or s.webhook_password)
        has_allowlist = bool(s.webhook_ip_allowlist)
        if not has_creds and not has_allowlist:
            raise HTTPException(status_code=401, detail="webhook auth not configured")
        if has_creds:
            creds = _basic_credentials(request)
            ok = creds and hmac.compare_digest(creds[0], s.webhook_username) \
                and hmac.compare_digest(creds[1], s.webhook_password)
            if not ok:
                raise HTTPException(status_code=401, detail="bad webhook credentials",
                                    headers={"WWW-Authenticate": "Basic"})
        if has_allowlist:
            client_ip = request.client.host if request.client else ""
            if client_ip not in s.webhook_ip_allowlist:
                raise HTTPException(status_code=403, detail="ip not allowed")

        payload = await request.json()
        handled = 0
        for raw in iter_alerts(payload):
            event = parse_alert(raw)
            if not event.queue_id or not event.recipient:
                continue
            if await ctx.engine.handle_alert(event) is not None:
                handled += 1
        return {"received": True, "handled": handled}

    return router
