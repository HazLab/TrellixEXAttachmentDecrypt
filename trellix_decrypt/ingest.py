"""Alert ingestion: a pluggable source interface and the HTTP webhook router.

The pure alert parser lives in ``domain`` (parse_alert / iter_alerts) so it can
be shared with the EX client without dragging in a web framework. Syslog or
other transports can implement ``AlertSource`` later without touching parsing.
"""

from __future__ import annotations

import hmac
from abc import ABC, abstractmethod

from fastapi import APIRouter, Header, HTTPException, Request

from .domain import iter_alerts, parse_alert


class AlertSource(ABC):
    """A transport that yields normalized AlertEvents to the FlowEngine."""

    @abstractmethod
    async def start(self) -> None: ...


def build_webhook_router(ctx) -> APIRouter:
    """Public EX alert webhook. Reads the engine/settings from ctx at request
    time so a settings change (e.g. webhook secret) applies without a restart.
    """
    router = APIRouter()

    @router.post("/webhook/ex-alert")
    async def receive_alert(request: Request, x_webhook_secret: str = Header(default="")):
        settings = ctx.engine.settings
        if not hmac.compare_digest(x_webhook_secret, settings.webhook_secret):
            raise HTTPException(status_code=401, detail="bad webhook secret")
        if settings.webhook_ip_allowlist:
            client_ip = request.client.host if request.client else ""
            if client_ip not in settings.webhook_ip_allowlist:
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
