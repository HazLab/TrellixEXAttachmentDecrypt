"""Alert ingestion: a pluggable source interface and the HTTP webhook router.

The pure alert parser lives in ``domain`` (parse_alert / iter_alerts) so it can
be shared with the EX client without dragging in a web framework. Syslog or
other transports can implement ``AlertSource`` later without touching parsing.
"""

from __future__ import annotations

import base64
import binascii
import hmac
import json
import logging
from abc import ABC, abstractmethod

from fastapi import APIRouter, HTTPException, Request

from .domain import iter_alerts, parse_alert

log = logging.getLogger(__name__)


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
        events = [parse_alert(raw) for raw in iter_alerts(payload)]
        # Handle malicious re-detections before riskware ones within the same push, so a
        # decrypted-malicious verdict (MALWARE_OBJECT) always wins over a same-batch
        # wrong-password retry for the same email.
        events.sort(key=lambda e: 0 if (e.malicious or (e.alert_name or "").upper() == "MALWARE_OBJECT") else 1)
        rules = ctx.engine.rules
        log.info("webhook: received %d alert(s)", len(events))
        handled = 0
        for event in events:
            log.info("webhook: alert queue_id=%r recipient=%r name=%r malware=%r",
                     event.queue_id, event.recipient, event.alert_name, event.malware_names)
            if not event.queue_id or not event.recipient:
                log.warning("webhook: SKIPPED — missing queue_id/recipient. raw alert: %s",
                            _dump(event.raw))
                continue
            if await ctx.engine.handle_alert(event) is not None:
                handled += 1
                log.info("webhook: HANDLED queue_id=%s (case created/updated)", event.queue_id)
            else:
                log.info("webhook: IGNORED (no trigger match / uncorrelated _RA) — need alert "
                         "name==%r AND a malware name in %r. raw alert: %s",
                         rules._alert_name, sorted(rules._names), _dump(event.raw))
        return {"received": True, "handled": handled}

    return router


def _dump(obj, limit: int = 4000) -> str:
    try:
        text = json.dumps(obj, default=str)
    except (TypeError, ValueError):
        text = repr(obj)
    return text if len(text) <= limit else text[:limit] + "…(truncated)"
