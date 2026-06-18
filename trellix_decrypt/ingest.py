"""Alert ingestion: a pluggable source interface, an EX-alert parser, and the
HTTP webhook router. Syslog or other transports can implement ``AlertSource``
later without touching the parser or the flow engine.
"""

from __future__ import annotations

import hmac
from abc import ABC, abstractmethod

from fastapi import APIRouter, Header, HTTPException, Request

from .domain import AlertEvent, FlowEngine


class AlertSource(ABC):
    """A transport that yields normalized AlertEvents to the FlowEngine."""

    @abstractmethod
    async def start(self) -> None: ...


def _dig(obj, *path):
    """Walk dict keys / list indices, returning None if any step is missing."""
    cur = obj
    for key in path:
        if isinstance(cur, dict):
            cur = cur.get(key)
        elif isinstance(cur, list) and isinstance(key, int) and -len(cur) <= key < len(cur):
            cur = cur[key]
        else:
            return None
    return cur


def _first(*values):
    for v in values:
        if v not in (None, ""):
            return v
    return None


def _is_yes(value) -> bool:
    return str(value or "").strip().lower() in ("yes", "true", "1")


def parse_alert(alert: dict) -> AlertEvent:
    """Map one raw EX alert dict to an AlertEvent.

    Verified against docs/sample_alert.json. Field names vary by EX version —
    adjust the lookups here if your appliance differs. This is the only place
    that knows the wire shape of an alert.
    """
    return AlertEvent(
        queue_id=str(_first(alert.get("queue_id"), alert.get("queueId"), _dig(alert, "smtpMessage", "queueId")) or ""),
        recipient=str(_first(
            _dig(alert, "smtpMessage", "rcptTo"), _dig(alert, "dst", "smtpTo"),
            alert.get("recipient"), alert.get("rcpt_to"),
        ) or ""),
        alert_name=_first(alert.get("name"), alert.get("alert_name")),
        malicious=_is_yes(alert.get("malicious")),
        sender=_first(_dig(alert, "smtpMessage", "mailFrom"), _dig(alert, "src", "smtpMailFrom"), alert.get("sender")),
        subject=_first(_dig(alert, "smtpMessage", "subject"), alert.get("subject")),
        malware_names=[str(name) for m in _malware_entries(alert)
                       if (name := m.get("name") or m.get("malware_name")) is not None],
        raw=alert,
    )


def _malware_entries(alert: dict) -> list[dict]:
    """Pull the list of malware objects from an alert (key is typically ``malware``)."""
    entries = _first(
        _dig(alert, "explanation", "malwareDetected", "malware"),
        alert.get("malware"),
    ) or []
    if isinstance(entries, dict):
        entries = [entries]
    return [e for e in entries if isinstance(e, dict)]


def iter_alerts(payload: dict) -> list[dict]:
    """An EX notification wraps alerts under ``Alerts`` (see sample); accept variants."""
    alerts = payload.get("Alerts") or payload.get("alerts") or payload.get("alert") or payload
    return alerts if isinstance(alerts, list) else [alerts]


def build_webhook_router(engine: FlowEngine, settings) -> APIRouter:
    router = APIRouter()

    @router.post("/webhook/ex-alert")
    async def receive_alert(request: Request, x_webhook_secret: str = Header(default="")):
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
            if await engine.handle_alert(event) is not None:
                handled += 1
        return {"received": True, "handled": handled}

    return router
