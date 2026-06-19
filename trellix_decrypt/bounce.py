"""Bounce monitoring: poll the sender mailbox over IMAP for delivery-status
notifications (DSNs) and flip the corresponding case to BOUNCED.

This catches mail the SMTP server accepted (250) but later failed to deliver —
which the synchronous send path can't see. parse_bounce() is pure and testable;
BounceMonitor handles the IMAP transport.
"""

from __future__ import annotations

import asyncio
import email
import imaplib
import logging
from email import policy

log = logging.getLogger(__name__)


def _original_headers(part):
    """Return the embedded original message (or its headers) from a DSN part."""
    payload = part.get_payload()
    if isinstance(payload, list) and payload:
        return payload[0]
    if isinstance(payload, str):
        return email.message_from_string(payload, policy=policy.default)
    return None


def parse_bounce(raw: bytes) -> dict | None:
    """Parse a raw message; return {case_id, recipient, reason} if it's a hard
    bounce (DSN with Action: failed), else None."""
    try:
        msg = email.message_from_bytes(raw, policy=policy.default)
    except Exception:  # noqa: BLE001
        return None

    action = status = diagnostic = case_id = final_recipient = None
    for part in msg.walk():
        ctype = part.get_content_type()
        if ctype == "message/delivery-status":
            for sub in part.get_payload():
                if not hasattr(sub, "get"):
                    continue
                action = action or sub.get("Action")
                status = status or sub.get("Status")
                diagnostic = diagnostic or sub.get("Diagnostic-Code")
                final_recipient = final_recipient or sub.get("Final-Recipient")
        elif ctype in ("message/rfc822", "text/rfc822-headers"):
            orig = _original_headers(part)
            if orig is not None and hasattr(orig, "get"):
                case_id = case_id or orig.get("X-Case-Id")

    if (action or "").strip().lower() != "failed":
        return None
    if final_recipient and ";" in final_recipient:   # "rfc822; user@host" -> "user@host"
        final_recipient = final_recipient.split(";", 1)[1].strip()
    reason = " ".join(p.strip() for p in (status, diagnostic) if p) or "delivery failed"
    return {
        "case_id": (str(case_id).strip() or None) if case_id else None,
        "recipient": final_recipient,
        "reason": reason,
    }


class BounceMonitor:
    """Periodically polls the configured IMAP mailbox and reports bounces to the engine."""

    def __init__(self, engine):
        self._engine = engine

    async def run(self):
        while True:
            interval = max(30, self._engine.settings.bounce_poll_interval)
            await asyncio.sleep(interval)
            try:
                await self.poll_once()
            except Exception:  # never let the loop die
                log.exception("bounce poll failed")

    async def poll_once(self):
        if not self._engine.settings.imap_host:
            return
        for bounce in await asyncio.to_thread(self._fetch_bounces):
            if self._engine.handle_bounce(bounce):
                log.info("bounce recorded for case=%s recipient=%s: %s",
                         bounce.get("case_id"), bounce.get("recipient"), bounce.get("reason"))

    def _fetch_bounces(self) -> list[dict]:
        s = self._engine.settings
        client_cls = imaplib.IMAP4_SSL if s.imap_ssl else imaplib.IMAP4
        client = client_cls(s.imap_host, s.imap_port)
        bounces: list[dict] = []
        try:
            client.login(s.imap_username, s.imap_password)
            client.select(s.imap_mailbox)
            typ, data = client.search(None, "UNSEEN")
            if typ != "OK" or not data or not data[0]:
                return bounces
            for num in data[0].split():
                typ, msg_data = client.fetch(num, "(RFC822)")  # marks \Seen
                if typ != "OK" or not msg_data or not msg_data[0]:
                    continue
                parsed = parse_bounce(msg_data[0][1])
                if parsed:
                    bounces.append(parsed)
            return bounces
        finally:
            try:
                client.logout()
            except Exception:  # noqa: BLE001
                pass
