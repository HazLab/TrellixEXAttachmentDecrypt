# Trellix EX Attachment Decrypt
# Developed by Hazem Aljawhari

"""EX alert wire format: the normalized ``AlertEvent`` and the pure parsers.

The single place that knows the wire shape of an EX alert and of a quarantine list
entry. Verified against tests/fixtures/sample_alert.json (webhook push) and
sample_alerts_query.json (API). Pure functions, no I/O — shared by the webhook
(ingest), the flow engine (domain) and reconcile.
"""

from __future__ import annotations

import dataclasses


@dataclasses.dataclass
class AlertEvent:
    """Normalized EX alert. One quarantined email can list several recipients."""

    queue_id: str
    recipients: list[str] = dataclasses.field(default_factory=list)
    alert_name: str | None = None   # top-level alert "name", e.g. "RISKWARE_OBJECT"
    malicious: bool = False          # alert "malicious" == "yes"
    sender: str | None = None
    subject: str | None = None
    malware_names: list[str] = dataclasses.field(default_factory=list)
    raw: dict = dataclasses.field(default_factory=dict)

    @property
    def recipient(self) -> str:
        """Primary recipient (first To); the full set is ``recipients``."""
        return self.recipients[0] if self.recipients else ""

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
    for value in values:
        if value not in (None, ""):
            return value
    return None


def _text(value):
    """Resolve a field that may be a scalar, a {"value": ...} wrapper, or a list of either.

    The HTTP notification push wraps element text in {"value": ...}; the alerts
    query returns plain scalars. This normalizes both.
    """
    if isinstance(value, list):
        value = value[0] if value else None
    if isinstance(value, dict):
        value = value.get("value")
    return None if value in (None, "") else str(value)


def split_addrs(value) -> list[str]:
    """Split a recipients string ('a@x, b@x; c@x') into a de-duplicated list,
    order preserved. Used to unpack the stored, comma-joined recipient column."""
    out, seen = [], set()
    for part in str(value or "").replace(";", ",").split(","):
        addr = part.strip()
        if addr and addr not in seen:
            seen.add(addr)
            out.append(addr)
    return out


def _text_list(value) -> list[str]:
    """Normalize an EX recipient field to a list of addresses. Handles a scalar, a
    {"value": ...} wrapper, a list of either, and a single string carrying several
    comma/semicolon-separated addresses — covering both wire formats."""
    items = value if isinstance(value, list) else [value]
    out, seen = [], set()
    for item in items:
        if isinstance(item, dict):
            item = item.get("value")
        for addr in split_addrs(item):
            if addr not in seen:
                seen.add(addr)
                out.append(addr)
    return out


def _is_yes(value) -> bool:
    return str(value or "").strip().lower() in ("yes", "true", "1")


def _malware_entries(alert: dict) -> list[dict]:
    entries = _first(
        _dig(alert, "explanation", "malware-detected", "malware"),   # push (hyphenated)
        _dig(alert, "explanation", "malwareDetected", "malware"),     # query (camelCase)
        alert.get("malware"),
    ) or []
    if isinstance(entries, dict):
        entries = [entries]
    return [e for e in entries if isinstance(e, dict)]


def entry_queue_id(entry: dict) -> str:
    """Queue id of a raw EX quarantine list entry (camelCase or snake_case)."""
    return _text(_first(entry.get("queue_id"), entry.get("queueId"))) or ""


def entry_alert_uuids(entry: dict) -> list[str]:
    """Alert UUIDs a quarantine entry references (may be several; may be absent)."""
    return [str(u) for u in (entry.get("alert_uuids") or entry.get("alertUuids") or []) if u]


def iter_alerts(payload: dict) -> list[dict]:
    """EX wraps alerts under ``Alerts``/``alerts``/``alert`` (or a bare alert); accept all."""
    alerts = payload.get("Alerts") or payload.get("alerts") or payload.get("alert") or payload
    return alerts if isinstance(alerts, list) else [alerts]


def parse_alert(alert: dict) -> AlertEvent:
    """Map one raw EX alert dict to an AlertEvent.

    Handles both wire formats: the alerts-query JSON (camelCase scalars, e.g.
    ``queueId``, ``dst.smtpTo``) and the HTTP notification push (hyphenated keys
    with ``{"value": ...}`` wrappers, e.g. ``queue-id``, ``dst.smtp-to.value``).
    """
    return AlertEvent(
        queue_id=_text(_first(
            alert.get("queue-id"), alert.get("queueId"), alert.get("queue_id"),
            _dig(alert, "smtp-message", "queue-id"), _dig(alert, "smtpMessage", "queueId"),
        )) or "",
        recipients=_text_list(_first(
            _dig(alert, "dst", "smtp-to"), _dig(alert, "dst", "smtpTo"),
            _dig(alert, "smtpMessage", "rcptTo"), alert.get("recipient"), alert.get("rcpt_to"),
        )),
        alert_name=_text(_first(alert.get("name"), alert.get("alert_name"))),
        malicious=_is_yes(_text(alert.get("malicious"))),
        sender=_text(_first(
            _dig(alert, "src", "smtp-mail-from"), _dig(alert, "src", "smtpMailFrom"),
            _dig(alert, "smtpMessage", "mailFrom"), alert.get("sender"),
        )),
        subject=_text(_first(
            _dig(alert, "smtp-message", "subject"), _dig(alert, "smtpMessage", "subject"),
            alert.get("subject"),
        )),
        malware_names=[name for m in _malware_entries(alert)
                       if (name := _text(m.get("name")) or _text(m.get("malware_name"))) is not None],
        raw=alert,
    )


#: Marker substrings for the encrypted-attachment (pre-password-extraction) detection.
_ENCRYPTED_MARKERS = ("custompolicy.mvx", "passextractfailed", "password_extraction_failed")


def is_pre_extraction_alert(detail: dict) -> bool:
    """True for the ORIGINAL encrypted-attachment trigger alert (why the email landed in
    the app) — hidden from the drawer as redundant. An ``_RA`` re-detection is NOT hidden."""
    qid = detail.get("queue_id") or ""
    if qid.endswith("_RA"):
        return False
    names = [(m.get("name") or "").lower() for m in detail.get("malware") or []]
    return any(marker in n for n in names for marker in _ENCRYPTED_MARKERS)


def parse_alert_detail(alert: dict) -> dict:
    """Compact, display-only view of one raw EX alert (from GET /alerts/alert/<uuid>).

    Pure. Surfaces the fields worth showing in the case drawer — alert type/verdict,
    severity/action, when it occurred, the console link, and the detected malware
    (name + hashes). Tolerates both the camelCase query shape and the hyphenated push."""
    return {
        "uuid": _text(alert.get("uuid")),
        "name": _text(_first(alert.get("name"), alert.get("alert_name"))),
        "malicious": _is_yes(_text(alert.get("malicious"))),
        "severity": _text(alert.get("severity")),
        "action": _text(alert.get("action")),
        "occurred": _text(_first(alert.get("occurred"), alert.get("attackTime"), alert.get("attack-time"))),
        "alert_url": _text(_first(alert.get("alertUrl"), alert.get("alert-url"))),
        "queue_id": _text(_first(
            _dig(alert, "smtpMessage", "queueId"), _dig(alert, "smtp-message", "queue-id"),
            alert.get("queueId"), alert.get("queue-id"))),
        "malware": [
            {"name": _text(m.get("name")),
             "sha256": _text(_first(m.get("sha256"), m.get("sha-256"))),
             "md5": _text(_first(m.get("md5Sum"), m.get("md5sum"), m.get("md5")))}
            for m in _malware_entries(alert)
        ],
    }


def alert_uuid(alert: dict) -> str | None:
    """UUID of a raw EX alert, or None when the row carries none."""
    return _text(alert.get("uuid"))
