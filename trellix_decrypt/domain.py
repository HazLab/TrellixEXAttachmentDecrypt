"""Pure business logic: models, riskware rules, one-time tokens, and the flow engine.

This module performs **no I/O of its own** — the FlowEngine drives the flow by
calling injected collaborators (repository, EX client, mailer, scheduler), so it
is fully unit-testable with fakes.
"""

from __future__ import annotations

import dataclasses
import enum
import hashlib

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer


class FlowState(str, enum.Enum):
    RECEIVED = "received"
    AWAITING_PASSWORD = "awaiting_password"
    PASSWORD_SUBMITTED = "password_submitted"
    RESUBMITTED = "resubmitted"
    RECHECKING = "rechecking"
    DONE_CLEAN = "done_clean"
    DONE_MALICIOUS = "done_malicious"
    FAILED_MAX_RETRIES = "failed_max_retries"
    EXPIRED = "expired"


#: States from which a recheck poll may still run.
RECHECKABLE = (FlowState.RESUBMITTED, FlowState.RECHECKING)
#: Terminal states.
TERMINAL = (FlowState.DONE_CLEAN, FlowState.DONE_MALICIOUS, FlowState.FAILED_MAX_RETRIES, FlowState.EXPIRED)


class QuarantineOutcome(str, enum.Enum):
    NOT_QUARANTINED = "not_quarantined"   # delivered / clean
    FAILED_EXTRACTION = "failed_extraction"  # wrong password — retry
    MALICIOUS = "malicious"               # stop


@dataclasses.dataclass
class AlertEvent:
    """Normalized EX alert."""

    queue_id: str
    recipient: str
    alert_name: str | None = None   # top-level alert "name", e.g. "RISKWARE_OBJECT"
    malicious: bool = False          # alert "malicious" == "yes"
    sender: str | None = None
    subject: str | None = None
    malware_names: list[str] = dataclasses.field(default_factory=list)
    raw: dict = dataclasses.field(default_factory=dict)


class RiskwareRules:
    """Decides whether an alert should trigger the recovery flow.

    An alert matches when its top-level name equals the configured alert name
    (e.g. "RISKWARE_OBJECT") AND one of its malware names exactly equals one of
    the configured malware names (case-insensitive). With no malware names
    configured nothing matches — this avoids firing on every riskware object
    (e.g. unrelated CustomPolicy.MVX QR-code detections).
    """

    def __init__(self, trigger_malware_names=(), trigger_alert_name="RISKWARE_OBJECT"):
        self._names = {str(n).strip().lower() for n in trigger_malware_names if str(n).strip()}
        self._alert_name = (trigger_alert_name or "").strip().lower()

    def name_matches(self, name) -> bool:
        """Exact (case-insensitive) match of one malware name against the triggers."""
        return str(name or "").strip().lower() in self._names

    def alert_name_matches(self, alert_name) -> bool:
        return not self._alert_name or str(alert_name or "").strip().lower() == self._alert_name

    def matches(self, event: "AlertEvent") -> bool:
        if not self._names or not self.alert_name_matches(event.alert_name):
            return False
        return any(self.name_matches(n) for n in event.malware_names)


class TokenService:
    """Mint and verify signed, TTL-expiring one-time links carrying a case id.

    Single use is enforced by case state: once a password is submitted the case
    leaves AWAITING_PASSWORD, so a replayed link is rejected by the FlowEngine.
    """

    def __init__(self, secret_key: str, ttl: int):
        self._serializer = URLSafeTimedSerializer(secret_key, salt="password-link")
        self._ttl = ttl

    def mint(self, case_id: str) -> str:
        return self._serializer.dumps(case_id)

    def verify(self, token: str) -> str | None:
        try:
            return self._serializer.loads(token, max_age=self._ttl)
        except (BadSignature, SignatureExpired):
            return None


def hash_password(password: str) -> str:
    """One-way hash for de-duping wrong attempts. Plaintext is never persisted."""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


class FlowEngine:
    """Orchestrates the recovery state machine across injected collaborators."""

    def __init__(self, repo, ex, mailer, tokens: TokenService, rules: RiskwareRules, settings, scheduler):
        self.repo = repo
        self.ex = ex
        self.mailer = mailer
        self.tokens = tokens
        self.rules = rules
        self.settings = settings
        self.scheduler = scheduler

    async def handle_alert(self, event: AlertEvent):
        """Entry point for an incoming EX alert. Returns the case, or None if ignored."""
        if not self.rules.matches(event):
            return None
        case = self.repo.get_or_create_case(event)
        if case.state == FlowState.RECEIVED:
            await self._send_password_request(case)
        return case

    async def handle_password(self, token: str, password: str):
        """Handle a password submission. Returns (case_or_None, status_string)."""
        case_id = self.tokens.verify(token)
        if not case_id:
            return None, "invalid_or_expired"
        case = self.repo.get_case(case_id)
        if case is None:
            return None, "not_found"
        if case.state != FlowState.AWAITING_PASSWORD:
            return case, "not_awaiting"

        self.repo.add_attempt(case, hash_password(password))
        self.repo.set_state(case, FlowState.PASSWORD_SUBMITTED, "password submitted")
        # The rescan endpoint takes the email's UUID; resolve it from quarantine.
        email_uuid, _ = await self.ex.resolve_email_uuid(case.queue_id)
        await self.ex.rescan(email_uuid or case.queue_id, [password])
        self.repo.set_state(case, FlowState.RESUBMITTED, "resubmitted to EX (rescan)")
        self.scheduler.schedule_recheck(case.id)
        return case, "ok"

    async def recheck(self, case_id: str, final: bool = False) -> bool:
        """Re-evaluate a resubmitted case. Returns True when polling should stop."""
        case = self.repo.get_case(case_id)
        if case is None or case.state not in RECHECKABLE:
            return True
        self.repo.set_state(case, FlowState.RECHECKING, "rechecking quarantine")

        outcome = await self.ex.classify_resubmission(case.queue_id, case.recipient, self.rules)
        if outcome is QuarantineOutcome.MALICIOUS:
            self.repo.set_state(case, FlowState.DONE_MALICIOUS, "re-quarantined: malicious")
            return True
        if outcome is QuarantineOutcome.FAILED_EXTRACTION:
            if case.attempts >= self.settings.max_password_attempts:
                self.repo.set_state(case, FlowState.FAILED_MAX_RETRIES, "max password attempts reached")
            else:
                await self._send_password_request(case, retry=True)
            return True
        # NOT_QUARANTINED: maybe still analyzing — only conclude clean on the last poll.
        if final:
            self.repo.set_state(case, FlowState.DONE_CLEAN, "not re-quarantined: delivered")
            return True
        return False

    async def resume_pending(self):
        """On startup, reschedule rechecks for cases left mid-flight."""
        for case_id in self.repo.list_pending_ids():
            self.scheduler.schedule_recheck(case_id)

    async def aclose(self):
        await self.ex.aclose()

    async def _send_password_request(self, case, retry: bool = False):
        token = self.tokens.mint(case.id)
        link = f"{self.settings.public_base_url.rstrip('/')}/p/{token}"
        await self.mailer.send_password_request(case.recipient, link, case, retry=retry)
        self.repo.set_state(case, FlowState.AWAITING_PASSWORD, "password link sent" + (" (retry)" if retry else ""))


# --- Alert parsing ----------------------------------------------------------
# The single place that knows the wire shape of an EX alert. Verified against
# docs/sample_alert.json (webhook push) and docs/sample_alerts_query.json (API).
# Pure functions — reused by the webhook (ingest) and the EX client (recheck).


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


def _is_yes(value) -> bool:
    return str(value or "").strip().lower() in ("yes", "true", "1")


def _malware_entries(alert: dict) -> list[dict]:
    entries = _first(_dig(alert, "explanation", "malwareDetected", "malware"), alert.get("malware")) or []
    if isinstance(entries, dict):
        entries = [entries]
    return [e for e in entries if isinstance(e, dict)]


def iter_alerts(payload: dict) -> list[dict]:
    """EX wraps alerts under ``Alerts`` (webhook push) or ``alert`` (API); accept both."""
    alerts = payload.get("Alerts") or payload.get("alerts") or payload.get("alert") or payload
    return alerts if isinstance(alerts, list) else [alerts]


def parse_alert(alert: dict) -> AlertEvent:
    """Map one raw EX alert dict to an AlertEvent."""
    return AlertEvent(
        queue_id=str(_first(alert.get("queue_id"), alert.get("queueId"), _dig(alert, "smtpMessage", "queueId")) or ""),
        recipient=str(_first(_dig(alert, "smtpMessage", "rcptTo"), _dig(alert, "dst", "smtpTo"),
                             alert.get("recipient"), alert.get("rcpt_to")) or ""),
        alert_name=_first(alert.get("name"), alert.get("alert_name")),
        malicious=_is_yes(alert.get("malicious")),
        sender=_first(_dig(alert, "smtpMessage", "mailFrom"), _dig(alert, "src", "smtpMailFrom"), alert.get("sender")),
        subject=_first(_dig(alert, "smtpMessage", "subject"), alert.get("subject")),
        malware_names=[str(name) for m in _malware_entries(alert)
                       if (name := m.get("name") or m.get("malware_name")) is not None],
        raw=alert,
    )
