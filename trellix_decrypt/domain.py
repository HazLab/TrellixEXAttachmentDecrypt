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
    rule_id: int | None = None
    sender: str | None = None
    subject: str | None = None
    malware_type: str | None = None
    raw: dict = dataclasses.field(default_factory=dict)


class RiskwareRules:
    """Decides whether an alert's rule ID should trigger the recovery flow."""

    def __init__(self, trigger_rule_ids):
        self._triggers = {int(r) for r in trigger_rule_ids}

    def is_trigger(self, rule_id) -> bool:
        if rule_id is None:
            return False
        try:
            return int(rule_id) in self._triggers
        except (TypeError, ValueError):
            return False


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
        if not self.rules.is_trigger(event.rule_id):
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
        await self.ex.resubmit(case.queue_id, [password])
        self.repo.set_state(case, FlowState.RESUBMITTED, "resubmitted to EX")
        self.scheduler.schedule_recheck(case.id)
        return case, "ok"

    async def recheck(self, case_id: str, final: bool = False) -> bool:
        """Re-evaluate a resubmitted case. Returns True when polling should stop."""
        case = self.repo.get_case(case_id)
        if case is None or case.state not in RECHECKABLE:
            return True
        self.repo.set_state(case, FlowState.RECHECKING, "rechecking quarantine")

        outcome = await self.ex.classify_resubmission(case.queue_id, self.rules)
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
