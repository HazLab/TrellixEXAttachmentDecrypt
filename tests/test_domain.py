"""Unit tests for the pure flow logic (no network/SMTP/real DB I/O)."""

from __future__ import annotations

import pytest

from trellix_decrypt.domain import AlertEvent, FlowState, QuarantineOutcome, RiskwareRules, TokenService

from .conftest import TRIGGER_MALWARE_NAME


def _alert(name=TRIGGER_MALWARE_NAME, alert_name="RISKWARE_OBJECT", queue_id="Q1"):
    return AlertEvent(queue_id=queue_id, recipient="user@corp.test", subject="Invoice",
                      alert_name=alert_name, malware_names=[name])


# --- rules & tokens ---------------------------------------------------------
def test_rules_require_alert_name_and_exact_malware_name():
    rules = RiskwareRules([TRIGGER_MALWARE_NAME], "RISKWARE_OBJECT")
    assert rules.matches(_alert(TRIGGER_MALWARE_NAME))                       # exact name + right alert
    assert not rules.matches(_alert(TRIGGER_MALWARE_NAME, alert_name="MALWARE_OBJECT"))  # wrong alert name
    assert not rules.matches(_alert("CustomPolicy.MVX.65055.qrCodePresent"))  # different policy
    assert not rules.matches(_alert("CustomPolicy.MVX"))                     # stem alone doesn't match


def test_rules_never_trigger_without_configured_names():
    rules = RiskwareRules([], "RISKWARE_OBJECT")
    assert not rules.matches(_alert(TRIGGER_MALWARE_NAME))  # empty names => never fire


def test_token_roundtrip_and_tamper():
    svc = TokenService("secret", ttl=60)
    token = svc.mint("case-123")
    assert svc.verify(token) == "case-123"
    assert svc.verify(token + "x") is None


# --- flow engine ------------------------------------------------------------
async def test_non_trigger_alert_ignored(engine):
    # A different CustomPolicy.MVX riskware object (e.g. QR-code) must NOT trigger.
    assert await engine.handle_alert(_alert("CustomPolicy.MVX.65055.qrCodePresent")) is None
    assert engine.mailer.sent == []


async def test_alert_emails_recipient_and_awaits(engine):
    case = await engine.handle_alert(_alert())
    assert case.state == FlowState.AWAITING_PASSWORD
    assert len(engine.mailer.sent) == 1


async def test_duplicate_alert_does_not_resend(engine):
    await engine.handle_alert(_alert())
    await engine.handle_alert(_alert())  # same queue_id
    assert len(engine.mailer.sent) == 1


async def test_password_submission_resubmits(engine):
    case = await engine.handle_alert(_alert())
    token = engine.tokens.mint(case.id)
    result, status = await engine.handle_password(token, "hunter2")
    assert status == "ok"
    assert result.state == FlowState.RESUBMITTED
    assert engine.ex.rescanned == [("uuid-Q1", ["hunter2"])]  # rescans by resolved email_uuid
    assert engine.scheduler.scheduled == [case.id]


async def test_replayed_link_rejected_after_submission(engine):
    case = await engine.handle_alert(_alert())
    token = engine.tokens.mint(case.id)
    await engine.handle_password(token, "pw")
    _, status = await engine.handle_password(token, "pw")  # reuse
    assert status == "not_awaiting"


async def test_recheck_malicious_stops(engine):
    case = await engine.handle_alert(_alert())
    await engine.handle_password(engine.tokens.mint(case.id), "pw")
    engine.ex.outcomes = [QuarantineOutcome.MALICIOUS]
    assert await engine.recheck(case.id) is True
    assert engine.repo.get_case(case.id).state == FlowState.DONE_MALICIOUS


async def test_recheck_clean_only_on_final_poll(engine):
    case = await engine.handle_alert(_alert())
    await engine.handle_password(engine.tokens.mint(case.id), "pw")
    engine.ex.outcomes = [QuarantineOutcome.NOT_QUARANTINED, QuarantineOutcome.NOT_QUARANTINED]
    assert await engine.recheck(case.id, final=False) is False  # keep polling
    assert await engine.recheck(case.id, final=True) is True
    assert engine.repo.get_case(case.id).state == FlowState.DONE_CLEAN


async def test_wrong_password_retries_then_gives_up(engine):
    case = await engine.handle_alert(_alert())
    # 3 wrong-password rounds (max_password_attempts=3)
    for _ in range(3):
        await engine.handle_password(engine.tokens.mint(case.id), "wrong")
        engine.ex.outcomes = [QuarantineOutcome.FAILED_EXTRACTION]
        await engine.recheck(case.id)
    assert engine.repo.get_case(case.id).state == FlowState.FAILED_MAX_RETRIES
    # one initial + two retry emails (third attempt hits the cap)
    assert len(engine.mailer.sent) == 3
