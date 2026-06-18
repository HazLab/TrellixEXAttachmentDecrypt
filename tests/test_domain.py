"""Unit tests for the pure flow logic (no network/SMTP/real DB I/O)."""

from __future__ import annotations

import pytest

from trellix_decrypt.domain import AlertEvent, FlowState, QuarantineOutcome, RiskwareRules, TokenService


def _alert(name="CustomPolicy.MVX.pdf", malware_type="riskware-object", queue_id="Q1"):
    return AlertEvent(queue_id=queue_id, recipient="user@corp.test", subject="Invoice",
                      malware=[{"name": name, "type": malware_type}])


# --- rules & tokens ---------------------------------------------------------
TRIGGER_NAMES = ["CustomPolicy.MVX.pdf", "CustomPolicy.MVX.zip", "CustomPolicy.MVX.docx"]


def test_rules_require_type_and_exact_name():
    rules = RiskwareRules(TRIGGER_NAMES, "riskware-object")
    assert rules.matches(_alert("CustomPolicy.MVX.zip"))               # exact name + right type
    assert not rules.matches(_alert("CustomPolicy.MVX.zip", "malware-object"))  # wrong type
    assert not rules.matches(_alert("CustomPolicy.MVX.exe"))           # name not in the list
    assert not rules.matches(_alert("CustomPolicy.MVX"))               # stem alone doesn't match


def test_rules_type_only_when_no_names():
    rules = RiskwareRules([], "riskware-object")
    assert rules.matches(_alert("anything", "riskware-object"))
    assert not rules.matches(_alert("anything", "trojan-object"))


def test_token_roundtrip_and_tamper():
    svc = TokenService("secret", ttl=60)
    token = svc.mint("case-123")
    assert svc.verify(token) == "case-123"
    assert svc.verify(token + "x") is None


# --- flow engine ------------------------------------------------------------
async def test_non_trigger_alert_ignored(engine):
    assert await engine.handle_alert(_alert(malware_type="trojan-object")) is None
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
    assert engine.ex.resubmitted == [("Q1", ["hunter2"])]
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
