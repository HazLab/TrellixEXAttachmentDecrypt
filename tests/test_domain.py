"""Unit tests for the pure flow logic (no network/SMTP/real DB I/O)."""

from __future__ import annotations

import pytest

from trellix_decrypt.domain import AlertEvent, FlowState, RiskwareRules, TokenService

from .conftest import TRIGGER_MALWARE_NAME


def _alert(name=TRIGGER_MALWARE_NAME, alert_name="RISKWARE_OBJECT", queue_id="Q1"):
    return AlertEvent(queue_id=queue_id, recipient="user@corp.test", subject="Invoice",
                      alert_name=alert_name, malware_names=[name])


def _malware_ra(queue_id="Q1_RA", names=("FE_Backdoor_Go_Sandcat_1",)):
    """A pushed _RA re-detection as EX really sends it: hyphenated lowercase alert name
    and no top-level `malicious` field (the verdict is the MALWARE_OBJECT name itself)."""
    return AlertEvent(queue_id=queue_id, recipient="user@corp.test", subject="Invoice",
                      alert_name="malware-object", malware_names=list(names))


async def _submit(engine, case_id, password="pw"):
    """Recipient submits the password, then drive the (decoupled) background rescan."""
    await engine.handle_password(engine.tokens.mint(case_id), password)
    await engine.resubmit_case(case_id)


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


async def test_ra_realert_folds_into_existing_case(engine):
    case = await engine.handle_alert(_alert(queue_id="QABC"))
    # EX re-quarantines the resubmitted email as <queue>_RA and pushes a new alert.
    result = await engine.handle_alert(_alert(queue_id="QABC_RA"))
    assert result.id == case.id                    # same case, not a new one
    assert len(engine.repo.list_cases()) == 1      # no duplicate entry
    assert len(engine.mailer.sent) == 1            # no second "new case" email


async def test_email_failure_recorded_not_raised(engine):
    engine.mailer.fail = True
    case = await engine.handle_alert(_alert())          # must not raise
    assert case.state == FlowState.NOTIFY_FAILED
    assert case.notify_attempts == 1
    assert engine.mailer.sent == []                      # nothing delivered


async def test_retry_sweep_resends_failed_then_succeeds(engine):
    engine.mailer.fail = True
    case = await engine.handle_alert(_alert())
    assert case.state == FlowState.NOTIFY_FAILED

    engine.mailer.fail = False                           # SMTP recovers
    await engine.retry_failed_notifications()
    assert engine.repo.get_case(case.id).state == FlowState.AWAITING_PASSWORD
    assert len(engine.mailer.sent) == 1


async def test_retry_sweep_respects_cap(engine):
    engine.mailer.fail = True
    case = await engine.handle_alert(_alert())           # attempt 1
    for _ in range(10):
        await engine.retry_failed_notifications()        # keeps failing
    # the sweep stops once notify_attempts reaches the configured cap
    assert engine.repo.get_case(case.id).notify_attempts <= engine.settings.notify_max_retries


async def test_manual_resend_after_recovery(engine):
    engine.mailer.fail = True
    case = await engine.handle_alert(_alert())
    engine.mailer.fail = False
    assert await engine.resend(case.id) is True
    assert engine.repo.get_case(case.id).state == FlowState.AWAITING_PASSWORD
    assert await engine.resend("no-such-case") is None   # invalid -> None


async def test_password_submission_decoupled_from_ex(engine):
    case = await engine.handle_alert(_alert())
    result, status = await engine.handle_password(engine.tokens.mint(case.id), "hunter2")
    # Recipient is acknowledged immediately; EX rescan is only scheduled, not awaited.
    assert status == "ok"
    assert result.state == FlowState.PASSWORD_SUBMITTED
    assert engine.scheduler.resubmits == [case.id]
    assert engine.ex.rescanned == []
    assert engine.repo.get_case(case.id).pwd_enc is not None  # held (encrypted) for the rescan

    # Driving the background step then performs the rescan and clears the password.
    await engine.resubmit_case(case.id)
    c = engine.repo.get_case(case.id)
    assert c.state == FlowState.RESUBMITTED
    assert engine.ex.rescanned == [("Q1", ["hunter2"])]
    assert c.pwd_enc is None
    assert engine.scheduler.scheduled == [case.id]


async def test_password_accepted_even_if_ex_rescan_fails(engine):
    case = await engine.handle_alert(_alert())
    engine.ex.rescan_fail = True
    _, status = await engine.handle_password(engine.tokens.mint(case.id), "pw")
    assert status == "ok"                                   # user's submission still succeeds
    await engine.resubmit_case(case.id)                     # background rescan fails
    assert engine.repo.get_case(case.id).state == FlowState.RESUBMIT_FAILED

    engine.ex.rescan_fail = False                           # EX fixed -> retry works without re-asking
    await engine.resubmit_case(case.id)                     # (same as the Retry-rescan button / sweep)
    assert engine.repo.get_case(case.id).state == FlowState.RESUBMITTED
    assert engine.ex.rescanned == [("Q1", ["pw"])]


async def test_resubmit_email_not_found_handled_cleanly(engine):
    case = await engine.handle_alert(_alert())
    engine.ex.rescan_not_found = True                       # EX 400 "email not quarantined"
    await engine.handle_password(engine.tokens.mint(case.id), "pw")
    await engine.resubmit_case(case.id)                     # must not crash the background task
    stored = engine.repo.get_case(case.id)
    assert stored.state == FlowState.RESUBMIT_FAILED
    assert stored.resubmit_attempts == 1                    # counted toward the bounded retry cap
    assert stored.pwd_enc                                   # password retained for the retry

    engine.ex.rescan_not_found = False                      # email (re)appears -> retry succeeds
    await engine.resubmit_case(case.id)
    assert engine.repo.get_case(case.id).state == FlowState.RESUBMITTED


async def test_resubmit_retry_sweep_recovers(engine):
    case = await engine.handle_alert(_alert())
    engine.ex.rescan_fail = True
    await engine.handle_password(engine.tokens.mint(case.id), "pw")
    await engine.resubmit_case(case.id)                     # -> RESUBMIT_FAILED, password retained
    assert engine.repo.get_case(case.id).state == FlowState.RESUBMIT_FAILED

    engine.ex.rescan_fail = False
    await engine.retry_failed_resubmissions()               # background sweep, no user involvement
    assert engine.repo.get_case(case.id).state == FlowState.RESUBMITTED


async def test_replayed_link_rejected_after_submission(engine):
    case = await engine.handle_alert(_alert())
    token = engine.tokens.mint(case.id)
    await engine.handle_password(token, "pw")
    _, status = await engine.handle_password(token, "pw")  # reuse
    assert status == "not_awaiting"


async def test_pushed_malicious_ra_stops(engine):
    case = await engine.handle_alert(_alert())
    await _submit(engine, case.id)                          # -> RESUBMITTED
    # EX re-analyzes, extracts with the correct password, finds malware, pushes _RA
    # (hyphenated 'malware-object', no extraction-failure marker).
    result = await engine.handle_alert(_malware_ra())
    assert result.id == case.id                            # correlated to the same case
    c = engine.repo.get_case(case.id)
    assert c.state == FlowState.DONE_MALICIOUS
    assert c.pwd_enc is None                               # held password purged


async def test_password_failed_marker_in_malware_alert_is_wrong_password(engine):
    # A wrong-password zip _RA arrives as a MALWARE_OBJECT alert (signature hits on the
    # encrypted blob) but names PASSWORD_EXTRACTION_FAILED — that marker is authoritative.
    case = await engine.handle_alert(_alert())
    await _submit(engine, case.id)                          # -> RESUBMITTED
    await engine.handle_alert(_malware_ra(names=["Malware.Parent.ZIP", "PASSWORD_EXTRACTION_FAILED"]))
    c = engine.repo.get_case(case.id)
    assert c.state == FlowState.AWAITING_PASSWORD          # re-asked, NOT marked malicious
    assert c.attempts == 1


async def test_RA_arriving_as_multiple_pushes_counts_once(engine):
    # The real log: a wrong-password zip _RA lands as three malware-object pushes; only
    # the first names PASSWORD_EXTRACTION_FAILED. Stays wrong-password, counts one attempt.
    case = await engine.handle_alert(_alert())
    await _submit(engine, case.id)
    await engine.handle_alert(_malware_ra(names=["Malware.Parent.ZIP", "PASSWORD_EXTRACTION_FAILED"]))
    await engine.handle_alert(_malware_ra(names=["Test.EICAR.1", "FE_Test_EICAR_1"]))
    await engine.handle_alert(_malware_ra(names=["CustomPolicy.MVX.com", "Test.EICAR.1"]))
    c = engine.repo.get_case(case.id)
    assert c.state == FlowState.AWAITING_PASSWORD
    assert c.attempts == 1                                 # not 3


async def test_password_failed_marker_reopens_if_malware_push_first(engine):
    # If a no-marker malware push lands before the PASSWORD_EXTRACTION_FAILED one, the
    # marker must still win and reopen the case for another attempt.
    case = await engine.handle_alert(_alert())
    await _submit(engine, case.id)
    await engine.handle_alert(_malware_ra(names=["Malware.Parent.ZIP"]))   # jumps to malicious
    assert engine.repo.get_case(case.id).state == FlowState.DONE_MALICIOUS
    await engine.handle_alert(_malware_ra(names=["Malware.Parent.ZIP", "PASSWORD_EXTRACTION_FAILED"]))
    c = engine.repo.get_case(case.id)
    assert c.state == FlowState.AWAITING_PASSWORD          # reopened
    assert c.attempts == 1


async def test_recheck_declares_clean_only_when_not_requarantined(engine):
    case = await engine.handle_alert(_alert())
    await _submit(engine, case.id)                          # -> RESUBMITTED
    engine.ex.ra_quarantined = False                       # no _RA entry remains
    assert await engine.recheck(case.id, final=False) is False   # wait for the pushed verdict
    assert engine.repo.get_case(case.id).state == FlowState.RECHECKING
    assert await engine.recheck(case.id, final=True) is True
    assert engine.repo.get_case(case.id).state == FlowState.DONE_CLEAN


async def test_recheck_backstop_fails_closed_when_still_requarantined(engine):
    # The verdict push was missed but the email is still re-quarantined: never declare
    # clean — treat as a wrong password (re-ask), so a held email is never released.
    case = await engine.handle_alert(_alert())
    await _submit(engine, case.id)
    engine.ex.ra_quarantined = True
    assert await engine.recheck(case.id, final=True) is True
    c = engine.repo.get_case(case.id)
    assert c.state == FlowState.AWAITING_PASSWORD          # re-asked, not DONE_CLEAN
    assert c.attempts == 1


async def test_wrong_password_retries_then_gives_up(engine):
    case = await engine.handle_alert(_alert())
    # 3 wrong-password rounds (max_password_attempts=3); each pushes a riskware _RA.
    for _ in range(3):
        await _submit(engine, case.id, "wrong")            # -> RESUBMITTED
        await engine.handle_alert(_alert(queue_id="Q1_RA"))  # still failed extraction
    assert engine.repo.get_case(case.id).state == FlowState.FAILED_MAX_RETRIES
    # one initial + two retry emails (third attempt hits the cap)
    assert len(engine.mailer.sent) == 3
