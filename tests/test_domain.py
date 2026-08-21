"""Unit tests for the pure flow logic (no network/SMTP/real DB I/O)."""

from __future__ import annotations

import pytest

from trellix_decrypt.domain import AlertEvent, FlowState, RiskwareRules, TokenService

from .conftest import TRIGGER_MALWARE_NAME


def _alert(name=TRIGGER_MALWARE_NAME, alert_name="RISKWARE_OBJECT", queue_id="Q1"):
    return AlertEvent(queue_id=queue_id, recipients=["user@corp.test"], subject="Invoice",
                      alert_name=alert_name, malware_names=[name])


def _malware_ra(queue_id="Q1_RA", names=("FE_Backdoor_Go_Sandcat_1",)):
    """A pushed _RA re-detection as EX really sends it: hyphenated lowercase alert name
    and no top-level `malicious` field (the verdict is the MALWARE_OBJECT name itself)."""
    return AlertEvent(queue_id=queue_id, recipients=["user@corp.test"], subject="Invoice",
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


# --- alert detail (display) -------------------------------------------------
def test_parse_alert_detail_extracts_display_fields():
    import json
    from pathlib import Path

    from trellix_decrypt.domain import parse_alert_detail
    raw = json.loads(Path("docs/sample alert response by uuid.json").read_text())["alert"][0]
    d = parse_alert_detail(raw)
    assert d["name"] == "MALWARE_OBJECT"
    assert d["malicious"] is True
    assert d["severity"] == "MAJR"
    assert d["action"] == "blocked"
    assert d["queue_id"] == "4h7F8c082jz68C5P_RA"
    assert d["uuid"] == "22a6e16f-b4b0-440a-8896-ca684f442ab2"
    assert d["alert_url"].startswith("https://")
    assert d["malware"][0]["name"] == "Malware.Parent.DOCX"
    assert d["malware"][0]["sha256"].startswith("f4f5b844")


async def test_alert_details_for_case_fetches_all_uuids(engine):
    case = await engine.handle_alert(_alert())
    engine.ex.alert_uuids = ["a-1", "a-2"]
    engine.ex.alerts = {
        "a-1": {"uuid": "a-1", "name": "MALWARE_OBJECT", "malicious": "yes",
                "explanation": {"malwareDetected": {"malware": [{"name": "Malware.Parent.DOCX"}]}}},
        "a-2": {"uuid": "a-2", "name": "RISKWARE_OBJECT", "malicious": "no"},
    }
    details = await engine.alert_details_for_case(case.id)
    assert [d["uuid"] for d in details] == ["a-1", "a-2"]
    assert details[0]["malware"][0]["name"] == "Malware.Parent.DOCX"


async def test_alert_details_for_case_unknown_case_is_empty(engine):
    assert await engine.alert_details_for_case("nope") == []


async def test_alert_details_hides_pre_extraction_but_keeps_ra(engine):
    # The original encrypted-attachment trigger alert is hidden (redundant); an _RA
    # re-detection (still encrypted / wrong password) is kept.
    case = await engine.handle_alert(_alert(queue_id="Q1"))
    engine.ex.alert_uuids = ["orig", "ra"]
    engine.ex.alerts = {
        "orig": {"uuid": "orig", "name": "RISKWARE_OBJECT", "malicious": "no",
                 "smtpMessage": {"queueId": "Q1"},
                 "explanation": {"malwareDetected": {"malware": [{"name": "CustomPolicy.MVX.pdf"}]}}},
        "ra": {"uuid": "ra", "name": "RISKWARE_OBJECT", "malicious": "no",
               "smtpMessage": {"queueId": "Q1_RA"},
               "explanation": {"malwareDetected": {"malware": [{"name": "CustomPolicy.MVX.pdf"}]}}},
    }
    details = await engine.alert_details_for_case(case.id)
    assert [d["uuid"] for d in details] == ["ra"]  # original pre-extraction alert hidden


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


async def test_multi_recipient_email_goes_to_all(engine):
    ev = AlertEvent(queue_id="QM", recipients=["alice@corp.test", "bob@corp.test"],
                    alert_name="RISKWARE_OBJECT", malware_names=[TRIGGER_MALWARE_NAME], subject="Invoice")
    case = await engine.handle_alert(ev)
    assert case.state == FlowState.AWAITING_PASSWORD
    assert engine.repo.get_case(case.id).recipient == "alice@corp.test, bob@corp.test"  # both stored on one case
    recipients, _link, _retry = engine.mailer.sent[0]
    assert recipients == ["alice@corp.test", "bob@corp.test"]  # link emailed to all To recipients


async def test_separate_alerts_same_queue_merge_recipients(engine):
    # If EX emits one alert per recipient for the same email, the recipients accumulate
    # onto the single case (keyed by queue_id) rather than creating duplicates.
    await engine.handle_alert(AlertEvent(queue_id="QS", recipients=["a@corp.test"],
                                         alert_name="RISKWARE_OBJECT", malware_names=[TRIGGER_MALWARE_NAME]))
    case = await engine.handle_alert(AlertEvent(queue_id="QS", recipients=["b@corp.test"],
                                                alert_name="RISKWARE_OBJECT", malware_names=[TRIGGER_MALWARE_NAME]))
    assert len(engine.repo.list_cases()) == 1
    assert engine.repo.get_case(case.id).recipient == "a@corp.test, b@corp.test"


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


async def test_pushed_ra_quarantined_stops(engine):
    case = await engine.handle_alert(_alert())
    await _submit(engine, case.id)                          # -> RESUBMITTED
    # EX re-analyzes with the correct password and re-quarantines the email; the push
    # (no still-encrypted marker) triggers a decision, confirmed against the quarantine.
    engine.ex.ra_quarantined = True                        # the _RA is genuinely held
    result = await engine.handle_alert(_malware_ra())
    assert result.id == case.id                            # correlated to the same case
    c = engine.repo.get_case(case.id)
    assert c.state == FlowState.DONE_QUARANTINED
    assert c.pwd_enc is None                               # held password purged


async def test_ra_quarantined_as_riskware_object_stops(engine):
    # The re-detection type is not trusted: whether it's a riskware- or malware-object,
    # the verdict is the quarantine list. A non-encrypted _RA that is genuinely held
    # (ra_quarantined=True) -> DONE_QUARANTINED regardless of the pushed alert name.
    case = await engine.handle_alert(_alert())
    await _submit(engine, case.id)                          # -> RESUBMITTED
    engine.ex.ra_quarantined = True
    await engine.handle_alert(AlertEvent(
        queue_id="Q1_RA", recipients=["user@corp.test"], subject="Invoice",
        alert_name="riskware-object", malware_names=["CustomPolicy.MVX.SomeOtherRule"]))
    c = engine.repo.get_case(case.id)
    assert c.state == FlowState.DONE_QUARANTINED
    assert c.pwd_enc is None


async def test_ra_pushed_but_not_actually_quarantined_is_passed(engine):
    # The bug this flow fixes: a riskware rule can alert *without* quarantining. A push
    # arrives, but the quarantine list shows no _RA -> the email passed, not "malicious".
    case = await engine.handle_alert(_alert())
    await _submit(engine, case.id)                          # -> RESUBMITTED
    engine.ex.ra_quarantined = False                       # alerted but NOT held
    await engine.handle_alert(AlertEvent(
        queue_id="Q1_RA", recipients=["user@corp.test"], subject="Invoice",
        alert_name="riskware-object", malware_names=["CustomPolicy.MVX.SomeOtherRule"]))
    assert engine.repo.get_case(case.id).state == FlowState.DONE_PASSED


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


def _last_detail(engine, case_id, state):
    """The detail of the most recent timeline event in the given state."""
    events = [e for e in engine.repo.case_detail(case_id)["events"] if e["state"] == state.value]
    return events[-1]["detail"] if events else ""


async def test_quarantined_records_the_pushed_detection_detail(engine):
    # The alert detail (type + malware names) that the removed API lookup used to surface
    # now rides in on the push and must land on the timeline when the email is held.
    case = await engine.handle_alert(_alert())
    await _submit(engine, case.id)
    engine.ex.ra_quarantined = True
    await engine.handle_alert(_malware_ra(names=["FE_Backdoor_Go_Sandcat_1"]))
    detail = _last_detail(engine, case.id, FlowState.DONE_QUARANTINED)
    assert "malware-object" in detail
    assert "FE_Backdoor_Go_Sandcat_1" in detail


async def test_wrong_password_retry_records_the_still_encrypted_marker(engine):
    # A wrong-password re-ask should say why: the still-encrypted detection that triggered it.
    case = await engine.handle_alert(_alert())
    await _submit(engine, case.id)
    await engine.handle_alert(_malware_ra(names=["Malware.Parent.ZIP", "PASSWORD_EXTRACTION_FAILED"]))
    detail = _last_detail(engine, case.id, FlowState.AWAITING_PASSWORD)
    assert "wrong password" in detail
    assert "PASSWORD_EXTRACTION_FAILED" in detail


async def test_recheck_timer_outcome_has_no_detection_suffix(engine):
    # No push (recheck-timer path) -> _detection_summary is empty -> plain detail, no dangling dash.
    case = await engine.handle_alert(_alert())
    await _submit(engine, case.id)
    engine.ex.ra_quarantined = True
    await engine.recheck(case.id, final=True)
    detail = _last_detail(engine, case.id, FlowState.DONE_QUARANTINED)
    assert detail == "re-quarantined after resubmission: held"


async def test_password_failed_marker_reopens_if_quarantine_push_first(engine):
    # If a no-marker re-quarantine push lands before the PASSWORD_EXTRACTION_FAILED one,
    # the marker must still win and reopen the case for another attempt.
    case = await engine.handle_alert(_alert())
    await _submit(engine, case.id)
    engine.ex.ra_quarantined = True
    await engine.handle_alert(_malware_ra(names=["Malware.Parent.ZIP"]))   # jumps to quarantined
    assert engine.repo.get_case(case.id).state == FlowState.DONE_QUARANTINED
    await engine.handle_alert(_malware_ra(names=["Malware.Parent.ZIP", "PASSWORD_EXTRACTION_FAILED"]))
    c = engine.repo.get_case(case.id)
    assert c.state == FlowState.AWAITING_PASSWORD          # reopened
    assert c.attempts == 1


async def test_recheck_declares_passed_only_when_not_requarantined(engine):
    case = await engine.handle_alert(_alert())
    await _submit(engine, case.id)                          # -> RESUBMITTED
    engine.ex.ra_quarantined = False                       # no _RA entry remains
    assert await engine.recheck(case.id, final=False) is False   # wait for the pushed verdict
    assert engine.repo.get_case(case.id).state == FlowState.RECHECKING
    assert await engine.recheck(case.id, final=True) is True
    assert engine.repo.get_case(case.id).state == FlowState.DONE_PASSED


async def test_recheck_declares_quarantined_when_still_requarantined(engine):
    # No verdict push arrived, but the final poll finds the _RA still held: the email
    # is quarantined (terminal), never passed.
    case = await engine.handle_alert(_alert())
    await _submit(engine, case.id)
    engine.ex.ra_quarantined = True
    assert await engine.recheck(case.id, final=True) is True
    assert engine.repo.get_case(case.id).state == FlowState.DONE_QUARANTINED


async def test_recheck_releases_early_when_original_gone(engine):
    # Clean content pushes nothing, but once EX has released the original (no _RA, no
    # original) the poll concludes DONE_PASSED immediately — no waiting for the deadline.
    case = await engine.handle_alert(_alert())
    await _submit(engine, case.id)                     # -> RESUBMITTED
    engine.ex.ra_quarantined = False
    engine.ex.original_quarantined = False             # released/delivered
    assert await engine.recheck(case.id, final=False) is True
    assert engine.repo.get_case(case.id).state == FlowState.DONE_PASSED


async def test_recheck_keeps_polling_while_pending(engine):
    # Original still quarantined and no _RA yet = analysis unfinished -> keep polling.
    case = await engine.handle_alert(_alert())
    await _submit(engine, case.id)
    engine.ex.ra_quarantined = False
    engine.ex.original_quarantined = True
    assert await engine.recheck(case.id, final=False) is False
    assert engine.repo.get_case(case.id).state == FlowState.RECHECKING


async def test_recheck_held_concludes_on_any_poll(engine):
    # The _RA appearing is decisive on any poll, not just the final one.
    case = await engine.handle_alert(_alert())
    await _submit(engine, case.id)
    engine.ex.ra_quarantined = True
    assert await engine.recheck(case.id, final=False) is True
    assert engine.repo.get_case(case.id).state == FlowState.DONE_QUARANTINED


async def test_wrong_password_retries_then_gives_up(engine):
    case = await engine.handle_alert(_alert())
    # 3 wrong-password rounds (max_password_attempts=3); each pushes a riskware _RA.
    for _ in range(3):
        await _submit(engine, case.id, "wrong")            # -> RESUBMITTED
        await engine.handle_alert(_alert(queue_id="Q1_RA"))  # still failed extraction
    assert engine.repo.get_case(case.id).state == FlowState.FAILED_MAX_RETRIES
    # one initial + two retry emails (third attempt hits the cap)
    assert len(engine.mailer.sent) == 3


def _raw_alert(qid, rcpt="u@corp.test", alert_name="RISKWARE_OBJECT", malware=TRIGGER_MALWARE_NAME):
    """A raw EX alert dict (as returned by get_alert_by_uuid / the alerts query)."""
    return {"name": alert_name, "malicious": "no",
            "dst": {"smtpTo": rcpt},
            "smtpMessage": {"queueId": qid, "subject": "Invoice"},
            "explanation": {"malwareDetected": {"malware": [{"name": malware}]}}}


def _held(qid, alert_uuids):
    """A raw EX quarantine list entry (currently held)."""
    return {"queue_id": qid, "alert_uuids": list(alert_uuids)}


async def test_reconcile_backfills_only_held_matching_emails(engine):
    # Quarantine-first: the held set is authoritative; each entry's trigger is confirmed
    # from its alerts (fetched by UUID).
    engine.ex.held = [
        _held("Q-A", ["UA"]),        # new + matches -> create + email
        _held("Q-B", ["UB"]),        # wrong alert name -> skip
        _held("Q-C", ["UC"]),        # wrong malware -> skip
        _held("Q-D_RA", ["UD"]),     # _RA re-detection -> skip (recheck owns it)
    ]
    engine.ex.alerts = {
        "UA": _raw_alert("Q-A"),
        "UB": _raw_alert("Q-B", alert_name="MALWARE_OBJECT"),
        "UC": _raw_alert("Q-C", malware="Other.thing"),
        "UD": _raw_alert("Q-D_RA"),
    }
    res = await engine.reconcile()
    assert res["created"] == 1 and res["held"] == 4
    assert engine.repo.find_case_by_queue_id("Q-A") is not None
    assert engine.repo.find_case_by_queue_id("Q-B") is None
    assert engine.repo.find_case_by_queue_id("Q-C") is None
    assert engine.repo.find_case_by_queue_id("Q-D_RA") is None
    assert len(engine.mailer.sent) == 1                   # emailed the backfilled recipient


async def test_reconcile_ignores_alerted_but_not_quarantined(engine):
    # A trigger alert exists in the alerts list, but the email is NOT held (alert-but-allow)
    # -> nothing to recover, so no case and no email. This is the quarantine-first win.
    engine.ex.held = []
    engine.ex.alerts_payload = {"alert": [_raw_alert("Q-ALLOW")]}
    res = await engine.reconcile()
    assert res["created"] == 0
    assert engine.repo.find_case_by_queue_id("Q-ALLOW") is None
    assert len(engine.mailer.sent) == 0


async def test_reconcile_alerts_fallback_when_entry_lacks_uuid_linkage(engine):
    # Held entry carries NO alert_uuids, so quarantine-first can't confirm the trigger;
    # the alerts fallback (constrained to the held set) recovers it.
    engine.ex.held = [_held("Q-NOUUID", [])]
    engine.ex.alerts_payload = {"alert": [_raw_alert("Q-NOUUID")]}
    res = await engine.reconcile()
    assert res["created"] == 1
    assert engine.repo.find_case_by_queue_id("Q-NOUUID") is not None
    assert len(engine.mailer.sent) == 1


async def test_reconcile_is_idempotent(engine):
    engine.ex.held = [_held("Q-A", ["UA"])]
    engine.ex.alerts = {"UA": _raw_alert("Q-A")}
    await engine.reconcile()
    r2 = await engine.reconcile()                         # second run: already known
    assert r2["created"] == 0 and r2["already_known"] == 1
    assert sum(1 for c in engine.repo.list_cases() if c["queue_id"] == "Q-A") == 1
    assert len(engine.mailer.sent) == 1                   # no duplicate email


async def test_reconcile_noop_when_ex_not_configured(engine):
    engine.settings.ex_base_url = ""                      # e.g. setup mode
    res = await engine.reconcile()
    assert res["created"] == 0 and res.get("note") == "EX not configured"
