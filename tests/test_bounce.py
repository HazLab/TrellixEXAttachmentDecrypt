"""DSN parsing + bounce handling."""

from __future__ import annotations

from trellix_decrypt.bounce import parse_bounce
from trellix_decrypt.domain import AlertEvent, FlowState

from .conftest import make_context


def _dsn(case_id="CASE-1", recipient="head.sales@networkshark.com",
         status="5.1.1", action="failed", diagnostic="smtp; 550 5.1.1 user unknown"):
    return (
        "From: MAILER-DAEMON@mail.local\r\n"
        "To: attachment-help@corp.test\r\n"
        "Subject: Undelivered Mail Returned to Sender\r\n"
        'Content-Type: multipart/report; report-type=delivery-status; boundary="B"\r\n'
        "\r\n"
        "--B\r\n"
        "Content-Type: text/plain\r\n\r\nDelivery failed.\r\n"
        "--B\r\n"
        "Content-Type: message/delivery-status\r\n\r\n"
        f"Final-Recipient: rfc822; {recipient}\r\n"
        f"Action: {action}\r\n"
        f"Status: {status}\r\n"
        f"Diagnostic-Code: {diagnostic}\r\n\r\n"
        "--B\r\n"
        "Content-Type: text/rfc822-headers\r\n\r\n"
        f"X-Case-Id: {case_id}\r\n"
        "Subject: Password needed for your quarantined attachment\r\n\r\n"
        "--B--\r\n"
    ).encode()


def test_parse_bounce_extracts_case_recipient_reason():
    b = parse_bounce(_dsn())
    assert b["case_id"] == "CASE-1"
    assert b["recipient"] == "head.sales@networkshark.com"
    assert "5.1.1" in b["reason"]


def test_parse_bounce_ignores_non_failures():
    assert parse_bounce(_dsn(action="delivered")) is None
    assert parse_bounce(b"not a bounce at all") is None


def test_handle_bounce_marks_case_by_case_id():
    ctx = make_context()
    case = ctx.repo.get_or_create_case(AlertEvent(
        queue_id="Q1", recipients=["head.sales@networkshark.com"], alert_name="RISKWARE_OBJECT",
        malware_names=["CustomPolicy.MVX.zip"]))
    ctx.repo.set_state(case, FlowState.AWAITING_PASSWORD, "sent")

    assert ctx.engine.handle_bounce({"case_id": case.id, "recipient": None, "reason": "550 user unknown"})
    assert ctx.repo.get_case(case.id).state == FlowState.BOUNCED


def test_handle_bounce_falls_back_to_recipient():
    ctx = make_context()
    case = ctx.repo.get_or_create_case(AlertEvent(
        queue_id="Q2", recipients=["bob@corp.test"], alert_name="RISKWARE_OBJECT",
        malware_names=["CustomPolicy.MVX.zip"]))
    ctx.repo.set_state(case, FlowState.AWAITING_PASSWORD, "sent")

    assert ctx.engine.handle_bounce({"case_id": None, "recipient": "bob@corp.test", "reason": "bounced"})
    assert ctx.repo.get_case(case.id).state == FlowState.BOUNCED


def test_handle_bounce_does_not_override_terminal():
    ctx = make_context()
    case = ctx.repo.get_or_create_case(AlertEvent(
        queue_id="Q3", recipients=["x@corp.test"], alert_name="RISKWARE_OBJECT",
        malware_names=["CustomPolicy.MVX.zip"]))
    ctx.repo.set_state(case, FlowState.DONE_QUARANTINED, "quarantined")
    assert ctx.engine.handle_bounce({"case_id": case.id, "reason": "late bounce"}) is False
    assert ctx.repo.get_case(case.id).state == FlowState.DONE_QUARANTINED
