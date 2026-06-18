"""Alert parsing tests."""

from __future__ import annotations

from trellix_decrypt.ingest import iter_alerts, parse_alert


def test_parse_flat_alert():
    event = parse_alert({
        "queue_id": "ABC123", "recipient": "bob@corp.test",
        "rule_id": "65030", "sender": "ext@x.test", "subject": "Docs",
    })
    assert event.queue_id == "ABC123"
    assert event.recipient == "bob@corp.test"
    assert event.rule_id == 65030  # coerced to int


def test_parse_nested_smtp_message():
    event = parse_alert({
        "smtpMessage": {"queueId": "Q9", "rcptTo": "ann@corp.test", "subject": "Hi"},
        "explanation": {"malwareDetected": {"malware": [{"sid": 65001, "type": "riskware"}]}},
    })
    assert event.queue_id == "Q9"
    assert event.recipient == "ann@corp.test"
    assert event.rule_id == 65001
    assert event.malware_type == "riskware"


def test_iter_alerts_wraps_single_and_list():
    assert iter_alerts({"alert": [{"a": 1}, {"a": 2}]}) == [{"a": 1}, {"a": 2}]
    assert iter_alerts({"queue_id": "x"}) == [{"queue_id": "x"}]
