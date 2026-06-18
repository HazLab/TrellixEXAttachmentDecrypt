"""Alert parsing tests, including the real sample fixture (docs/sample_alert.json)."""

from __future__ import annotations

import json
from pathlib import Path

from trellix_decrypt.ingest import iter_alerts, parse_alert

SAMPLE = json.loads((Path(__file__).resolve().parents[1] / "docs" / "sample_alert.json").read_text())


def test_parse_flat_alert():
    event = parse_alert({
        "queue_id": "ABC123", "recipient": "bob@corp.test",
        "name": "RISKWARE_OBJECT", "sender": "ext@x.test", "subject": "Docs",
    })
    assert event.queue_id == "ABC123"
    assert event.recipient == "bob@corp.test"
    assert event.alert_name == "RISKWARE_OBJECT"


def test_parse_real_sample():
    alerts = iter_alerts(SAMPLE)
    assert len(alerts) == 2  # the "Alerts" wrapper is unwrapped

    first = parse_alert(alerts[0])
    assert first.queue_id == "4gh3zJ4CHGzmWwX"
    assert first.recipient == "head.sales@networkshark.com"
    assert first.sender == "sales@networkshark.com"
    assert first.subject == "Limited-Time HeliosGuard Savings"
    assert first.alert_name == "RISKWARE_OBJECT"
    assert first.malicious is False
    assert first.malware_names == ["Riskware.Parent.DOCX"]

    second = parse_alert(alerts[1])
    assert second.malware_names == ["CustomPolicy.MVX.65055.qrCodePresent"]


def test_iter_alerts_wraps_single_and_list():
    assert iter_alerts({"Alerts": [{"a": 1}, {"a": 2}]}) == [{"a": 1}, {"a": 2}]
    assert iter_alerts({"queue_id": "x"}) == [{"queue_id": "x"}]
