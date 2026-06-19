"""Alert parsing tests, including the real sample fixtures under docs/."""

from __future__ import annotations

import json
from pathlib import Path

from trellix_decrypt.domain import RiskwareRules, iter_alerts, parse_alert

from .conftest import TRIGGER_MALWARE_NAME

DOCS = Path(__file__).resolve().parents[1] / "docs"
WEBHOOK_SAMPLE = json.loads((DOCS / "sample_alert.json").read_text())        # "Alerts" envelope
QUERY_SAMPLE = json.loads((DOCS / "sample_alerts_query.json").read_text())   # "alert" envelope


def test_parse_flat_alert():
    event = parse_alert({"queue_id": "ABC123", "recipient": "bob@corp.test",
                         "name": "RISKWARE_OBJECT", "subject": "Docs"})
    assert event.queue_id == "ABC123"
    assert event.recipient == "bob@corp.test"
    assert event.alert_name == "RISKWARE_OBJECT"


def test_parse_webhook_sample():
    alerts = iter_alerts(WEBHOOK_SAMPLE)
    assert len(alerts) == 2  # "Alerts" envelope unwrapped

    first = parse_alert(alerts[0])
    assert first.queue_id == "4gh3zJ4CHGzmWwX"
    assert first.recipient == "head.sales@networkshark.com"
    assert first.sender == "sales@networkshark.com"
    assert first.subject == "Limited-Time HeliosGuard Savings"
    assert first.alert_name == "RISKWARE_OBJECT"
    assert first.malicious is False
    assert first.malware_names == ["Riskware.Parent.DOCX"]


def test_query_sample_distinguishes_trigger_riskware_and_malware():
    rules = RiskwareRules(["CustomPolicy.MVX.pdf", "CustomPolicy.MVX.zip", "CustomPolicy.MVX.docx"], "RISKWARE_OBJECT")
    events = {parse_alert(a).malware_names[0]: parse_alert(a) for a in iter_alerts(QUERY_SAMPLE)}

    assert rules.matches(events["CustomPolicy.MVX.pdf"])                 # encrypted attachment -> trigger
    assert not rules.matches(events["CustomPolicy.MVX.65055.qrCodePresent"])  # other policy -> no
    malware = events["FE_Backdoor_Go_Sandcat_1"]
    assert malware.alert_name == "MALWARE_OBJECT" and malware.malicious is True
    assert not rules.matches(malware)                                    # malicious -> not a trigger


def test_parse_http_notification_push_format():
    # Hyphenated keys with {"value": ...} wrappers, lowercase-hyphen alert name.
    push = {"alert": [{
        "name": "riskware-object",
        "malicious": "no",
        "queue-id": "4gh3zJ4CHGzmWwX",
        "dst": {"smtp-to": {"value": "head.sales@networkshark.com"}},
        "src": {"smtp-mail-from": {"value": "sales@networkshark.com"}},
        "smtp-message": {"subject": {"value": "Encrypted doc"}},
        "explanation": {"malware-detected": {"malware": [{"name": "CustomPolicy.MVX.zip"}]}},
    }]}
    event = parse_alert(iter_alerts(push)[0])
    assert event.queue_id == "4gh3zJ4CHGzmWwX"
    assert event.recipient == "head.sales@networkshark.com"
    assert event.sender == "sales@networkshark.com"
    assert event.subject == "Encrypted doc"
    assert event.alert_name == "riskware-object"
    assert event.malware_names == ["CustomPolicy.MVX.zip"]

    # And it triggers: alert name normalizes (riskware-object == RISKWARE_OBJECT).
    rules = RiskwareRules(["CustomPolicy.MVX.zip"], "RISKWARE_OBJECT")
    assert rules.matches(event)


def test_iter_alerts_handles_both_envelopes_and_single():
    assert iter_alerts({"Alerts": [{"a": 1}]}) == [{"a": 1}]
    assert iter_alerts({"alert": [{"a": 1}, {"a": 2}]}) == [{"a": 1}, {"a": 2}]
    assert iter_alerts({"queue_id": "x"}) == [{"queue_id": "x"}]
