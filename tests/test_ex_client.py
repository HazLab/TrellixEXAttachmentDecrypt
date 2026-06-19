"""EX client tests with the HTTP layer mocked by respx (paths from the API PDFs)."""

from __future__ import annotations

import httpx
import respx

from trellix_decrypt import ex_client as ex
from trellix_decrypt.domain import QuarantineOutcome, RiskwareRules

from .conftest import TRIGGER_MALWARE_NAME

BASE = "https://ex.test"
RULES = RiskwareRules([TRIGGER_MALWARE_NAME], "RISKWARE_OBJECT")
RECIPIENT = "head.sales@networkshark.com"


def _client():
    return ex.EXClient(BASE, "user", "pass", verify_tls=False)


def _mock_login(router):
    router.post(BASE + ex.EP_LOGIN).mock(
        return_value=httpx.Response(200, headers={ex.TOKEN_HEADER: "tok-123"}))


def _alert(queue_id, name, malware, malicious="no"):
    return {
        "name": name, "malicious": malicious,
        "smtpMessage": {"queueId": queue_id},
        "dst": {"smtpTo": RECIPIENT},
        "explanation": {"malwareDetected": {"malware": [{"name": malware}]}},
    }


@respx.mock
async def test_rescan_target_picks_rescannable_entry_not_RA():
    router = respx.mock
    _mock_login(router)
    # Both the rescannable original (has quarantine_path) and the _RA re-analysis
    # record (null path) are present; only the original is rescannable.
    router.get(BASE + ex.EP_QUARANTINE).mock(return_value=httpx.Response(200, json=[
        {"email_uuid": "uuid-RA", "queue_id": "Q1_RA", "quarantine_path": None},
        {"email_uuid": "uuid-orig", "queue_id": "Q1", "quarantine_path": "/data/.../Q1"},
    ]))
    rescan = router.post(url__regex=rf"{BASE}{ex.EP_QUARANTINE_RESCAN}/.*").mock(
        return_value=httpx.Response(200, json={"ok": True}))

    client = _client()
    assert await client.rescan_target("Q1", "s@x", "subj") == ("Q1", "uuid-orig")  # not the _RA
    await client.rescan("Q1", ["pw1"])
    assert rescan.calls.last.request.url.path.endswith("/rescan/Q1")
    await client.aclose()


@respx.mock
async def test_rescan_target_none_when_only_RA():
    router = respx.mock
    _mock_login(router)
    router.get(BASE + ex.EP_QUARANTINE).mock(return_value=httpx.Response(200, json=[
        {"email_uuid": "uuid-RA", "queue_id": "Q1_RA", "quarantine_path": None}]))
    client = _client()
    assert await client.rescan_target("Q1", "s@x", "subj") == (None, None)  # nothing rescannable
    await client.aclose()


@respx.mock
async def test_classify_not_quarantined():
    router = respx.mock
    _mock_login(router)
    # Only the original remains (no _RA re-analysis record) -> delivered/clean.
    router.get(BASE + ex.EP_QUARANTINE).mock(return_value=httpx.Response(200, json=[
        {"email_uuid": "u", "queue_id": "Q1", "quarantine_path": "/p"}]))
    client = _client()
    assert await client.classify_resubmission("Q1", "s@x", "subj", RULES) is QuarantineOutcome.NOT_QUARANTINED
    await client.aclose()


@respx.mock
async def test_classify_failed_extraction_via_alert_uuid():
    router = respx.mock
    _mock_login(router)
    # _RA re-analysis record present; its alert is still a riskware trigger.
    router.get(BASE + ex.EP_QUARANTINE).mock(return_value=httpx.Response(200, json=[
        {"queue_id": "Q1_RA", "quarantine_path": None, "alert_uuids": ["a-1"]}]))
    router.get(BASE + ex.EP_ALERT_DETAILS + "/a-1").mock(return_value=httpx.Response(200, json={"alert": [
        _alert("Q1_RA", "RISKWARE_OBJECT", TRIGGER_MALWARE_NAME)]}))
    client = _client()
    assert await client.classify_resubmission("Q1", "s@x", "subj", RULES) is QuarantineOutcome.FAILED_EXTRACTION
    await client.aclose()


@respx.mock
async def test_classify_malicious_via_alert_uuid():
    router = respx.mock
    _mock_login(router)
    router.get(BASE + ex.EP_QUARANTINE).mock(return_value=httpx.Response(200, json=[
        {"queue_id": "Q1_RA", "quarantine_path": None, "alert_uuids": ["a-2"]}]))
    router.get(BASE + ex.EP_ALERT_DETAILS + "/a-2").mock(return_value=httpx.Response(200, json={"alert": [
        _alert("Q1_RA", "MALWARE_OBJECT", "FE_Backdoor_Go_Sandcat_1", malicious="yes")]}))
    client = _client()
    assert await client.classify_resubmission("Q1", "s@x", "subj", RULES) is QuarantineOutcome.MALICIOUS
    await client.aclose()


@respx.mock
async def test_reauth_on_401():
    router = respx.mock
    router.post(BASE + ex.EP_LOGIN).mock(return_value=httpx.Response(200, headers={ex.TOKEN_HEADER: "tok"}))
    route = router.get(BASE + ex.EP_ALERTS).mock(
        side_effect=[httpx.Response(401), httpx.Response(200, json={"alert": []})])
    client = _client()
    assert await client.get_alerts() == {"alert": []}
    assert route.call_count == 2
    await client.aclose()
