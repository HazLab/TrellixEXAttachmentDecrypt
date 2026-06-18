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
async def test_current_queue_id_and_rescan():
    router = respx.mock
    _mock_login(router)
    # On a retry the email is re-quarantined under the original id + suffix.
    router.get(BASE + ex.EP_QUARANTINE).mock(return_value=httpx.Response(200, json=[
        {"email_uuid": "u", "queue_id": "Q1_RA", "from": "x@y.test", "subject": "s"},
    ]))
    rescan = router.post(url__regex=rf"{BASE}{ex.EP_QUARANTINE_RESCAN}/.*").mock(
        return_value=httpx.Response(200, json={"ok": True}))

    client = _client()
    assert await client.current_queue_id("Q1") == "Q1_RA"  # reads EX-appended suffix

    await client.rescan("Q1_RA", ["pw1", "pw2"])
    sent = rescan.calls.last.request
    assert sent.url.path.endswith("/rescan/Q1_RA")
    import json
    assert json.loads(sent.content) == {"rescan_properties": {"pwd_list": ["pw1", "pw2"]}}
    await client.aclose()


@respx.mock
async def test_classify_not_quarantined():
    router = respx.mock
    _mock_login(router)
    # Quarantine has only the original (no _RA re-quarantine) -> delivered/clean.
    router.get(BASE + ex.EP_QUARANTINE).mock(return_value=httpx.Response(200, json=[
        {"email_uuid": "u", "queue_id": "Q1"}]))
    client = _client()
    assert await client.classify_resubmission("Q1", RECIPIENT, RULES) is QuarantineOutcome.NOT_QUARANTINED
    await client.aclose()


@respx.mock
async def test_classify_failed_extraction():
    router = respx.mock
    _mock_login(router)
    router.get(BASE + ex.EP_QUARANTINE).mock(return_value=httpx.Response(200, json=[
        {"email_uuid": "u", "queue_id": "Q1_RA"}]))  # re-quarantined (EX appended _RA)
    router.get(BASE + ex.EP_ALERTS).mock(return_value=httpx.Response(200, json={"alert": [
        _alert("Q1_RA", "RISKWARE_OBJECT", TRIGGER_MALWARE_NAME)]}))
    client = _client()
    assert await client.classify_resubmission("Q1", RECIPIENT, RULES) is QuarantineOutcome.FAILED_EXTRACTION
    await client.aclose()


@respx.mock
async def test_classify_malicious():
    router = respx.mock
    _mock_login(router)
    router.get(BASE + ex.EP_QUARANTINE).mock(return_value=httpx.Response(200, json=[
        {"email_uuid": "u", "queue_id": "Q1_RA"}]))
    router.get(BASE + ex.EP_ALERTS).mock(return_value=httpx.Response(200, json={"alert": [
        _alert("Q1_RA", "MALWARE_OBJECT", "FE_Backdoor_Go_Sandcat_1", malicious="yes")]}))
    client = _client()
    assert await client.classify_resubmission("Q1", RECIPIENT, RULES) is QuarantineOutcome.MALICIOUS
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
