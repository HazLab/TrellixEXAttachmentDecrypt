"""EX client tests with the HTTP layer mocked by respx."""

from __future__ import annotations

import httpx
import respx

from trellix_decrypt import ex_client as ex
from trellix_decrypt.domain import QuarantineOutcome, RiskwareRules

from .conftest import TRIGGER_MALWARE_NAME

BASE = "https://ex.test"
RULES = RiskwareRules([TRIGGER_MALWARE_NAME], "RISKWARE_OBJECT")


def _client():
    return ex.EXClient(BASE, "user", "pass", verify_tls=False)


def _mock_login(router):
    router.post(BASE + ex.EP_LOGIN).mock(
        return_value=httpx.Response(200, headers={ex.TOKEN_HEADER: "tok-123"})
    )


@respx.mock
async def test_resubmit_authenticates_then_posts():
    router = respx.mock
    _mock_login(router)
    submit = router.post(BASE + ex.EP_QUARANTINE_RESUBMIT).mock(return_value=httpx.Response(200, json={"ok": True}))

    client = _client()
    result = await client.resubmit("Q1", ["pw1", "pw2"])
    await client.aclose()

    assert result == {"ok": True}
    assert submit.called
    sent = submit.calls.last.request
    assert sent.headers[ex.TOKEN_HEADER] == "tok-123"


def _alert(queue_id, name, malware, malicious="no"):
    return {
        "name": name, "malicious": malicious,
        "smtpMessage": {"queueId": queue_id},
        "explanation": {"malwareDetected": {"malware": [{"name": malware}]}},
    }


@respx.mock
async def test_classify_not_quarantined():
    router = respx.mock
    _mock_login(router)
    # Only the original (pre-resubmit) alert exists, not the _RA one.
    router.get(BASE + ex.EP_ALERTS).mock(return_value=httpx.Response(
        200, json={"alert": [_alert("Q1", "RISKWARE_OBJECT", TRIGGER_MALWARE_NAME)]}))
    client = _client()
    assert await client.classify_resubmission("Q1", RULES) is QuarantineOutcome.NOT_QUARANTINED
    await client.aclose()


@respx.mock
async def test_classify_failed_extraction_vs_malicious():
    router = respx.mock
    _mock_login(router)
    a = router.get(BASE + ex.EP_ALERTS)

    a.mock(return_value=httpx.Response(200, json={"alert": [
        _alert("Q1_RA", "RISKWARE_OBJECT", TRIGGER_MALWARE_NAME)]}))
    client = _client()
    assert await client.classify_resubmission("Q1", RULES) is QuarantineOutcome.FAILED_EXTRACTION

    a.mock(return_value=httpx.Response(200, json={"alert": [
        _alert("Q1_RA", "MALWARE_OBJECT", "FE_Backdoor_Go_Sandcat_1", malicious="yes")]}))
    assert await client.classify_resubmission("Q1", RULES) is QuarantineOutcome.MALICIOUS
    await client.aclose()


@respx.mock
async def test_reauth_on_401():
    router = respx.mock
    router.post(BASE + ex.EP_LOGIN).mock(return_value=httpx.Response(200, headers={ex.TOKEN_HEADER: "tok"}))
    # First call 401, retry succeeds.
    route = router.get(BASE + ex.EP_ALERTS).mock(
        side_effect=[httpx.Response(401), httpx.Response(200, json={"alert": []})]
    )
    client = _client()
    assert await client.get_alerts() == {"alert": []}
    assert route.call_count == 2
    await client.aclose()
