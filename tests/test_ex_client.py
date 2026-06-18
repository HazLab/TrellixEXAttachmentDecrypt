"""EX client tests with the HTTP layer mocked by respx."""

from __future__ import annotations

import httpx
import respx

from trellix_decrypt import ex_client as ex
from trellix_decrypt.domain import QuarantineOutcome, RiskwareRules

BASE = "https://ex.test"
RULES = RiskwareRules([65001, 65030])


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


@respx.mock
async def test_classify_not_quarantined():
    router = respx.mock
    _mock_login(router)
    router.get(BASE + ex.EP_QUARANTINE).mock(return_value=httpx.Response(200, json={"email": []}))
    client = _client()
    assert await client.classify_resubmission("Q1", RULES) is QuarantineOutcome.NOT_QUARANTINED
    await client.aclose()


@respx.mock
async def test_classify_failed_extraction_vs_malicious():
    router = respx.mock
    _mock_login(router)
    q = router.get(BASE + ex.EP_QUARANTINE)

    q.mock(return_value=httpx.Response(200, json=[{"queue_id": "Q1_RA", "rule_id": 65001}]))
    client = _client()
    assert await client.classify_resubmission("Q1", RULES) is QuarantineOutcome.FAILED_EXTRACTION

    q.mock(return_value=httpx.Response(200, json=[{"queue_id": "Q1_RA", "rule_id": 30100}]))
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
