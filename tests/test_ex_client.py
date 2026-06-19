"""EX client tests with the HTTP layer mocked by respx (paths from the API PDFs)."""

from __future__ import annotations

import httpx
import respx

from trellix_decrypt import ex_client as ex

BASE = "https://ex.test"


def _client():
    return ex.EXClient(BASE, "user", "pass", verify_tls=False)


def _mock_login(router):
    router.post(BASE + ex.EP_LOGIN).mock(
        return_value=httpx.Response(200, headers={ex.TOKEN_HEADER: "tok-123"}))


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
async def test_has_resubmission_quarantine_true_when_RA_present():
    router = respx.mock
    _mock_login(router)
    # An _RA re-analysis record alongside the original means it was re-quarantined.
    router.get(BASE + ex.EP_QUARANTINE).mock(return_value=httpx.Response(200, json=[
        {"queue_id": "Q1", "quarantine_path": "/p"},
        {"queue_id": "Q1_RA", "quarantine_path": None},
    ]))
    client = _client()
    assert await client.has_resubmission_quarantine("Q1", "s@x", "subj") is True
    await client.aclose()


@respx.mock
async def test_has_resubmission_quarantine_false_when_only_original():
    router = respx.mock
    _mock_login(router)
    # Only the original remains (no _RA) -> released/delivered.
    router.get(BASE + ex.EP_QUARANTINE).mock(return_value=httpx.Response(200, json=[
        {"queue_id": "Q1", "quarantine_path": "/p"}]))
    client = _client()
    assert await client.has_resubmission_quarantine("Q1", "s@x", "subj") is False
    await client.aclose()


@respx.mock
async def test_rescan_not_found_flags_error():
    router = respx.mock
    _mock_login(router)
    router.post(url__regex=rf"{BASE}{ex.EP_QUARANTINE_RESCAN}/.*").mock(return_value=httpx.Response(
        400, text='{"message":"Could not find quarantined email or Invalid queueid"}'))
    client = _client()
    try:
        await client.rescan("Q1_RA", ["pw"])
        assert False, "expected EXApiError"
    except ex.EXApiError as exc:
        assert exc.status_code == 400
        assert exc.not_found is True  # recognized as "email not quarantined"
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
