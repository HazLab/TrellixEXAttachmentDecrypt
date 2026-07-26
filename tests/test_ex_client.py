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
    # An <queue_id>_RA record is present -> the re-analysis is still held.
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
    # Only the original remains (no _RA) -> released/delivered = passed.
    router.get(BASE + ex.EP_QUARANTINE).mock(return_value=httpx.Response(200, json=[
        {"queue_id": "Q1", "quarantine_path": "/p"}]))
    client = _client()
    assert await client.has_resubmission_quarantine("Q1", "s@x", "subj") is False
    await client.aclose()


@respx.mock
async def test_has_resubmission_quarantine_ignores_prefix_siblings():
    router = respx.mock
    _mock_login(router)
    # The bug: a loose prefix match flagged everything held. Entries that merely START
    # with the queue id (a longer unrelated id, or a non-_RA suffix) are NOT this email's
    # re-analysis -> passed. Only an exact <queue_id>_RA counts.
    router.get(BASE + ex.EP_QUARANTINE).mock(return_value=httpx.Response(200, json=[
        {"queue_id": "Q1", "quarantine_path": "/p"},       # the original itself
        {"queue_id": "Q12345", "quarantine_path": "/p2"},  # a different email, shares prefix
        {"queue_id": "Q1_OTHER", "quarantine_path": "/p3"},# same prefix, not an _RA suffix
    ]))
    client = _client()
    assert await client.has_resubmission_quarantine("Q1", "s@x", "subj") is False
    await client.aclose()


@respx.mock
async def test_list_quarantine_since_sets_time_window():
    from datetime import datetime, timezone
    router = respx.mock
    _mock_login(router)
    route = router.get(BASE + ex.EP_QUARANTINE).mock(return_value=httpx.Response(200, json=[]))
    client = _client()
    await client.list_quarantine(sender="s@x", since=datetime(2026, 7, 1, 9, 30, tzinfo=timezone.utc))
    params = route.calls.last.request.url.params
    # start_time is the arrival minus the skew (1h) -> 08:30; both sides present as a pair.
    assert params["start_time"] == "2026-07-01T08:30:00.000+0000"
    assert "end_time" in params
    assert params["from"] == "s@x"
    await client.aclose()


async def test_ex_time_formats_and_assumes_utc_when_naive():
    from datetime import datetime, timezone
    assert ex._ex_time(datetime(2026, 7, 1, 8, 30, 0, 123000, tzinfo=timezone.utc)) == \
        "2026-07-01T08:30:00.123+0000"
    # A naive timestamp (as SQLite round-trips can produce) is treated as UTC.
    assert ex._ex_time(datetime(2026, 7, 1, 8, 30)) == "2026-07-01T08:30:00.000+0000"


@respx.mock
async def test_get_alert_by_uuid_returns_raw_alert():
    router = respx.mock
    _mock_login(router)
    router.get(BASE + ex.EP_ALERT_DETAILS + "/u-1").mock(return_value=httpx.Response(200, json={
        "alert": [{"uuid": "u-1", "name": "MALWARE_OBJECT", "malicious": "yes"}], "alertsCount": 1}))
    client = _client()
    alert = await client.get_alert_by_uuid("u-1")
    assert alert["name"] == "MALWARE_OBJECT"
    await client.aclose()


@respx.mock
async def test_get_alert_by_uuid_none_when_not_found():
    router = respx.mock
    _mock_login(router)
    router.get(BASE + ex.EP_ALERT_DETAILS + "/nope").mock(return_value=httpx.Response(
        404, text='{"message":"alert not found"}'))
    client = _client()
    assert await client.get_alert_by_uuid("nope") is None
    await client.aclose()


@respx.mock
async def test_alert_uuids_for_collects_original_and_RA_deduped():
    router = respx.mock
    _mock_login(router)
    # The original and its _RA both belong to Q1; a prefix-sibling (Q12345) does not.
    router.get(BASE + ex.EP_QUARANTINE).mock(return_value=httpx.Response(200, json=[
        {"queue_id": "Q1", "alert_uuids": ["a-1", "a-2"]},
        {"queue_id": "Q1_RA", "alert_uuids": ["a-2", "a-3"]},   # a-2 repeats -> deduped
        {"queue_id": "Q12345", "alert_uuids": ["x-9"]},          # different email, ignored
    ]))
    client = _client()
    assert await client.alert_uuids_for("Q1", "s@x", "subj") == ["a-1", "a-2", "a-3"]
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
