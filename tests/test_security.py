"""Negative-path security behaviour: setup gating, rate limits, body cap, auth."""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from trellix_decrypt.domain import AlertEvent, FlowState
from trellix_decrypt.web import create_app

from .conftest import make_context


def _client(**overrides):
    ctx = make_context(**overrides)
    return TestClient(create_app(ctx)), ctx


# --- First-run setup mode ---------------------------------------------------

def test_setup_mode_opens_settings_without_auth():
    client, _ = _client(ui_password="")  # no admin password -> setup mode
    assert client.get("/settings").status_code == 200            # reachable to bootstrap
    body = client.get("/api/settings").json()
    assert body["setup_mode"] is True
    assert "ui_password" in body["missing"]


def test_setup_mode_dashboard_redirects_to_settings():
    client, _ = _client(ui_password="")
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/settings"


def test_setting_admin_password_exits_setup_mode():
    client, ctx = _client(ui_password="")
    r = client.post("/api/settings", json={"ui_password": "s3cret"})
    assert r.status_code == 200 and r.json()["setup_mode"] is False
    assert ctx.engine.settings.ui_password == "s3cret"          # applied live
    # Now auth is enforced: the API rejects an unauthenticated caller.
    assert client.get("/api/cases").status_code == 401


def test_webhook_503_until_configured():
    client, _ = _client(ui_password="")  # not fully configured
    r = client.post("/webhook/ex-alert", json={"Alerts": []},
                    auth=("exuser", "expass"))
    assert r.status_code == 503


# --- Auth + rate limiting ---------------------------------------------------

def test_webhook_rejects_bad_credentials_when_configured():
    client, _ = _client()  # configured (conftest sets ui_password)
    assert client.post("/webhook/ex-alert", json={}, auth=("exuser", "wrong")).status_code == 401


def test_login_rate_limited_after_threshold():
    client, _ = _client(login_rate_limit=3, login_rate_window=900)
    codes = [client.post("/login", data={"password": "nope"},
                         follow_redirects=False).status_code for _ in range(4)]
    assert codes[:3] == [401, 401, 401]
    assert codes[3] == 429                                       # 4th attempt from same IP blocked


def test_password_form_rate_limited():
    client, ctx = _client(form_rate_limit=1, form_rate_window=300)
    case = ctx.repo.get_or_create_case(AlertEvent(
        queue_id="Q1", recipients=["u@corp.test"], alert_name="RISKWARE_OBJECT",
        malware_names=["CustomPolicy.MVX.zip"]))
    ctx.repo.set_state(case, FlowState.AWAITING_PASSWORD, "sent")
    token = ctx.engine.tokens.mint(case.id)
    assert client.post(f"/p/{token}", data={"password": "x"}).status_code in (200, 400)
    assert client.post(f"/p/{token}", data={"password": "x"}).status_code == 429  # 2nd blocked


def test_webhook_body_too_large_rejected():
    client, _ = _client(max_request_bytes=50)
    big = {"Alerts": [{"name": "X", "blob": "z" * 500}]}
    assert client.post("/webhook/ex-alert", json=big, auth=("exuser", "expass")).status_code == 413


def test_invalid_password_token_404():
    client, _ = _client()
    assert client.get("/p/not-a-real-token").status_code == 404


@pytest.mark.parametrize("path", ["/api/cases", "/api/status", "/api/settings"])
def test_admin_api_requires_auth(path):
    client, _ = _client()
    assert client.get(path).status_code == 401
