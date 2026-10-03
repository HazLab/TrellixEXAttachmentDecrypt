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

def _setup_client(**overrides):
    """A client in first-run setup mode that has opened the one-time setup link."""
    client, ctx = _client(ui_password="", **overrides)
    r = client.get(f"/settings?setup={ctx.setup_token}", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/settings"   # token -> cookie
    return client, ctx


def test_setup_mode_opens_settings_without_auth():
    client, _ = _setup_client()  # no admin password -> setup mode, token presented
    assert client.get("/settings").status_code == 200            # reachable to bootstrap
    body = client.get("/api/settings").json()
    assert body["setup_mode"] is True
    assert "ui_password" in body["missing"]


def test_setup_mode_is_locked_without_the_setup_token():
    client, _ = _client(ui_password="")  # reached the port first, but has no token
    assert client.get("/settings").status_code == 403
    assert client.get("/settings?setup=wrong").status_code == 403
    assert client.get("/api/settings").status_code == 403
    assert client.post("/api/settings", json={"ui_password": "mine-now"}).status_code == 403
    assert client.get("/api/tls").status_code == 403


def test_setup_mode_dashboard_redirects_to_settings():
    client, _ = _client(ui_password="")
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/settings"


def test_setting_admin_password_exits_setup_mode():
    client, ctx = _setup_client()
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


def test_webhook_get_probe_is_200_not_405():
    # EX/browser GET probes to the webhook URL should get a helpful 200, not a 405.
    client, _ = _client()
    r = client.get("/webhook/ex-alert")
    assert r.status_code == 200 and r.json()["method"] == "POST"


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


# --- Settings validation ----------------------------------------------------

def _admin(**overrides):
    client, ctx = _client(**overrides)
    assert client.post("/login", data={"password": "admin-pw"}, follow_redirects=False).status_code == 303
    return client, ctx


def test_invalid_setting_is_rejected_and_not_saved():
    client, ctx = _admin()
    r = client.post("/api/settings", json={"recheck_interval": "abc", "smtp_host": "mail.new"})
    assert r.status_code == 400 and "recheck_interval" in r.json()["detail"]
    # Nothing from the rejected save was persisted, and the settings still load.
    assert client.get("/api/settings").status_code == 200
    assert ctx.store.effective_settings().smtp_host != "mail.new"


def test_bad_stored_setting_is_ignored_not_fatal():
    from trellix_decrypt.storage import Setting
    client, ctx = _admin()
    with ctx.store._sf() as s:                      # e.g. a hand-edited DB / older version
        s.add(Setting(key="recheck_interval", value="abc", is_secret=False))
        s.commit()
    eff = ctx.store.effective_settings()
    assert eff.recheck_interval == ctx.env.recheck_interval      # fell back, didn't raise
    assert client.get("/api/settings").status_code == 200


def test_admin_password_cannot_be_cleared():
    client, ctx = _admin()
    r = client.post("/api/settings", json={"__clear__": ["ui_password"]})
    assert r.status_code == 400
    assert ctx.engine.settings.ui_password == "admin-pw"


# --- Sessions ---------------------------------------------------------------

def test_non_ascii_password_is_a_clean_401():
    client, _ = _client()
    assert client.post("/login", data={"password": "pässwörd-✓"}, follow_redirects=False).status_code == 401


def test_non_ascii_webhook_credentials_are_a_clean_401():
    client, _ = _client()
    r = client.post("/webhook/ex-alert", json={"Alerts": []}, auth=("exuser".encode(), "pässwörd".encode()))
    assert r.status_code == 401


def test_logout_revokes_the_session():
    client, _ = _admin()
    stolen = client.cookies.get("ui_session")
    assert client.get("/api/cases").status_code == 200
    client.get("/logout", follow_redirects=False)
    client.cookies.set("ui_session", stolen)                     # a copied cookie is dead too
    assert client.get("/api/cases").status_code == 401


def test_changing_admin_password_invalidates_sessions():
    client, _ = _admin()
    assert client.post("/api/settings", json={"ui_password": "brand-new-pw"}).status_code == 200
    assert client.get("/api/cases").status_code == 401           # old session no longer valid


def test_session_cookie_is_secure_only_over_https():
    client, _ = _client()
    r = client.post("/login", data={"password": "admin-pw"}, follow_redirects=False)
    assert "secure" not in r.headers["set-cookie"].lower()       # plain HTTP: must still work
    https = TestClient(create_app(make_context()), base_url="https://testserver")
    r = https.post("/login", data={"password": "admin-pw"}, follow_redirects=False)
    assert "secure" in r.headers["set-cookie"].lower()


# --- Hardening --------------------------------------------------------------

def test_security_headers_on_every_response():
    client, _ = _client()
    for path in ("/login", "/healthz", "/p/not-a-real-token"):
        h = client.get(path).headers
        assert h["x-content-type-options"] == "nosniff"
        assert h["x-frame-options"] == "DENY"
        assert "frame-ancestors 'none'" in h["content-security-policy"]


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json"])
def test_api_explorer_is_not_exposed(path):
    client, _ = _client()
    assert client.get(path).status_code == 404
