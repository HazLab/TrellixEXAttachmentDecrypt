"""Admin UI: auth gating, case list/detail, and live settings update."""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from trellix_decrypt.domain import AlertEvent, FlowState
from trellix_decrypt.web import create_app

from .conftest import make_context

PW = "letmein"


@pytest.fixture
def client_ctx():
    ctx = make_context(ui_password=PW)
    with TestClient(create_app(ctx)) as client:
        yield client, ctx


def _login(client):
    r = client.post("/login", data={"password": PW}, follow_redirects=False)
    assert r.status_code == 303


def test_api_requires_auth(client_ctx):
    client, _ = client_ctx
    assert client.get("/api/cases").status_code == 401
    assert client.get("/api/settings").status_code == 401


def test_dashboard_redirects_when_unauthed(client_ctx):
    client, _ = client_ctx
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"


def test_wrong_password_no_session(client_ctx):
    client, _ = client_ctx
    assert client.post("/login", data={"password": "nope"}, follow_redirects=False).status_code == 401
    assert client.get("/api/cases").status_code == 401


def test_cases_listed_after_login(client_ctx):
    client, ctx = client_ctx
    # Seed a case directly via the repo (sync), then move it to AWAITING_PASSWORD.
    case = ctx.repo.get_or_create_case(AlertEvent(
        queue_id="Q9", recipients=["u@corp.test"], alert_name="RISKWARE_OBJECT",
        malware_names=["CustomPolicy.MVX.zip"], subject="Hi"))
    ctx.repo.set_state(case, FlowState.AWAITING_PASSWORD, "link sent")

    _login(client)
    cases = client.get("/api/cases").json()["cases"]
    assert len(cases) == 1
    assert cases[0]["queue_id"] == "Q9"
    assert cases[0]["attachment"] == "CustomPolicy.MVX.zip"
    assert cases[0]["status_label"] == "Password requested"


def test_settings_get_masks_secrets_and_update_applies(client_ctx):
    client, ctx = client_ctx
    _login(client)
    masked = client.get("/api/settings").json()
    assert masked["ex_password"] == "********"        # secret never returned
    assert masked["ex_username"] == "u"

    r = client.post("/api/settings", json={"max_password_attempts": 5, "ex_username": "svc-api"})
    assert r.status_code == 200
    assert ctx.engine.settings.max_password_attempts == 5   # applied live to the engine
    assert ctx.engine.settings.ex_username == "svc-api"
