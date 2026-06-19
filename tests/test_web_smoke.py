"""End-to-end wiring test through the real FastAPI app (EX/mailer/scheduler faked)."""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from trellix_decrypt.domain import FlowState
from trellix_decrypt.web import create_app

from .conftest import TRIGGER_MALWARE_NAME, make_context


@pytest.fixture
def app_ctx():
    ctx = make_context()
    return create_app(ctx), ctx


def test_full_webhook_to_resubmit(app_ctx):
    app, ctx = app_ctx
    engine, settings = ctx.engine, ctx.env
    with TestClient(app) as client:
        # 1. Bad secret rejected.
        assert client.post("/webhook/ex-alert", json={}).status_code == 401

        # 2. Trigger alert (real EX envelope) -> email sent, case awaiting.
        payload = {"Alerts": [{
            "name": "RISKWARE_OBJECT", "malicious": "no",
            "dst": {"smtpTo": "u@corp.test"},
            "smtpMessage": {"queueId": "Q-77", "subject": "Invoice"},
            "explanation": {"malwareDetected": {"malware": [{"name": TRIGGER_MALWARE_NAME}]}},
        }]}
        resp = client.post("/webhook/ex-alert", json=payload, headers={"X-Webhook-Secret": settings.webhook_secret})
        assert resp.status_code == 200 and resp.json()["handled"] == 1
        assert len(engine.mailer.sent) == 1

        # 3. Open the one-time link and submit a password.
        link = engine.mailer.sent[0][1]
        token = link.rsplit("/p/", 1)[1]
        assert client.get(f"/p/{token}").status_code == 200

        submit = client.post(f"/p/{token}", data={"password": "secret"})
        assert submit.status_code == 200
        assert engine.ex.rescanned == [("Q-77", ["secret"])]

        # 4. Replaying the link is rejected.
        assert client.post(f"/p/{token}", data={"password": "secret"}).status_code == 400

        case = engine.repo.get_case(engine.tokens.verify(token))
        assert case.state == FlowState.RESUBMITTED
        assert engine.scheduler.scheduled == [case.id]
