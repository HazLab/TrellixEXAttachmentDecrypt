"""End-to-end wiring test through the real FastAPI app (EX/mailer/scheduler faked)."""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from trellix_decrypt.domain import FlowEngine, FlowState, RiskwareRules, TokenService
from trellix_decrypt.storage import CaseRepository, build_session_factory
from trellix_decrypt.web import create_app

from .conftest import FakeEX, FakeMailer, FakeScheduler, make_settings


@pytest.fixture
def app_engine():
    settings = make_settings()
    repo = CaseRepository(build_session_factory(settings.db_url))
    engine = FlowEngine(repo, FakeEX(), FakeMailer(), TokenService(settings.secret_key, settings.token_ttl),
                        RiskwareRules(settings.trigger_rule_ids), settings, FakeScheduler())
    engine.scheduler.bind(engine)
    return create_app(engine, settings), engine, settings


def test_full_webhook_to_resubmit(app_engine):
    app, engine, settings = app_engine
    with TestClient(app) as client:
        # 1. Bad secret rejected.
        assert client.post("/webhook/ex-alert", json={}).status_code == 401

        # 2. Trigger alert -> email sent, case awaiting.
        alert = {"queue_id": "Q-77", "recipient": "u@corp.test", "rule_id": 65001, "subject": "Invoice"}
        resp = client.post("/webhook/ex-alert", json=alert, headers={"X-Webhook-Secret": settings.webhook_secret})
        assert resp.status_code == 200 and resp.json()["handled"] == 1
        assert len(engine.mailer.sent) == 1

        # 3. Open the one-time link and submit a password.
        link = engine.mailer.sent[0][1]
        token = link.rsplit("/p/", 1)[1]
        assert client.get(f"/p/{token}").status_code == 200

        submit = client.post(f"/p/{token}", data={"password": "secret"})
        assert submit.status_code == 200
        assert engine.ex.resubmitted == [("Q-77", ["secret"])]

        # 4. Replaying the link is rejected.
        assert client.post(f"/p/{token}", data={"password": "secret"}).status_code == 400

        case = engine.repo.get_case(token and engine.tokens.verify(token))
        assert case.state == FlowState.RESUBMITTED
        assert engine.scheduler.scheduled == [case.id]
