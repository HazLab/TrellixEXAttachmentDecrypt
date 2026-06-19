"""Application context: owns the live FlowEngine and rebuilds its transport
collaborators (EX client, mailer, rules, tokens) when settings change, so the
settings UI can apply changes without a restart.
"""

from __future__ import annotations

from .domain import FlowEngine, RiskwareRules, TokenService
from .ex_client import EXClient
from .mailer import SMTPMailer


def _build_components(s):
    ex = EXClient(s.ex_base_url, s.ex_username, s.ex_password, s.ex_verify_tls, s.ex_client_token)
    mailer = SMTPMailer(s)
    tokens = TokenService(s.secret_key, s.token_ttl)
    rules = RiskwareRules(s.trigger_malware_names, s.trigger_alert_name)
    return ex, mailer, tokens, rules


class AppContext:
    def __init__(self, env, store, repo, scheduler, engine: FlowEngine | None = None):
        self.env = env
        self.store = store
        self.repo = repo
        self.scheduler = scheduler
        if engine is not None:  # injected (tests)
            self.engine = engine
        else:
            s = store.effective_settings()
            ex, mailer, tokens, rules = _build_components(s)
            self.engine = FlowEngine(repo, ex, mailer, tokens, rules, s, scheduler)
        scheduler.bind(self.engine)

    async def reload(self) -> None:
        """Apply current settings to the running engine (keeps its identity stable)."""
        s = self.store.effective_settings()
        ex, mailer, tokens, rules = _build_components(s)
        old_ex = self.engine.ex
        self.engine.ex = ex
        self.engine.mailer = mailer
        self.engine.tokens = tokens
        self.engine.rules = rules
        self.engine.settings = s
        await old_ex.aclose()
