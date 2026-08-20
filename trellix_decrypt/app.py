"""Composition root: build settings, wire every layer, return the FastAPI app."""

from __future__ import annotations

import logging
from pathlib import Path

from .config import Settings, resolve_secret_key
from .context import AppContext
from .recheck import RecheckScheduler
from .settings_store import SettingsStore
from .storage import CaseRepository, build_session_factory
from .web import create_app

_LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"

#: Filename for the auto-generated SECRET_KEY (written under DATA_DIR / the CWD).
SECRET_KEY_FILE = "secret.key"
#: The built-in default DB_URL; relocated under DATA_DIR when the operator didn't override it.
DEFAULT_DB_URL = "sqlite:///trellix_decrypt.sqlite3"
DEFAULT_DB_FILENAME = "trellix_decrypt.sqlite3"


def _configure_logging(settings: Settings) -> None:
    """Console + optional rotating file, both capturing EVERYTHING — including every
    HTTP request (uvicorn's access log reaches the root handlers because we start
    uvicorn with log_config=None; see __main__). Useful for inspecting raw EX
    notifications hitting the box, not just our own app events."""
    level = getattr(logging, settings.log_level.upper(), logging.INFO)
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    if settings.log_file:
        from logging.handlers import RotatingFileHandler
        handlers.append(RotatingFileHandler(
            settings.log_file, maxBytes=settings.log_file_max_bytes,
            backupCount=settings.log_file_backups, encoding="utf-8"))
    logging.basicConfig(level=level, format=_LOG_FORMAT, handlers=handlers, force=True)


def build_context(settings: Settings) -> AppContext:
    session_factory = build_session_factory(settings.db_url)
    repo = CaseRepository(session_factory)
    store = SettingsStore(settings, session_factory)
    scheduler = RecheckScheduler()
    return AppContext(settings, store, repo, scheduler)


def build(settings: Settings | None = None):
    settings = settings or Settings()
    # Resolve the persistent data directory (DATA_DIR, else CWD). The secret key and,
    # unless DB_URL was overridden, the SQLite file live here so a single mounted
    # volume (Docker) or writable folder (exe) keeps both across restarts.
    data_dir = Path(settings.data_dir) if settings.data_dir else Path.cwd()
    data_dir.mkdir(parents=True, exist_ok=True)
    if settings.data_dir and settings.db_url == DEFAULT_DB_URL:
        settings.db_url = "sqlite:///" + (data_dir / DEFAULT_DB_FILENAME).as_posix()
    key_path = str(data_dir / SECRET_KEY_FILE)
    # Never run on the shipped placeholder key: resolve to an explicit env key, or a
    # persisted/auto-generated one, before anything signs a token or encrypts a secret.
    generated_before = not Path(key_path).exists()
    settings.secret_key = resolve_secret_key(settings.secret_key, key_path)
    ctx = build_context(settings)
    # Effective settings = env defaults overlaid with UI-saved DB overrides. Logging
    # and the bind host/port come from here so GUI-configured infra applies on restart
    # (db_url is the exception — it must stay env-only; it points at this very DB).
    eff = ctx.engine.settings
    _configure_logging(eff)
    log = logging.getLogger(__name__)
    if generated_before and Path(key_path).exists():
        log.warning("no SECRET_KEY supplied — generated a strong one and saved it to %s "
                    "(keep this file safe; deleting it invalidates all links and sessions)",
                    key_path)
    log.info("trigger config: alert_name=%r malware_names=%r", eff.trigger_alert_name, eff.trigger_malware_names)
    if not eff.is_configured():
        log.warning("SETUP MODE — configuration incomplete, missing: %s. Open the admin UI to "
                    "finish setup; the webhook returns 503 until then.", ", ".join(eff.missing_required()))
    log.info("serving on http://%s:%s — password links built from PUBLIC_BASE_URL=%s "
             "(scheme/host/port must match how recipients reach this server)",
             eff.web_host, eff.web_port, eff.public_base_url)
    return create_app(ctx), eff
