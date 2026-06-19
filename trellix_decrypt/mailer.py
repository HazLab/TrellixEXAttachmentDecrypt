"""SMTP delivery of the password-request email, rendered from Jinja2 templates."""

from __future__ import annotations

import logging
from email.message import EmailMessage
from pathlib import Path

import aiosmtplib
from aiosmtplib.errors import SMTPException, SMTPRecipientsRefused
from jinja2 import Environment, FileSystemLoader, select_autoescape

log = logging.getLogger(__name__)
TEMPLATES_DIR = Path(__file__).parent / "templates"

# Map our TLS mode to aiosmtplib's (start_tls, use_tls) arguments.
# start_tls=None => opportunistic (upgrade if the server offers STARTTLS).
_TLS_MODES = {
    "opportunistic": {"start_tls": None, "use_tls": False},
    "starttls": {"start_tls": True, "use_tls": False},
    "none": {"start_tls": False, "use_tls": False},
    "ssl": {"start_tls": False, "use_tls": True},   # implicit TLS / SMTPS (e.g. 465)
}


def tls_kwargs(mode: str) -> dict:
    return _TLS_MODES.get((mode or "opportunistic").strip().lower(), _TLS_MODES["opportunistic"])


def _format_smtp_error(exc: Exception) -> str:
    """Turn an aiosmtplib error into the server's actual reason (code + message)."""
    if isinstance(exc, SMTPRecipientsRefused):
        parts = [f"{addr}: {resp.code} {resp.message}".strip() for addr, resp in exc.recipients.items()]
        return "recipient(s) refused by mail server — " + "; ".join(parts)
    code = getattr(exc, "code", None)
    message = getattr(exc, "message", None)
    text = f"SMTP {code or ''} {message or ''}".strip() if (code or message) else f"{type(exc).__name__}: {exc}"
    low = text.lower()
    if "auth" in low and "not supported" in low:
        text += " — this relay offers no SMTP AUTH; clear SMTP_USERNAME to send unauthenticated"
    return text


class SMTPMailer:
    def __init__(self, settings, templates_dir: Path = TEMPLATES_DIR):
        self._s = settings
        self._env = Environment(
            loader=FileSystemLoader(str(templates_dir)),
            autoescape=select_autoescape(["html", "j2"]),
        )

    async def send_password_request(self, recipient: str, link: str, case, retry: bool = False) -> None:
        ctx = {"link": link, "case": case, "retry": retry}
        html = self._env.get_template("password_request.html.j2").render(**ctx)
        text = self._env.get_template("password_request.txt.j2").render(**ctx)

        msg = EmailMessage()
        msg["From"] = self._s.smtp_from
        msg["To"] = recipient
        msg["X-Case-Id"] = case.id  # lets the bounce monitor correlate a DSN back to this case
        msg["Subject"] = ("Reminder: " if retry else "") + "Password needed for your quarantined attachment"
        msg.set_content(text)
        msg.add_alternative(html, subtype="html")

        # Only authenticate when a username is set; otherwise don't attempt AUTH
        # (relays without the AUTH extension reject the attempt outright).
        username = self._s.smtp_username or None
        password = (self._s.smtp_password or None) if username else None
        try:
            errors, response = await aiosmtplib.send(
                msg,
                hostname=self._s.smtp_host,
                port=self._s.smtp_port,
                username=username,
                password=password,
                local_hostname=self._s.smtp_helo_hostname or None,
                validate_certs=self._s.smtp_verify_tls,
                **tls_kwargs(self._s.smtp_tls_mode),
            )
        except SMTPException as exc:
            # Surface the server's actual response so "recipient refused" vs
            # "relay denied" / "auth required" is distinguishable.
            raise RuntimeError(_format_smtp_error(exc)) from exc
        # Success path: log the server's final response (often "250 ... queued as
        # <id>"), which is the handle to trace the message in the mail server logs.
        log.info("SMTP accepted message for %s via %s:%s — %s",
                 recipient, self._s.smtp_host, self._s.smtp_port, response)
        if errors:
            log.warning("SMTP reported per-recipient issues for %s: %s", recipient, errors)
