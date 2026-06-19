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


def _format_smtp_error(exc: Exception) -> str:
    """Turn an aiosmtplib error into the server's actual reason (code + message)."""
    if isinstance(exc, SMTPRecipientsRefused):
        parts = [f"{addr}: {resp.code} {resp.message}".strip() for addr, resp in exc.recipients.items()]
        return "recipient(s) refused by mail server — " + "; ".join(parts)
    code = getattr(exc, "code", None)
    message = getattr(exc, "message", None)
    if code or message:
        return f"SMTP {code or ''} {message or ''}".strip()
    return f"{type(exc).__name__}: {exc}"


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
                start_tls=self._s.smtp_starttls,
                local_hostname=self._s.smtp_helo_hostname or None,
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
