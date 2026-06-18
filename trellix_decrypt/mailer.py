"""SMTP delivery of the password-request email, rendered from Jinja2 templates."""

from __future__ import annotations

from email.message import EmailMessage
from pathlib import Path

import aiosmtplib
from jinja2 import Environment, FileSystemLoader, select_autoescape

TEMPLATES_DIR = Path(__file__).parent / "templates"


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
        msg["Subject"] = ("Reminder: " if retry else "") + "Password needed for your quarantined attachment"
        msg.set_content(text)
        msg.add_alternative(html, subtype="html")

        await aiosmtplib.send(
            msg,
            hostname=self._s.smtp_host,
            port=self._s.smtp_port,
            username=self._s.smtp_username or None,
            password=self._s.smtp_password or None,
            start_tls=self._s.smtp_starttls,
        )
