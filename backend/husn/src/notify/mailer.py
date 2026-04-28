"""SMTP transport for incident reports.

Designed to gracefully degrade: if SMTP is disabled or misconfigured the
mailer logs the event and returns a structured failure rather than
raising, so the rest of the defense pipeline keeps working.
"""
from __future__ import annotations

import logging
import smtplib
import ssl
from dataclasses import dataclass, field
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from pathlib import Path
from typing import Any

from husn.src import config

log = logging.getLogger("husn.mailer")


@dataclass
class SendResult:
    ok: bool
    detail: str
    recipients: list[str] = field(default_factory=list)


def _smtp_settings() -> dict[str, Any]:
    return config.get("smtp", {}) or {}


def is_enabled() -> bool:
    s = _smtp_settings()
    return bool(s.get("enabled")) and bool(s.get("host")) and bool(s.get("from_addr"))


def recipients() -> list[str]:
    """Current recipient list (config seed + runtime additions). Mutated via add/remove."""
    cfg_list = config.get("recipients", []) or []
    runtime = _runtime_recipients
    # Preserve order, dedupe.
    seen: set[str] = set()
    out: list[str] = []
    for addr in [*cfg_list, *runtime]:
        if addr and addr not in seen:
            seen.add(addr)
            out.append(addr)
    return out


_runtime_recipients: list[str] = []


def add_recipient(addr: str) -> bool:
    if addr and addr not in recipients():
        _runtime_recipients.append(addr)
        return True
    return False


def remove_recipient(addr: str) -> bool:
    if addr in _runtime_recipients:
        _runtime_recipients.remove(addr)
        return True
    return False


def send(
    subject: str,
    html_body: str,
    text_body: str,
    inline_images: dict[str, bytes] | None = None,
    attachments: dict[str, bytes] | None = None,
    to: list[str] | None = None,
) -> SendResult:
    """Send a multipart email. `inline_images` keys become Content-IDs you can
    reference in the HTML as `<img src="cid:KEY">`."""
    s = _smtp_settings()
    rcpt = to or recipients()

    if not is_enabled():
        log.info("[mailer] SMTP disabled — skipping send. subject=%r", subject)
        return SendResult(False, "smtp disabled in config", rcpt)
    if not rcpt:
        log.warning("[mailer] No recipients configured — skipping send.")
        return SendResult(False, "no recipients", [])

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = s.get("from_addr")
    msg["To"] = ", ".join(rcpt)
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain=config.get("domain", "husn.local"))
    msg.set_content(text_body)
    msg.add_alternative(html_body, subtype="html")

    if inline_images:
        # Inline images attach to the HTML alternative part.
        html_part = msg.get_payload()[1]
        for cid, data in inline_images.items():
            html_part.add_related(data, maintype="image", subtype="png", cid=f"<{cid}>")

    if attachments:
        for filename, data in attachments.items():
            ext = Path(filename).suffix.lstrip(".") or "bin"
            maintype, subtype = ("text", ext) if ext in ("md", "txt", "html", "json") else ("application", "octet-stream")
            msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=filename)

    host = s.get("host", "localhost")
    port = int(s.get("port", 587))
    timeout = int(s.get("timeout_seconds", 15))
    use_ssl = bool(s.get("use_ssl"))
    use_tls = bool(s.get("use_tls"))
    user = s.get("user", "")
    password = s.get("password", "")  # resolved from password_env in config loader

    try:
        ctx = ssl.create_default_context()
        if use_ssl:
            with smtplib.SMTP_SSL(host, port, timeout=timeout, context=ctx) as smtp:
                if user:
                    smtp.login(user, password)
                smtp.send_message(msg, to_addrs=rcpt)
        else:
            with smtplib.SMTP(host, port, timeout=timeout) as smtp:
                smtp.ehlo()
                if use_tls:
                    smtp.starttls(context=ctx)
                    smtp.ehlo()
                if user:
                    smtp.login(user, password)
                smtp.send_message(msg, to_addrs=rcpt)
    except (smtplib.SMTPException, OSError, TimeoutError) as exc:
        log.exception("[mailer] SMTP delivery failed")
        return SendResult(False, f"smtp error: {exc}", rcpt)

    log.info("[mailer] sent subject=%r to=%s", subject, rcpt)
    return SendResult(True, "delivered", rcpt)
