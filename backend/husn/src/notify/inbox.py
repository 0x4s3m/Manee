"""SOC mailbox listener — email-to-chatbot bridge.

Lets anyone email manee@build-aura.com and get an LLM-generated SOC
analyst reply. Same DeepSeek brain as the dashboard chat tab; this is
just a different UI for it.

How it works:
  1. APScheduler fires `poll_and_reply()` every `inbox.interval_seconds`
     (default 90s).
  2. We connect to IMAP (Hostinger by default), fetch UNSEEN messages.
  3. Each message: skip our own outgoing alerts, skip auto-replies, skip
     loop-back. Otherwise extract the question, hand it to the SOC
     chatbot, send the reply back via SMTP threaded to the same subject.
  4. Persist a list of seen Message-IDs to /etc/husn/inbox-seen.json so
     restarts don't re-reply to old mail.

Auth: uses the same SMTP user + HUSN_SMTP_PASSWORD env var (Hostinger
shares creds across IMAP and SMTP). No separate IMAP password needed.
"""
from __future__ import annotations

import email
import hashlib
import imaplib
import json
import logging
import re
import ssl
import time
from email.utils import parseaddr
from pathlib import Path
from typing import Any

log = logging.getLogger("husn.inbox")


# ─────────────── Config helpers ─────────────────────────────────────

def _cfg() -> dict[str, Any]:
    from husn.src import config
    return config.get("inbox", {}) or {}


def _smtp_cfg() -> dict[str, Any]:
    from husn.src import config
    return config.get("smtp", {}) or {}


def is_enabled() -> bool:
    return bool(_cfg().get("enabled", False))


# ─────────────── Seen-message persistence ───────────────────────────

def _state_path() -> Path:
    from husn.src import config
    base = Path(config.get("paths.state_dir") or "/etc/husn")
    base.mkdir(parents=True, exist_ok=True)
    return base / "inbox-seen.json"


def _load_seen() -> set[str]:
    p = _state_path()
    if not p.exists():
        return set()
    try:
        return set(json.loads(p.read_text(encoding="utf-8")))
    except Exception:
        return set()


def _save_seen(seen: set[str]) -> None:
    # Cap at 5000 entries to keep file sane across years of operation.
    capped = sorted(seen)[-5000:]
    try:
        _state_path().write_text(json.dumps(capped), encoding="utf-8")
    except Exception:
        log.exception("[inbox] failed to persist seen state")


# ─────────────── Message parsing helpers ────────────────────────────

_REPLY_QUOTE_PATTERNS = [
    re.compile(r"^On .+wrote:$", re.MULTILINE),
    re.compile(r"^-----Original Message-----", re.MULTILINE),
    re.compile(r"^From:.*\nSent:", re.MULTILINE),
    re.compile(r"^في .+كتب", re.MULTILINE),       # Arabic Gmail-style attribution
    re.compile(r"^_{3,}\s*$", re.MULTILINE),       # signature separator
]


def _strip_quoted_reply(body: str) -> str:
    """Remove the previous message's quoted block so we only feed the
    latest user question to the LLM."""
    if not body:
        return ""
    earliest = len(body)
    for pat in _REPLY_QUOTE_PATTERNS:
        m = pat.search(body)
        if m:
            earliest = min(earliest, m.start())
    body = body[:earliest]
    # Drop > quoted lines anywhere
    out_lines = [ln for ln in body.splitlines() if not ln.lstrip().startswith(">")]
    return "\n".join(out_lines).strip()


def _allowed_senders() -> set[str]:
    """Whitelist of email addresses that may drive Manee by email.
    Combines:
      1. inbox.allowed_senders from /etc/husn/config.yml (explicit list)
      2. The dashboard's notification recipients (the people you already
         trust enough to send incident reports to)
    Anything not in this combined set is silently dropped.
    """
    explicit = _cfg().get("allowed_senders") or []
    if isinstance(explicit, str):
        explicit = [explicit]
    explicit = {str(a).strip().lower() for a in explicit if a}
    try:
        from husn.src.notify import mailer
        recipients = {a.strip().lower() for a in mailer.recipients() if a}
    except Exception:
        recipients = set()
    return explicit | recipients


def _is_authorized_sender(from_addr: str) -> bool:
    """True iff the sender is in the allowlist. Empty allowlist means
    NOBODY is authorized — fail closed, never open."""
    if not from_addr:
        return False
    allow = _allowed_senders()
    if not allow:
        return False
    return from_addr.strip().lower() in allow


def _is_loop_back(msg: email.message.Message) -> bool:
    """Don't respond to our own outgoing alerts, auto-replies, bounces."""
    from_addr = parseaddr(msg.get("From", ""))[1].lower()
    smtp_user = (_smtp_cfg().get("user") or "").lower()
    if from_addr and smtp_user and from_addr == smtp_user:
        return True

    # RFC 3834 — auto-reply marker
    if (msg.get("Auto-Submitted", "") or "").lower() not in ("", "no"):
        return True

    # Common bounce / vacation / autoresponder subjects
    subj = (msg.get("Subject", "") or "").lower()
    bounce_terms = (
        "out of office", "auto-reply", "autoresponder",
        "undeliverable", "delivery status notification",
        "mail delivery failed", "non-delivery", "[manee", "[husn",
    )
    if any(t in subj for t in bounce_terms):
        return True

    # Avoid replying to our own incident alert format
    if "manee defense grid blocked" in (msg.get("Subject", "") or "").lower():
        return True

    return False


def _extract_body(msg: email.message.Message) -> str:
    """Return the plain-text body. Falls back to text/html (tags stripped)."""
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp  = (part.get("Content-Disposition") or "").lower()
            if ctype == "text/plain" and "attachment" not in disp:
                payload = part.get_payload(decode=True)
                if payload:
                    return payload.decode(part.get_content_charset() or "utf-8", errors="replace")
        for part in msg.walk():
            if part.get_content_type() == "text/html":
                payload = part.get_payload(decode=True)
                if payload:
                    html = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
                    return re.sub(r"<[^>]+>", "", html)
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            return payload.decode(msg.get_content_charset() or "utf-8", errors="replace")
    return ""


# ─────────────── SOC actions (slash commands) ──────────────────────
# Slash commands let an emailer ASK MANEE TO DO things, not just chat.
# Format: a line starting with "/cmd args". Multiple commands per email
# are allowed — each is executed, results are returned in the reply.
#
# Recognised:
#   /whitelist <ip>         add IP to allow-list
#   /blacklist <ip>         add IP to deny-list
#   /unblock   <ip>         release a kernel-level block
#   /block     <ip>         block an IP right now (manual)
#   /investigate <ip>       full IP report (geo, reputation, history)
#   /status                 system snapshot
#   /blocked                currently blocked list
#   /scan      <host>       network scan
#   /pause     <seconds>    pause email alerts
#   /help                   list available actions
#
# Sender is NOT required to be an admin user to send commands — auth is
# implicit: only people who can email manee@build-aura.com can drive it,
# and the inbox is monitored manually. For production you'd add a
# command_allowlist in config.

_CMD_RX = re.compile(r"^\s*/([a-z][a-z0-9-]*)\s*(.*)$", re.IGNORECASE)


def _ip_ok(s: str) -> bool:
    return bool(re.match(r"^[0-9]{1,3}(\.[0-9]{1,3}){3}(/\d+)?$", s.strip()))


def _execute_command(cmd: str, args: str) -> dict:
    """Dispatch one slash command. Returns {'ok', 'detail'} suitable for inclusion in the reply."""
    cmd = cmd.lower().strip()
    args = args.strip()
    try:
        if cmd in ("help", "?"):
            return {"ok": True, "detail":
                "Available commands you can email me:\n"
                "  /status                 — system snapshot\n"
                "  /blocked                — list currently blocked IPs\n"
                "  /whitelist <ip>         — add to allow-list (Manee will never block this IP)\n"
                "  /blacklist <ip>         — add to deny-list\n"
                "  /block <ip>             — block an IP right now\n"
                "  /unblock <ip>           — release a block\n"
                "  /investigate <ip>       — full report on one IP\n"
                "  /pause <seconds>        — pause email alerts (e.g. 3600)\n"
                "  /scan <host>            — network scan a target\n"
                "  /help                   — this list"}

        if cmd in ("whitelist", "allow", "trust"):
            if not _ip_ok(args): return {"ok": False, "detail": f"/whitelist needs a valid IP (got {args!r})"}
            from husn.src.core import lists
            lists.add("ip-allow", args)
            return {"ok": True, "detail": f"✓ {args} added to whitelist — Manee will never block this IP"}

        if cmd in ("blacklist", "deny"):
            if not _ip_ok(args): return {"ok": False, "detail": f"/blacklist needs a valid IP (got {args!r})"}
            from husn.src.core import lists
            lists.add("ip-deny", args)
            return {"ok": True, "detail": f"✓ {args} added to blacklist"}

        if cmd in ("block",):
            if not _ip_ok(args): return {"ok": False, "detail": f"/block needs a valid IP (got {args!r})"}
            from husn.src.ai.model import HusnAI  # noqa
            # Use the singleton responder via the running app
            import husn.src.core.response as _rsp
            r = _rsp.responder.block_ip(args, attack_type="Manual (email)", severity="High", confidence=1.0)
            return {"ok": bool(r.get("ok")), "detail": f"block result: {r}"}

        if cmd in ("unblock", "release"):
            if not _ip_ok(args): return {"ok": False, "detail": f"/unblock needs a valid IP (got {args!r})"}
            import husn.src.core.response as _rsp
            r = _rsp.responder.unblock_ip(args)
            return {"ok": bool(r.get("ok")), "detail": f"unblock result: {r}"}

        if cmd in ("status",):
            from husn.src.system.traffic import sampler
            from husn.src.sniffer.sniffer import sniffer
            from husn.src.honeypot.server import honeypot
            import husn.src.core.response as _rsp
            blk = _rsp.responder.list_blocked()
            return {"ok": True, "detail":
                f"System snapshot:\n"
                f"  Blocked IPs    : {len(blk)}\n"
                f"  Sniffer running: {sniffer.status().get('running', False)}\n"
                f"  Honeypot       : {honeypot.status().get('running', False)} on {honeypot.status().get('listening_ports', [])}\n"
                f"  Active flows   : {sniffer.status().get('active_flows', 0)}\n"
                f"  Predictions    : {sniffer.status().get('predictions', 0)}\n"}

        if cmd in ("blocked",):
            import husn.src.core.response as _rsp
            blk = _rsp.responder.list_blocked()
            if not blk:
                return {"ok": True, "detail": "No IPs are currently blocked."}
            lines = [f"  {b['ip']:<18} {b['attack_type']:<22} {b['severity']:<10} {b['confidence']:.0%}"
                     for b in blk[:30]]
            return {"ok": True, "detail": f"Currently blocked ({len(blk)}):\n" + "\n".join(lines)}

        if cmd in ("investigate", "investigate"):
            if not _ip_ok(args): return {"ok": False, "detail": f"/investigate needs a valid IP (got {args!r})"}
            from husn.src.intel import geoip, reputation
            import husn.src.core.response as _rsp
            geo = geoip.lookup(args) or {}
            rep = reputation.lookup(args) if hasattr(reputation, "lookup") else {}
            blocked_now = any(b["ip"] == args for b in _rsp.responder.list_blocked())
            return {"ok": True, "detail":
                f"Investigation: {args}\n"
                f"  Country     : {geo.get('country', '—')} ({geo.get('country_code', '?')})\n"
                f"  ISP         : {geo.get('isp', '—')}\n"
                f"  Reputation  : {rep.get('score', '—') if isinstance(rep, dict) else '—'}\n"
                f"  Currently blocked: {'YES' if blocked_now else 'no'}"}

        if cmd in ("pause",):
            try: secs = int(args or "3600")
            except ValueError: return {"ok": False, "detail": f"/pause needs an integer seconds (got {args!r})"}
            from husn.src.notify import settings
            settings.set_pause(secs)
            return {"ok": True, "detail": f"✓ Email alerts paused for {secs}s"}

        if cmd in ("scan",):
            host = args.strip().split()[0] if args.strip() else ""
            if not host:
                return {"ok": False, "detail": "/scan needs a host (IP or domain)"}
            try:
                from husn.src.system import scan as _scan
                result = _scan.scan(host)
                if result.get("error"):
                    return {"ok": False, "detail": f"scan error: {result['error']}"}
                ports = ", ".join(f"{p['port']}/{p['service']}" for p in (result.get("open_ports") or [])[:10])
                return {"ok": True, "detail":
                    f"Scan {host} ({result.get('resolved_ip', '?')}) — {result.get('engine', '?')}\n"
                    f"  Open ports: {ports or 'none'}"}
            except Exception as e:
                return {"ok": False, "detail": f"scan crashed: {e}"}

        return {"ok": False, "detail": f"Unknown command: /{cmd}. Send /help for the list."}
    except Exception as e:
        log.exception("[inbox] command /%s failed", cmd)
        return {"ok": False, "detail": f"Command failed: {e}"}


def _parse_and_run_commands(body: str) -> tuple[list[str], str]:
    """Pull /cmd lines out of the body, execute each. Return (list of formatted
    result strings, body with command lines stripped)."""
    results: list[str] = []
    remaining: list[str] = []
    for line in body.splitlines():
        m = _CMD_RX.match(line)
        if not m:
            remaining.append(line)
            continue
        cmd, args = m.group(1), m.group(2)
        r = _execute_command(cmd, args)
        marker = "✓" if r.get("ok") else "✗"
        results.append(f"[{marker} /{cmd}] {r.get('detail', '')}")
    return results, "\n".join(remaining).strip()


def _md_to_html(text: str) -> str:
    """Lightweight markdown → email-safe HTML.

    Handles **bold**, *italic*, `code`, headings, ordered + unordered
    lists, fenced code blocks, links, and paragraph breaks. Doesn't
    pull in the Python `markdown` package (one less pip install on the
    VPS, faster cold start).
    """
    if not text:
        return ""

    # 1. Escape HTML first — anything that survives must be markdown
    #    we explicitly transform below.
    s = (text.replace("&", "&amp;")
             .replace("<", "&lt;")
             .replace(">", "&gt;"))

    # 2. Fenced code blocks ```lang\n...\n```
    def _fence(m):
        body = m.group(2).strip()
        return (f'<pre style="background:#050505;border:1px solid rgba(255,255,255,0.10);'
                f'border-radius:6px;padding:10px;overflow-x:auto;font-family:ui-monospace,Menlo,Monaco,monospace;'
                f'font-size:12px;color:#a1a1aa;margin:8px 0">{body}</pre>')
    s = re.sub(r"```(\w*)\n([\s\S]*?)```", _fence, s)

    # 3. Inline `code`
    s = re.sub(r"`([^`\n]+)`",
               r'<code style="background:rgba(255,255,255,0.06);border:1px solid rgba(255,255,255,0.10);'
               r'padding:1px 5px;border-radius:3px;font-family:ui-monospace,Menlo,Monaco,monospace;'
               r'font-size:12px;color:#e4e4e7">\1</code>', s)

    # 4. Bold **text** and italic *text*  (bold first, so ** doesn't get eaten)
    s = re.sub(r"\*\*([^*\n]+)\*\*",
               r'<strong style="color:#ffffff;font-weight:600">\1</strong>', s)
    s = re.sub(r"(?<![\w*])\*([^*\n]+)\*(?!\*)",
               r'<em style="color:#e4e4e7">\1</em>', s)

    # 5. Headings (# / ## / ###) — only at line start
    s = re.sub(r"^### (.+)$",
               r'<h4 style="color:#fff;font-size:13px;margin:14px 0 6px;letter-spacing:0.05em">\1</h4>',
               s, flags=re.MULTILINE)
    s = re.sub(r"^## (.+)$",
               r'<h3 style="color:#fff;font-size:14px;margin:16px 0 8px;letter-spacing:0.05em">\1</h3>',
               s, flags=re.MULTILINE)
    s = re.sub(r"^# (.+)$",
               r'<h2 style="color:#fff;font-size:16px;margin:18px 0 10px;letter-spacing:0.04em">\1</h2>',
               s, flags=re.MULTILINE)

    # 6. Links [text](url)
    s = re.sub(r"\[([^\]]+)\]\(([^)]+)\)",
               r'<a href="\2" style="color:#10b981;text-decoration:underline">\1</a>', s)

    # 7. Lists — group consecutive list lines into <ul>/<ol>
    out_lines: list[str] = []
    in_ul = in_ol = False
    for line in s.split("\n"):
        stripped = line.lstrip()
        ul_m = re.match(r"^[-*]\s+(.+)$", stripped)
        ol_m = re.match(r"^\d+\.\s+(.+)$", stripped)
        if ul_m:
            if in_ol:
                out_lines.append("</ol>"); in_ol = False
            if not in_ul:
                out_lines.append('<ul style="margin:6px 0;padding-inline-start:20px;color:#a1a1aa">')
                in_ul = True
            out_lines.append(f'<li style="margin:3px 0">{ul_m.group(1)}</li>')
        elif ol_m:
            if in_ul:
                out_lines.append("</ul>"); in_ul = False
            if not in_ol:
                out_lines.append('<ol style="margin:6px 0;padding-inline-start:22px;color:#a1a1aa">')
                in_ol = True
            out_lines.append(f'<li style="margin:3px 0">{ol_m.group(1)}</li>')
        else:
            if in_ul:
                out_lines.append("</ul>"); in_ul = False
            if in_ol:
                out_lines.append("</ol>"); in_ol = False
            out_lines.append(line)
    if in_ul: out_lines.append("</ul>")
    if in_ol: out_lines.append("</ol>")
    s = "\n".join(out_lines)

    # 8. Paragraphs — blank line splits into <p> blocks; single newlines stay as <br>
    paragraphs = [p.strip() for p in re.split(r"\n\s*\n", s) if p.strip()]
    blocks = []
    for p in paragraphs:
        # Don't wrap raw block elements (headings, lists, pre) in <p>
        if re.match(r"^<(h\d|ul|ol|pre|div)", p):
            blocks.append(p)
        else:
            inner = p.replace("\n", "<br/>")
            blocks.append(f'<p style="margin:8px 0;line-height:1.65">{inner}</p>')
    return "\n".join(blocks)


def _build_html_reply(reply_text: str, original_subject: str) -> str:
    rendered = _md_to_html(reply_text)
    return f"""<!doctype html>
<html><body style="margin:0;padding:0;background:#000000;font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#e4e4e7">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#000000">
<tr><td align="center" style="padding:32px 12px">
  <table role="presentation" width="640" cellpadding="0" cellspacing="0" style="background:#0a0a0a;border:1px solid rgba(255,255,255,0.08);border-radius:14px;overflow:hidden;max-width:640px;width:100%">
    <tr><td style="padding:22px 28px;border-bottom:1px solid rgba(16,185,129,0.30);background:#08160e">
      <div style="font-size:10px;letter-spacing:0.22em;color:#71717a;text-transform:uppercase;font-weight:600">منيع · Manee · SOC Analyst</div>
      <div style="font-size:18px;font-weight:600;margin-top:6px;color:#ffffff">Auto-reply from the AI analyst</div>
      <div style="font-size:11px;color:#a1a1aa;margin-top:6px">Re: {original_subject or "(no subject)"}</div>
    </td></tr>
    <tr><td style="padding:24px 28px;background:#0a0a0a;font-family:Inter,sans-serif;font-size:14px;line-height:1.65;color:#e4e4e7">
      {rendered}
    </td></tr>
    <tr><td style="padding:18px 28px;background:#000000;border-top:1px solid rgba(255,255,255,0.06);font-size:10px;color:#52525b;letter-spacing:0.10em;line-height:1.6">
      Auto-generated by <strong style="color:#a1a1aa">Manee SOC Analyst</strong> · DeepSeek-powered<br/>
      <span style="color:#3f3f46">Reply to this thread to ask follow-up questions. The conversation is remembered per sender address.</span>
    </td></tr>
  </table>
</td></tr></table>
</body></html>"""


# ─────────────── The main poll loop ─────────────────────────────────

def poll_and_reply() -> dict[str, Any]:
    """One IMAP poll cycle. Returns a summary suitable for the API."""
    if not is_enabled():
        return {"ok": False, "skipped": "inbox listener disabled in config"}

    smtp = _smtp_cfg()
    user = smtp.get("user")
    password = smtp.get("password")
    if not user or not password:
        return {"ok": False, "error": "SMTP/IMAP credentials missing"}

    cfg       = _cfg()
    imap_host = cfg.get("imap_host") or "imap.hostinger.com"
    imap_port = int(cfg.get("imap_port") or 993)
    folder    = cfg.get("folder") or "INBOX"
    max_per   = int(cfg.get("max_per_poll") or 10)

    seen = _load_seen()
    processed: list[dict] = []
    failed:    list[dict] = []
    skipped:   list[dict] = []

    try:
        ctx = ssl.create_default_context()
        m = imaplib.IMAP4_SSL(imap_host, imap_port, ssl_context=ctx)
        m.login(user, password)
        m.select(folder)

        typ, ids = m.search(None, "(UNSEEN)")
        if typ != "OK":
            try: m.logout()
            except Exception: pass
            return {"ok": False, "error": "IMAP SEARCH failed"}

        msg_ids = (ids[0] or b"").split()[:max_per]
        for raw_id in msg_ids:
            try:
                typ, data = m.fetch(raw_id, "(RFC822)")
                if typ != "OK" or not data or not data[0]:
                    continue
                msg = email.message_from_bytes(data[0][1])

                m_id = (msg.get("Message-ID") or "").strip()
                if not m_id:
                    m_id = "sha:" + hashlib.sha256(data[0][1]).hexdigest()[:24]
                if m_id in seen:
                    continue
                seen.add(m_id)

                if _is_loop_back(msg):
                    skipped.append({"reason": "loop-back", "subject": msg.get("Subject", "")})
                    continue

                from_addr = parseaddr(msg.get("From", ""))[1]
                subject   = msg.get("Subject", "(no subject)")
                body      = _extract_body(msg)
                question  = _strip_quoted_reply(body)[:4000]

                if not from_addr:
                    skipped.append({"reason": "no sender", "subject": subject})
                    continue

                # ── HARD GATE: only authorized senders may drive Manee ──
                # Anyone else is silently dropped. We do NOT send a
                # rejection email — that would (a) confirm to attackers
                # that the inbox is monitored, and (b) be wasted SMTP
                # quota on noise.
                if not _is_authorized_sender(from_addr):
                    log.warning("[inbox] dropped unauthorized sender: %s subj=%r", from_addr, subject)
                    skipped.append({
                        "reason": "unauthorized sender (not in inbox.allowed_senders or recipients)",
                        "from": from_addr,
                        "subject": subject,
                    })
                    continue

                # Step 1: extract any /commands from the body and execute
                # them. The SOC helper can do real work — block IPs, run
                # scans, change config — not just chat.
                cmd_results, leftover = _parse_and_run_commands(question)

                # Step 2: hand whatever's left (the natural-language part)
                # to the LLM so it can add context, summarise, or just
                # reply if there were no commands at all.
                from husn.src.chat import chatbot
                llm_input = leftover or question
                if cmd_results:
                    # Tell the LLM what we already did so it doesn't re-do it.
                    llm_input = (
                        "I ran the following actions for the user; please write a "
                        "brief friendly summary in their language and add any "
                        "follow-up advice. Do NOT repeat the raw output, the user "
                        "will see it separately.\n\n"
                        + "\n".join(cmd_results)
                        + "\n\nThe user's original message was:\n"
                        + (leftover or "(commands only, no extra question)")
                    )

                if not llm_input.strip():
                    skipped.append({"reason": "empty after parsing", "subject": subject})
                    continue

                resp = chatbot.chat(session_id=f"email:{from_addr.lower()}",
                                    user_message=llm_input)
                llm_text = resp.get("reply", "") if resp.get("ok") else (
                    f"(SOC analyst LLM unavailable — {resp.get('error', 'unknown error')})"
                )

                # Step 3: assemble the reply. Command results come first
                # (concrete actions), then the LLM's narrative.
                if cmd_results:
                    reply_text = (
                        "📋 Actions executed:\n\n"
                        + "\n".join(cmd_results)
                        + "\n\n────────────\n\n"
                        + llm_text
                    )
                else:
                    reply_text = llm_text or "(empty reply)"
                from husn.src.notify import mailer
                reply_subject = subject if subject.lower().startswith("re:") else f"Re: {subject}"
                send_res = mailer.send(
                    subject=reply_subject,
                    html_body=_build_html_reply(reply_text, subject),
                    text_body=reply_text + "\n\n---\nManee SOC Analyst (auto-reply) · Reply to this thread for follow-up.",
                    to=[from_addr],
                )
                if send_res.ok:
                    processed.append({"from": from_addr, "subject": subject, "chars": len(reply_text)})
                    log.info("[inbox] replied to %s subj=%r chars=%d", from_addr, subject, len(reply_text))
                else:
                    failed.append({"from": from_addr, "error": send_res.detail})
            except Exception as e:
                log.exception("[inbox] failed to process one message")
                failed.append({"error": str(e)})

        try: m.logout()
        except Exception: pass

    except Exception as e:
        log.exception("[inbox] poll cycle crashed")
        return {"ok": False, "error": str(e)}

    _save_seen(seen)
    return {
        "ok": True,
        "processed_count": len(processed),
        "failed_count":    len(failed),
        "skipped_count":   len(skipped),
        "processed": processed,
        "failed":    failed,
        "skipped":   skipped,
        "ts": time.time(),
    }


# ─────────────── APScheduler integration ────────────────────────────

_scheduler = None


_stop_event = None


def start_scheduler() -> None:
    """Idempotent — call from the FastAPI lifespan. Skips if disabled.

    Uses a plain `threading.Thread` (not APScheduler) so we can prove
    in the journal that polls are actually firing. Background threads
    started via APScheduler have caused silent no-ops on this box; a
    bare thread + sleep loop is impossible to misconfigure.
    """
    global _scheduler, _stop_event
    if _scheduler is not None or not is_enabled():
        return

    import threading

    interval = int(_cfg().get("interval_seconds") or 60)
    _stop_event = threading.Event()

    def _loop():
        # First poll after a short warm-up delay so the rest of the
        # backend has finished booting (config reload, AI load, etc).
        if _stop_event.wait(8):
            return
        log.info("[inbox] poll loop entered, interval=%ds", interval)
        while not _stop_event.is_set():
            try:
                res = poll_and_reply()
                _debug_log_poll_outcome(res)
            except Exception:
                log.exception("[inbox] poll iteration crashed (continuing)")
            if _stop_event.wait(interval):
                break
        log.info("[inbox] poll loop exited")

    t = threading.Thread(target=_loop, name="manee-inbox-poll", daemon=True)
    t.start()
    _scheduler = t
    log.info("[inbox] listener thread started — first poll in 8s, then every %ds against %s",
             interval, _cfg().get("imap_host"))


def _debug_log_poll_outcome(result: dict) -> None:
    """Lightweight log every poll cycle so journalctl always shows
    activity even when there's no new mail. Helps prove the scheduler
    is actually firing."""
    if not result.get("ok"):
        log.warning("[inbox] poll error: %s", result.get("error") or result)
        return
    p = result.get("processed_count", 0)
    s = result.get("skipped_count", 0)
    f = result.get("failed_count", 0)
    if p or f or s:
        log.info("[inbox] poll → %d processed, %d skipped, %d failed", p, s, f)
    else:
        log.debug("[inbox] poll → no new mail")


def stop_scheduler() -> None:
    global _scheduler, _stop_event
    if _stop_event is not None:
        _stop_event.set()
    if _scheduler is not None:
        # The thread is daemon so it dies with the process. Don't bother
        # joining — uvicorn shutdown timeout would block.
        _scheduler = None
