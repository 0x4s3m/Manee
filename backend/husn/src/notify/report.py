"""Incident report builder.

When `DefenseResponse.block_ip` fires, this module turns the event into a
human-readable report (Markdown + HTML + JSON), persists it to disk, and
emails the HTML version to the configured recipients with the SHAP
feature-importance chart inlined.

Throttling: a single source IP triggers at most one email per
`notify.throttle_seconds`, but every event still goes to disk.
"""
from __future__ import annotations

import io
import json
import logging
import socket
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from husn.src import config
from husn.src.notify import mailer, settings as notify_settings
from husn.src.notify.explanation import explain as nl_explain

log = logging.getLogger("husn.report")

# Last-sent timestamp per source IP — used by the throttler.
_last_sent: dict[str, float] = {}


@dataclass
class Incident:
    source_ip: str
    attack_type: str
    severity: str
    confidence: float = 0.0
    target: str = ""
    action: str = ""
    detected_at: float = field(default_factory=time.time)
    extras: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_ip": self.source_ip,
            "attack_type": self.attack_type,
            "severity": self.severity,
            "confidence": self.confidence,
            "target": self.target or socket.gethostname(),
            "action": self.action,
            "detected_at": self.detected_at,
            "detected_at_iso": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(self.detected_at)),
            "host": socket.gethostname(),
            "domain": config.get("domain", ""),
            "organization": config.get("organization.name", "Manee Defense"),
            **self.extras,
        }


def _should_send(source_ip: str) -> bool:
    window = int(config.get("notify.throttle_seconds", 60))
    now = time.time()
    last = _last_sent.get(source_ip, 0)
    if now - last < window:
        return False
    _last_sent[source_ip] = now
    return True


def _reports_dir() -> Path:
    p = Path(config.get("paths.reports_dir") or (Path.cwd() / "reports"))
    p.mkdir(parents=True, exist_ok=True)
    return p


def _shap_chart_png(features: list[dict[str, Any]]) -> bytes | None:
    """Render the current feature-importance chart as a PNG. Returns None if
    matplotlib isn't usable headless (very rare)."""
    if not features:
        return None
    try:
        import os
        os.environ.setdefault("MPLCONFIGDIR", "/tmp/matplotlib")
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception:
        return None

    top = sorted(features, key=lambda r: abs(r.get("value", 0)), reverse=True)[:10]
    names = [r["name"] for r in top][::-1]
    values = [r["value"] for r in top][::-1]

    fig, ax = plt.subplots(figsize=(7, 4), dpi=140)
    ax.barh(names, values, color="#00ff9d")
    ax.set_facecolor("#0a0e14")
    fig.patch.set_facecolor("#0a0e14")
    ax.set_title("AI Decision — Top Features (SHAP)", color="#e6f1ff")
    ax.tick_params(colors="#9aa6b2")
    for spine in ax.spines.values():
        spine.set_color("#1f2a37")
    fig.tight_layout()

    buf = io.BytesIO()
    fig.savefig(buf, format="png", facecolor=fig.get_facecolor())
    plt.close(fig)
    return buf.getvalue()


# ────── Severity → palette ────────────────────────────────────────────
# Email clients are inconsistent with CSS — keep colors as inline hex
# values everywhere. The hero band, the badge, and the recommended-action
# bullets all key off the same severity color so the visual urgency
# matches the words.
def _sev_palette(severity: str) -> dict[str, str]:
    s = (severity or "low").lower()
    if s == "critical":
        return {"name": "CRITICAL", "color": "#f43f5e", "bg": "#1a0810",
                "icon": "⚠", "tag": "Immediate response required"}
    if s == "high":
        return {"name": "HIGH",     "color": "#f97316", "bg": "#1a0d05",
                "icon": "▲", "tag": "Active threat — review now"}
    if s == "medium":
        return {"name": "MEDIUM",   "color": "#f59e0b", "bg": "#1a1208",
                "icon": "●", "tag": "Suspicious activity"}
    return {"name": "LOW",          "color": "#10b981", "bg": "#08160e",
            "icon": "✓", "tag": "Routine detection"}


def _ago_str(detected_at: float) -> str:
    delta = max(0, int(time.time() - detected_at))
    if delta < 60:    return f"{delta}s ago"
    if delta < 3600:  return f"{delta // 60}m ago"
    if delta < 86400: return f"{delta // 3600}h ago"
    return f"{delta // 86400}d ago"


def _markdown(inc: dict[str, Any]) -> str:
    sig = inc.get("signature") or "—"
    return f"""# 🛡 Manee Incident Report

> **{inc['severity'].upper()}** — {inc['attack_type']} from `{inc['source_ip']}`
> Detected {inc['detected_at_iso']} on host `{inc['host']}`

---

## Threat

| Field | Value |
|---|---|
| Source IP | `{inc['source_ip']}` |
| Attack Type | **{inc['attack_type']}** |
| Severity | **{inc['severity']}** |
| AI Confidence | {inc['confidence']:.2%} |
| Signature Match | {sig} |
| Target | `{inc['target']}` |
| Host | `{inc['host']}` |
| Detected (UTC) | {inc['detected_at_iso']} |

## Response
- **{inc['action']}**

## Recommended actions
1. Open the **Manee Dashboard → Defense** to review the live block list.
2. If this IP is yours or a partner, add it to **Defense → Whitelist**.
3. Open **Kill Chain** to see how far the attacker progressed.
4. Open **AI Inspector** for the exact 17 features and payload preview.
5. If false positive: unblock from the dashboard and we'll log a learning sample.

---

_Generated automatically by Manee (منيع) Intelligent Cyber Defense System.
No human intervention was required to detect or contain this threat._
"""


def _explanation_block_html(exp: dict[str, str] | None) -> str:
    if not exp: return ""
    return (
        '<tr><td style="padding:20px 28px;background:#0a0a0a;border-top:1px solid rgba(255,255,255,0.08)">'
        '<div style="font-size:10px;letter-spacing:0.20em;color:#71717a;text-transform:uppercase;margin-bottom:10px;font-weight:600">'
        '⊙ What this means'
        '</div>'
        f'<p style="font-size:14px;color:#e4e4e7;line-height:1.6;margin:0 0 12px 0">{exp["en"]}</p>'
        f'<p dir="rtl" style="font-size:14px;color:#a1a1aa;line-height:1.8;margin:0;font-family:Tahoma,Arial,sans-serif;border-top:1px solid rgba(255,255,255,0.05);padding-top:10px">{exp["ar"]}</p>'
        '</td></tr>'
    )


def _html(inc: dict[str, Any], has_chart: bool, explanation: dict[str, str] | None = None) -> str:
    pal = _sev_palette(inc["severity"])
    ago = _ago_str(inc["detected_at"])
    sig = inc.get("signature")
    domain = inc.get("domain") or ""
    dash_url = f"https://{domain}/" if domain else "#"

    # ── Optional signature row (only when payload-scanner matched) ──────
    sig_row = ""
    if sig:
        sig_row = (
            '<tr>'
            '<td style="padding:8px 0;color:#71717a;width:160px;vertical-align:top;font-size:13px">Signature match</td>'
            f'<td style="padding:8px 0">'
            f'<span style="display:inline-block;padding:3px 10px;border-radius:6px;background:rgba(245,158,11,0.10);'
            f'border:1px solid rgba(245,158,11,0.40);color:#f59e0b;font-size:12px;font-family:ui-monospace,Menlo,monospace">'
            f'⚠ {sig}</span></td></tr>'
        )

    # ── SHAP chart block (CID-inlined, with caption) ───────────────────
    chart_block = (
        '<tr><td style="padding:0 28px 24px 28px;background:#0a0a0a">'
        '<div style="background:#050505;border:1px solid rgba(255,255,255,0.08);border-radius:10px;overflow:hidden">'
        '<div style="padding:14px 18px;border-bottom:1px solid rgba(255,255,255,0.06)">'
        '<div style="font-size:10px;letter-spacing:0.20em;color:#71717a;text-transform:uppercase;font-weight:600">⌬ AI Decision · SHAP top features</div>'
        '<div style="font-size:11px;color:#52525b;margin-top:4px">Bars show which features pushed the verdict towards anomaly. Longer = more influence.</div>'
        '</div>'
        '<div style="padding:14px 14px 8px 14px;text-align:center">'
        '<img src="cid:shap_chart" alt="SHAP feature importance" '
        'style="max-width:100%;height:auto;border-radius:6px;display:block;margin:0 auto"/>'
        '</div></div></td></tr>'
        if has_chart else ""
    )

    # ── CTA row — only if a domain is configured ────────────────────────
    cta_row = ""
    if domain:
        cta_row = (
            '<tr><td style="padding:8px 28px 24px 28px;background:#0a0a0a">'
            '<table role="presentation" width="100%" cellpadding="0" cellspacing="0">'
            '<tr>'
            f'<td style="text-align:center"><!--[if mso]><v:roundrect xmlns:v="urn:schemas-microsoft-com:vml" xmlns:w="urn:schemas-microsoft-com:office:word" href="{dash_url}" style="height:42px;v-text-anchor:middle;width:200px;" arcsize="14%" stroke="f" fillcolor="#ffffff"><w:anchorlock/><center style="color:#000;font-family:sans-serif;font-size:13px;font-weight:600">Open Dashboard</center></v:roundrect><![endif]-->'
            f'<a href="{dash_url}" style="background:#ffffff;color:#000000;text-decoration:none;padding:12px 28px;border-radius:8px;display:inline-block;font-size:13px;font-weight:600;letter-spacing:0.10em;text-transform:uppercase;mso-hide:all">Open Dashboard</a>'
            '</td></tr></table></td></tr>'
        )

    # ── Recommended actions checklist ───────────────────────────────────
    actions_block = (
        '<tr><td style="padding:18px 28px 22px 28px;background:#050505;border-top:1px solid rgba(255,255,255,0.06)">'
        '<div style="font-size:10px;letter-spacing:0.20em;color:#71717a;text-transform:uppercase;font-weight:600;margin-bottom:14px">↳ Recommended actions</div>'
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="font-size:13px;color:#a1a1aa;line-height:1.6">'
        f'<tr><td style="width:24px;color:{pal["color"]};font-weight:700;vertical-align:top;padding:3px 8px 3px 0">1.</td><td style="padding:3px 0">Review the live block in <strong style="color:#fff">Dashboard → Defense</strong>.</td></tr>'
        f'<tr><td style="color:{pal["color"]};font-weight:700;vertical-align:top;padding:3px 8px 3px 0">2.</td><td style="padding:3px 0">If this IP is yours, add it to <strong style="color:#fff">Defense → Whitelist</strong>.</td></tr>'
        f'<tr><td style="color:{pal["color"]};font-weight:700;vertical-align:top;padding:3px 8px 3px 0">3.</td><td style="padding:3px 0">Open <strong style="color:#fff">Kill Chain</strong> to see how far the attacker progressed.</td></tr>'
        f'<tr><td style="color:{pal["color"]};font-weight:700;vertical-align:top;padding:3px 8px 3px 0">4.</td><td style="padding:3px 0">Open <strong style="color:#fff">AI Inspector</strong> for features and payload preview.</td></tr>'
        f'<tr><td style="color:{pal["color"]};font-weight:700;vertical-align:top;padding:3px 8px 3px 0">5.</td><td style="padding:3px 0">Mark as false positive (unblock) — Manee logs it as a learning sample.</td></tr>'
        '</table></td></tr>'
    )

    return f"""<!doctype html>
<html lang="en" dir="ltr"><head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<meta name="x-apple-disable-message-reformatting"/>
<title>Manee Incident — {inc['attack_type']}</title>
</head>
<body style="margin:0;padding:0;background:#000000;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#e4e4e7;-webkit-font-smoothing:antialiased">
<!-- Preheader (hidden but shown in inbox previews) -->
<div style="display:none;max-height:0;overflow:hidden;color:transparent;font-size:1px">
{pal['name']} alert · {inc['attack_type']} from {inc['source_ip']} · {ago} · Manee Defense Grid blocked it automatically.
</div>

<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#000000">
<tr><td align="center" style="padding:32px 12px">
  <table role="presentation" width="640" cellpadding="0" cellspacing="0" style="background:#0a0a0a;border:1px solid rgba(255,255,255,0.08);border-radius:14px;overflow:hidden;max-width:640px;width:100%">

    <!-- ============== HERO ============== -->
    <tr><td style="background:{pal['bg']};border-bottom:1px solid {pal['color']}40;padding:24px 28px">
      <table width="100%" cellpadding="0" cellspacing="0">
        <tr>
          <td style="vertical-align:top">
            <div style="font-size:10px;letter-spacing:0.22em;color:#71717a;text-transform:uppercase;font-weight:600">منيع · Manee Defense Grid</div>
            <div style="font-size:24px;font-weight:600;margin-top:6px;color:#ffffff;letter-spacing:0.5px">
              <span style="color:{pal['color']};font-size:24px;margin-right:8px">{pal['icon']}</span>
              {inc['attack_type']}
            </div>
            <div style="font-size:12px;color:#a1a1aa;margin-top:6px">{pal['tag']} · detected {ago}</div>
          </td>
          <td style="vertical-align:top;text-align:right;width:120px">
            <div style="display:inline-block;padding:6px 14px;border-radius:999px;background:{pal['color']};color:#000000;font-weight:700;font-size:11px;letter-spacing:0.14em">{pal['name']}</div>
          </td>
        </tr>
      </table>
    </td></tr>

    <!-- ============== STATUS BAR ============== -->
    <tr><td style="background:#050505;padding:12px 28px;border-bottom:1px solid rgba(255,255,255,0.06)">
      <table width="100%" cellpadding="0" cellspacing="0" style="font-size:11px;color:#71717a;text-transform:uppercase;letter-spacing:0.14em">
        <tr>
          <td>● <span style="color:#10b981;font-weight:600">Auto-blocked</span></td>
          <td style="text-align:center">{inc['detected_at_iso']}</td>
          <td style="text-align:right">host <span style="color:#a1a1aa;font-family:ui-monospace,Menlo,monospace">{inc['host']}</span></td>
        </tr>
      </table>
    </td></tr>

    <!-- ============== THREAT FACTS ============== -->
    <tr><td style="padding:24px 28px;background:#0a0a0a">
      <table width="100%" cellpadding="0" cellspacing="0" style="font-size:13px;line-height:1.6">
        <tr>
          <td style="padding:8px 0;color:#71717a;width:160px;vertical-align:top">Source IP</td>
          <td style="padding:8px 0"><code style="color:{pal['color']};font-size:14px;font-family:ui-monospace,Menlo,Monaco,monospace;background:rgba(255,255,255,0.04);padding:3px 8px;border-radius:5px">{inc['source_ip']}</code></td>
        </tr>
        <tr>
          <td style="padding:8px 0;color:#71717a;vertical-align:top">Attack type</td>
          <td style="padding:8px 0;color:#ffffff;font-weight:600">{inc['attack_type']}</td>
        </tr>
        <tr>
          <td style="padding:8px 0;color:#71717a;vertical-align:top">AI confidence</td>
          <td style="padding:8px 0">
            <table cellpadding="0" cellspacing="0">
              <tr>
                <td style="font-size:14px;color:#fff;font-weight:600;padding-right:10px">{inc['confidence']:.1%}</td>
                <td>
                  <table cellpadding="0" cellspacing="0" width="120" style="background:rgba(255,255,255,0.06);border-radius:3px;height:6px">
                    <tr><td style="background:{pal['color']};border-radius:3px;height:6px;width:{int(min(120, max(8, inc['confidence'] * 120)))}px"></td></tr>
                  </table>
                </td>
              </tr>
            </table>
          </td>
        </tr>
        {sig_row}
        <tr>
          <td style="padding:8px 0;color:#71717a;vertical-align:top">Target</td>
          <td style="padding:8px 0;color:#e4e4e7;font-family:ui-monospace,Menlo,monospace">{inc['target']}</td>
        </tr>
        <tr>
          <td style="padding:8px 0;color:#71717a;vertical-align:top">Action taken</td>
          <td style="padding:8px 0;color:#10b981;font-weight:600">✓ {inc['action']}</td>
        </tr>
      </table>
    </td></tr>

    {cta_row}
    {chart_block}
    {_explanation_block_html(explanation)}
    {actions_block}

    <!-- ============== FOOTER ============== -->
    <tr><td style="padding:18px 28px;background:#000000;border-top:1px solid rgba(255,255,255,0.06)">
      <table width="100%" cellpadding="0" cellspacing="0">
        <tr>
          <td style="font-size:10px;color:#52525b;letter-spacing:0.10em;line-height:1.6">
            Auto-generated by <strong style="color:#a1a1aa">منيع · Manee</strong> Intelligent Cyber Defense System<br/>
            <span style="color:#3f3f46">No human intervention was required to detect or contain this threat.</span>
          </td>
          <td style="text-align:right;font-size:10px;color:#52525b;letter-spacing:0.10em;vertical-align:top">
            DefensThon 2026
          </td>
        </tr>
      </table>
    </td></tr>

  </table>
  <div style="margin-top:14px;font-size:10px;color:#3f3f46;letter-spacing:0.16em">
    Manee · منيع · Defense Grid
  </div>
</td></tr></table>
</body></html>"""


def emit(
    incident: Incident,
    feature_importance: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Persist + (throttled) email an incident. Returns a result dict."""
    inc = incident.to_dict()
    timestamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime(incident.detected_at))
    safe_ip = incident.source_ip.replace(":", "_").replace("/", "_")
    base = _reports_dir() / f"{timestamp}_{safe_ip}_{incident.attack_type.replace(' ', '_')}"

    md = _markdown(inc)
    json_blob = json.dumps(inc, indent=2)
    chart_png = (
        _shap_chart_png(feature_importance or [])
        if config.get("notify.attach_shap_chart", True)
        else None
    )
    explanation = nl_explain(
        incident.attack_type, incident.confidence,
        feature_importance or [], incident.source_ip,
    )
    inc["explanation"] = explanation  # also persisted in JSON / available in report
    html = _html(inc, has_chart=chart_png is not None, explanation=explanation)

    base.with_suffix(".md").write_text(md, encoding="utf-8")
    base.with_suffix(".html").write_text(html, encoding="utf-8")
    base.with_suffix(".json").write_text(json_blob, encoding="utf-8")

    result: dict[str, Any] = {
        "incident": inc,
        "report_path": str(base.with_suffix(".html")),
        "throttled": False,
        "email": None,
    }

    # Operator-set runtime gates (pause + severity threshold)
    allowed, reason = notify_settings.should_send(incident.severity)
    if not allowed:
        result["throttled"] = True
        result["skipped_reason"] = reason
        log.info("[report] skipped email — %s", reason)
        return result

    if not _should_send(incident.source_ip):
        result["throttled"] = True
        log.info("[report] throttled email for %s (within %ss window)",
                 incident.source_ip, config.get("notify.throttle_seconds", 60))
        return result

    sev_emoji = {"critical": "🚨", "high": "⚠️", "medium": "⚡", "low": "ℹ️"}.get(
        incident.severity.lower(), "🛡"
    )
    subject = (
        f"{sev_emoji} [Manee · {incident.severity.upper()}] "
        f"{incident.attack_type} from {incident.source_ip} → blocked"
    )
    inline = {"shap_chart": chart_png} if chart_png else None
    attachments = {f"{base.name}.md": md.encode("utf-8")}
    send_result = mailer.send(subject, html, md, inline_images=inline, attachments=attachments)
    result["email"] = {"ok": send_result.ok, "detail": send_result.detail, "to": send_result.recipients}
    return result


def send_test_email() -> dict[str, Any]:
    """Trigger a dummy incident — handy for verifying SMTP from the dashboard."""
    inc = Incident(
        source_ip="203.0.113.42",
        attack_type="Test Alert",
        severity="Low",
        confidence=0.99,
        target=socket.gethostname(),
        action="None — this is a test message",
    )
    return emit(inc, feature_importance=[])
