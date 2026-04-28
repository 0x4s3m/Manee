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
from husn.src.notify import mailer
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
            "organization": config.get("organization.name", "Husn Defense"),
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


def _markdown(inc: dict[str, Any]) -> str:
    return f"""# Husn Incident Report

**Detected**: {inc['detected_at_iso']}
**Host**: `{inc['host']}` ({inc.get('domain') or 'no domain configured'})
**Organization**: {inc['organization']}

## Threat
- **Source IP**: `{inc['source_ip']}`
- **Attack Type**: **{inc['attack_type']}**
- **Severity**: {inc['severity']}
- **AI Confidence**: {inc['confidence']:.2%}

## Response
- **Action Taken**: {inc['action']}
- **Target**: `{inc['target']}`

## Notes
This report was generated automatically by the Husn (حصن) Intelligent Cyber Defense System.
No human intervention was required to detect or contain this threat.
"""


def _explanation_block_html(exp: dict[str, str] | None) -> str:
    if not exp: return ""
    return (
        '<tr><td style="padding:18px 32px;background:#0e1520;border-top:1px solid #1f2a37">'
        '<div style="font-size:11px;letter-spacing:0.18em;color:#8b919e;text-transform:uppercase;margin-bottom:8px">Explanation</div>'
        f'<p style="font-size:14px;color:#e6f1ff;line-height:1.55;margin:0 0 10px 0">{exp["en"]}</p>'
        f'<p dir="rtl" style="font-size:14px;color:#e6f1ff;line-height:1.7;margin:0;font-family:Arial,sans-serif">{exp["ar"]}</p>'
        '</td></tr>'
    )


def _html(inc: dict[str, Any], has_chart: bool, explanation: dict[str, str] | None = None) -> str:
    chart_block = (
        '<tr><td style="padding:24px 32px;background:#0a0e14;text-align:center">'
        '<img src="cid:shap_chart" alt="SHAP feature importance" '
        'style="max-width:100%;border-radius:8px;border:1px solid #1f2a37"/></td></tr>'
        if has_chart else ""
    )
    sev = inc["severity"].lower()
    sev_color = {"high": "#ff3860", "medium": "#ffdd57", "low": "#48c774"}.get(sev, "#00ff9d")
    return f"""<!doctype html>
<html><body style="margin:0;padding:0;background:#0a0e14;font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#e6f1ff">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#0a0e14">
<tr><td align="center" style="padding:40px 16px">
  <table role="presentation" width="640" cellpadding="0" cellspacing="0" style="background:#0e1520;border:1px solid #1f2a37;border-radius:12px;overflow:hidden">
    <tr><td style="padding:24px 32px;background:linear-gradient(90deg,#0e1520,#102233);border-bottom:1px solid #1f2a37">
      <div style="font-size:12px;letter-spacing:0.2em;color:#00ff9d;text-transform:uppercase">{inc['organization']}</div>
      <div style="font-size:22px;font-weight:600;margin-top:4px">حصن — Husn Incident Alert</div>
      <div style="font-size:13px;color:#9aa6b2;margin-top:4px">{inc['detected_at_iso']} · host <code style="color:#e6f1ff">{inc['host']}</code></div>
    </td></tr>
    <tr><td style="padding:24px 32px">
      <table width="100%" cellpadding="0" cellspacing="0" style="font-size:14px;line-height:1.6">
        <tr><td style="color:#9aa6b2;width:140px">Source IP</td><td><code style="color:#ff7b72;font-size:15px">{inc['source_ip']}</code></td></tr>
        <tr><td style="color:#9aa6b2">Attack Type</td><td><strong style="color:#e6f1ff">{inc['attack_type']}</strong></td></tr>
        <tr><td style="color:#9aa6b2">Severity</td><td><span style="display:inline-block;padding:2px 10px;border-radius:999px;background:{sev_color};color:#0a0e14;font-weight:600;font-size:12px">{inc['severity'].upper()}</span></td></tr>
        <tr><td style="color:#9aa6b2">AI Confidence</td><td>{inc['confidence']:.1%}</td></tr>
        <tr><td style="color:#9aa6b2">Target</td><td><code style="color:#e6f1ff">{inc['target']}</code></td></tr>
        <tr><td style="color:#9aa6b2;padding-top:12px" valign="top">Action Taken</td><td style="padding-top:12px;color:#48c774;font-weight:600">{inc['action']}</td></tr>
      </table>
    </td></tr>
    {chart_block}
    {_explanation_block_html(explanation)}
    <tr><td style="padding:20px 32px;border-top:1px solid #1f2a37;font-size:12px;color:#6b7785;line-height:1.5">
      Auto-generated by <strong style="color:#00ff9d">Husn (حصن)</strong> Intelligent Cyber Defense System.<br/>
      No human intervention was required to detect or contain this threat.
    </td></tr>
  </table>
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

    if not _should_send(incident.source_ip):
        result["throttled"] = True
        log.info("[report] throttled email for %s (within %ss window)",
                 incident.source_ip, config.get("notify.throttle_seconds", 60))
        return result

    subject = f"[Husn] {incident.severity.upper()} — {incident.attack_type} from {incident.source_ip}"
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
