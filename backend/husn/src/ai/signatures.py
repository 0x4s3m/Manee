"""
Payload-signature scanner — second detection layer.

The flow-statistics XGBoost catches *behavioural* anomalies (DDoS shape,
port-scan distributions, brute-force timing). It cannot see what's
actually inside an HTTP body — so a single curl that uploads
`/etc/passwd` looks identical, statistically, to one that uploads a
selfie.

This module fills that gap with rule-based detection on the first
payload bytes captured per flow. A match upgrades the AI's verdict
deterministically: anomaly=True, label=signature attack_type,
confidence>=signature confidence. The combined defence catches both
feature-anomalous attacks (DDoS / scans the AI is good at) and
content-anomalous attacks (RCE / SQLi / log4shell the rules are good at).

All patterns are compiled once at module load. The scan is O(n_patterns)
per payload — with ~25 patterns that's microseconds even on slow VMs.
"""

from __future__ import annotations
import re
from typing import Optional, TypedDict


class SigMatch(TypedDict):
    pattern_name: str
    attack_type: str
    severity: str
    confidence: float


# Each tuple: (regex source, pattern_name, attack_type, severity, confidence)
# attack_type values must match HusnAI's training labels:
#   BENIGN / DDoS / PortScan / Brute Force / Infiltration / Web Attack
#
# Severity values match notify/report.py:
#   Critical / High / Medium / Low
_RAW: list[tuple[str, str, str, str, float]] = [

    # ───────────── SQL Injection ─────────────
    (r"(?i)(\bUNION\b\s*(ALL\s+)?\bSELECT\b|\bOR\b\s+\d+\s*=\s*\d+|'\s*OR\s*'\d+'\s*=\s*'\d+|\bSLEEP\s*\(|\bBENCHMARK\s*\(|';\s*--|';\s*#)",
     "sqli_classic", "Web Attack", "High", 0.94),
    (r"(?i)(\bDROP\b\s+TABLE\b|\bINSERT\b\s+INTO\b|\bUPDATE\b\s+\w+\s+SET\b)",
     "sqli_destructive", "Web Attack", "Critical", 0.98),
    (r"(?i)(\bxp_cmdshell\b|\bsp_executesql\b|EXEC\s*\(\s*master\.\.)",
     "sqli_mssql_cmd", "Web Attack", "Critical", 0.98),
    (r"(?i)(\bload_file\s*\(|\binto\s+outfile\b|\binto\s+dumpfile\b)",
     "sqli_file", "Web Attack", "Critical", 0.97),

    # ───────────── XSS ─────────────
    (r"(?i)(<script[^>]*>|</script>|javascript\s*:[^/]|onerror\s*=|onload\s*=|onmouseover\s*=|<iframe\b|<img[^>]*src\s*=\s*['\"]?\s*javascript:)",
     "xss_reflected", "Web Attack", "High", 0.92),
    (r"(?i)(document\.cookie|window\.location|<svg[^>]*onload)",
     "xss_dom", "Web Attack", "High", 0.90),

    # ───────────── Command / Code injection ─────────────
    (r"(?i)([;&|`]\s*(cat|ls|whoami|id|uname|hostname|wget|curl|nc|ncat|bash|sh|zsh|python|perl|ruby|php)\b|\|\s*nc\s+-)",
     "cmd_injection", "Web Attack", "Critical", 0.96),
    (r"(?i)(\$\(\s*(cat|ls|wget|curl|whoami|id)\b|`\s*(cat|ls|wget|curl)\b)",
     "cmd_substitution", "Web Attack", "Critical", 0.96),

    # ───────────── Reverse / bind shells ─────────────
    (r"(?i)(bash\s+-i\b|/dev/tcp/|/dev/udp/|nc\s+-e\s|ncat\s+-e\s|python\s+-c\s+['\"]?\s*import\s+(socket|pty)|mkfifo\s+/tmp/)",
     "reverse_shell", "Infiltration", "Critical", 0.99),

    # ───────────── Path traversal ─────────────
    (r"(\.\./){2,}|(\.\.\\){2,}|%2e%2e%2f|%252e%252e%252f|\.\.%2f|\.\.%5c",
     "path_traversal", "Web Attack", "High", 0.93),
    (r"(?i)(/etc/passwd|/etc/shadow|/proc/self/environ|\\windows\\system32\\drivers\\etc\\hosts)",
     "sensitive_file_read", "Web Attack", "High", 0.94),

    # ───────────── File inclusion (LFI/RFI) ─────────────
    (r"(?i)(\?(file|page|inc|path|template|view)=(https?:|ftp:|php:|file:|data:|expect:))",
     "file_inclusion", "Web Attack", "High", 0.91),

    # ───────────── SSRF probes ─────────────
    (r"(?i)(https?://(127\.0\.0\.1|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|169\.254\.169\.254)|file:///|gopher://|dict://)",
     "ssrf_probe", "Web Attack", "High", 0.90),

    # ───────────── XXE / XML attacks ─────────────
    (r"(?i)<!ENTITY\s+\w+\s+SYSTEM",
     "xxe_external_entity", "Web Attack", "High", 0.93),

    # ───────────── Log4Shell / JNDI injection ─────────────
    (r"\$\{(jndi|env|ctx|sys|java|date|lower|upper|::-?j|\${)",
     "log4shell_jndi", "Infiltration", "Critical", 0.99),

    # ───────────── Spring4Shell / template injection ─────────────
    (r"(?i)(class\.module\.classLoader|\$\{[^}]*runtime\.exec|<#assign.*runtime|\{\{.*system\.exec)",
     "template_injection", "Infiltration", "Critical", 0.97),

    # ───────────── Common scanner fingerprints (User-Agent or path) ─────────────
    (r"(?i)\b(nmap|nikto|sqlmap|dirbuster|gobuster|wpscan|hydra|metasploit|havij|acunetix|nuclei|jaeles|wfuzz|ffuf|nessus|openvas|whatweb|masscan|zmap)\b",
     "scanner_fingerprint", "PortScan", "Medium", 0.88),

    # ───────────── Sensitive-path probing ─────────────
    (r"(?i)(/\.env\b|/\.git/|/\.svn/|/\.aws/credentials|/\.ssh/id_rsa|/wp-admin|/wp-config\.php|/phpmyadmin|/admin\.php|/console|/actuator(/env|/heapdump|/jolokia)?|/server-status\b|/cgi-bin/luci)",
     "sensitive_path", "PortScan", "Medium", 0.84),

    # ───────────── Webshells & uploads ─────────────
    (r"(?i)(<\?php\s+system|<\?=|eval\s*\(\s*\$_(GET|POST|REQUEST)|cmd\.jsp\?cmd=|cmd\.aspx\?cmd=|c99shell|r57shell|b374k)",
     "webshell", "Infiltration", "Critical", 0.98),

    # ───────────── Brute-force credential probes ─────────────
    (r"(?i)(password|passwd|pwd)=(123456|123456789|qwerty(123)?|admin(123)?|password|password1|letmein|welcome|root|toor|p@ssw0rd|monkey|husn|test|guest)\b",
     "weak_credentials", "Brute Force", "High", 0.90),
    (r"(?i)(username|user|email|login)=(admin|administrator|root|test|guest|sa|operator|husn)\b.*(password|pwd)=",
     "default_credentials", "Brute Force", "High", 0.88),

    # ───────────── HTTP request smuggling ─────────────
    (r"(?i)transfer-encoding:\s*chunked[\r\n]+content-length",
     "http_smuggle", "Web Attack", "Medium", 0.85),

    # ───────────── NoSQL injection ─────────────
    (r"(?i)(\$ne\s*:|\$gt\s*:|\$where\s*:|\$regex\s*:|\$exists\s*:)",
     "nosql_injection", "Web Attack", "High", 0.89),

    # ───────────── LDAP injection ─────────────
    (r"\(\s*\|\s*\(\s*\w+=\*|\(\s*&\s*\(\s*\w+=\*|\)\s*\(\s*\|\s*\(",
     "ldap_injection", "Web Attack", "Medium", 0.83),

    # ───────────── Living-off-the-land binaries (LOLBins) ─────────────
    (r"(?i)(powershell\s+-(e|en|enc|encod|encode|encoded|encodedcommand)\b|certutil\s+-(decode|urlcache|f|f\s+-)|bitsadmin\s+/transfer|mshta\s+http|regsvr32\s+/s\s+/u\s+/i:http)",
     "lolbin_abuse", "Infiltration", "Critical", 0.97),

    # ───────────── Server-side template injection ─────────────
    (r"\{\{\s*[\d\w]+\s*[+*/-]\s*[\d\w]+\s*\}\}|\{%.*\bimport\b|\$\{T\(.*\)\.|<%\s*=?\s*Runtime",
     "ssti", "Web Attack", "High", 0.90),
]

_COMPILED: list[tuple[re.Pattern, str, str, str, float]] = [
    (re.compile(p), n, a, s, c) for (p, n, a, s, c) in _RAW
]


def scan(payload: str | bytes | None) -> Optional[SigMatch]:
    """Return the first signature match, or None.

    Order matters — more-specific / higher-impact patterns sit earlier so
    they win when overlap exists (e.g. log4shell beats generic XSS).
    """
    if not payload:
        return None
    if isinstance(payload, bytes):
        try:
            payload = payload.decode("latin-1", errors="replace")
        except Exception:
            return None
    for regex, name, atk, sev, conf in _COMPILED:
        if regex.search(payload):
            return SigMatch(
                pattern_name=name,
                attack_type=atk,
                severity=sev,
                confidence=conf,
            )
    return None


def all_patterns() -> list[dict]:
    """Inventory of patterns — useful for the docs / dashboard 'rules' tab."""
    return [
        {"pattern_name": n, "attack_type": a, "severity": s, "confidence": c}
        for (_, n, a, s, c) in _COMPILED
    ]


def count() -> int:
    return len(_COMPILED)
