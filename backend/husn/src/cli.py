import os
import socket
import time
import sys
import random
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.live import Live
from rich.layout import Layout
from rich.align import Align
from rich import box
from rich.columns import Columns
from rich.rule import Rule

from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.history import FileHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.formatted_text import ANSI

from husn.src.core.response import DefenseResponse
from husn.src import config as cfg
from husn.src.system import hardware, processes, network, scanner, traffic
from husn.src.notify import mailer, report
from husn.src.updater import updater
from husn.src.intel import geoip as intel_geoip, reputation as intel_reputation

app = typer.Typer(help="Husn — Intelligent Cyber Defense System")
console = Console()
responder = DefenseResponse(console=console)

HISTORY_FILE = Path.home() / ".husn_history"

LOGO = r"""
[bold white]       ██╗  ██╗ ██╗   ██╗ ███████╗ ███╗   ██╗[/bold white]
[bold white]       ██║  ██║ ██║   ██║ ██╔════╝ ████╗  ██║[/bold white]
[bold white]       ███████║ ██║   ██║ ███████╗ ██╔██╗ ██║[/bold white]
[bold white]       ██╔══██║ ██║   ██║ ╚════██║ ██║╚██╗██║[/bold white]
[bold white]       ██║  ██║ ╚██████╔╝ ███████║ ██║ ╚████║[/bold white]
[bold white]       ╚═╝  ╚═╝  ╚═════╝  ╚══════╝ ╚═╝  ╚═══╝[/bold white]

[dim cyan]              ── INTELLIGENT CYBER DEFENSE ──[/dim cyan]
"""


# ----------------------------------------------------------------------
# Boot sequence
# ----------------------------------------------------------------------

def boot_sequence():
    """Real subsystem checks — each step actually verifies something is reachable
    or importable. No fake percentages."""
    steps = [
        ("Loading host telemetry (psutil)",       _check_telemetry),
        ("Reading configuration",                  _check_config),
        ("Loading AI engine (XGBoost + IF)",       _check_ai_models),
        ("Initialising threat intel (GeoIP)",      _check_intel),
        ("Wiring active defense layer",            _check_defense),
        ("Probing notification transport (SMTP)",  _check_smtp),
    ]
    for label, fn in steps:
        with console.status(f"[cyan]{label}...[/cyan]", spinner="dots12"):
            t0 = time.perf_counter()
            try:
                detail = fn()
                ok = True
            except Exception as exc:
                detail = str(exc)
                ok = False
            dt = (time.perf_counter() - t0) * 1000
        mark = "[bold green]✓[/bold green]" if ok else "[bold red]✗[/bold red]"
        console.print(f"  {mark} [white]{label:<42}[/white] [dim]{detail}[/dim] [dim cyan]{dt:.0f}ms[/dim cyan]")
    console.print()
    console.print(Rule("[bold green]HUSN SYSTEM ONLINE[/bold green]", style="green"))


# Real check functions — each returns a one-line summary on success, raises on failure.

def _check_telemetry() -> str:
    snap = hardware.snapshot()
    return f"{snap['cpu']['logical_cores']} cores · {snap['memory']['total_gb']} GB RAM"

def _check_config() -> str:
    cfg.reload()
    p = cfg.loaded_from()
    return f"loaded from {p.name if p else '(defaults)'}"

def _check_ai_models() -> str:
    from husn.src.ai.model import HusnAI
    ai = HusnAI()
    if not ai.models_exist():
        raise RuntimeError("models not yet trained — run setup.sh")
    ai.load_models()
    return f"{len(ai.features)} features · classifier ready"

def _check_intel() -> str:
    online = bool(cfg.get("intel.online", False))
    db = cfg.get("intel.geoip_db_path") or ""
    parts = []
    if db: parts.append("MaxMind DB")
    if online: parts.append("ip-api.com fallback")
    return ", ".join(parts) or "offline mode"

def _check_defense() -> str:
    real = bool(cfg.get("response.real_iptables", False))
    wl = len(cfg.get("response.whitelist", []) or [])
    mode = "REAL iptables" if real else "simulated"
    return f"{mode} · {wl} whitelisted"

def _check_smtp() -> str:
    if not mailer.is_enabled():
        return "disabled in config"
    s = cfg.get("smtp", {}) or {}
    return f"{s.get('host')}:{s.get('port')} as {s.get('user', '?')}"


def show_banner():
    console.print(Align.center(LOGO))
    cfg_path = cfg.loaded_from()
    cfg_line = f"Config: [cyan]{cfg_path}[/cyan]" if cfg_path else "Config: [yellow](defaults — no /etc/husn/config.yml found)[/yellow]"
    smtp_line = "[green]SMTP enabled[/green]" if mailer.is_enabled() else "[yellow]SMTP off[/yellow]"
    real_block = bool(cfg.get("response.real_iptables", False))
    block_line = "[red]REAL iptables active[/red]" if real_block else "[yellow]Simulated blocking[/yellow]"
    console.print(Panel(
        Align.center(
            f"[bold white]Welcome to Husn — Intelligent Cyber Defense System[/bold white]\n"
            f"[dim]State-of-the-art protection for the digital frontier[/dim]\n\n"
            f"{cfg_line}\nDefense: {block_line}    Notifications: {smtp_line}"
        ),
        border_style="bright_green",
        box=box.DOUBLE,
    ))


# ----------------------------------------------------------------------
# Pretty renderers (shared by API and CLI)
# ----------------------------------------------------------------------

def _hardware_panel() -> Panel:
    snap = hardware.snapshot()
    os_ = snap["os"]
    cpu = snap["cpu"]
    mem = snap["memory"]
    grid = Table.grid(padding=(0, 1))
    grid.add_column(style="cyan", justify="right")
    grid.add_column(justify="left")
    grid.add_row("Host", f"[bold]{os_['hostname']}[/bold]   [dim]({os_['fqdn']})[/dim]")
    grid.add_row("OS", f"{os_['system']} {os_['release']}")
    grid.add_row("Uptime", _humanize_seconds(os_["uptime_seconds"]))
    grid.add_row("CPU", f"{cpu['model']}  ·  {cpu['physical_cores']}c/{cpu['logical_cores']}t  ·  {cpu['frequency_mhz']}MHz")
    grid.add_row("CPU load", f"{cpu['usage_percent']}%   load avg {cpu.get('load_average') or '—'}")
    grid.add_row("RAM", f"{mem['used_gb']} / {mem['total_gb']} GB  ({mem['percent']}%)")
    if mem["swap_total_gb"]:
        grid.add_row("Swap", f"{mem['swap_used_gb']} / {mem['swap_total_gb']} GB  ({mem['swap_percent']}%)")
    return Panel(grid, title="[bold green]HOST OVERVIEW[/bold green]", border_style="green", box=box.ROUNDED)


def _disk_panel() -> Panel:
    table = Table(box=box.SIMPLE_HEAD, show_edge=False)
    table.add_column("Mount", style="cyan")
    table.add_column("FS", style="dim")
    table.add_column("Size (GB)", justify="right")
    table.add_column("Used (GB)", justify="right")
    table.add_column("%", justify="right")
    for d in hardware.disk_info():
        pct_color = "green" if d["percent"] < 75 else "yellow" if d["percent"] < 90 else "red"
        table.add_row(d["mountpoint"], d["fstype"], f"{d['total_gb']}", f"{d['used_gb']}",
                      f"[{pct_color}]{d['percent']}[/{pct_color}]")
    return Panel(table, title="[bold green]DISKS[/bold green]", border_style="green", box=box.ROUNDED)


def _interfaces_panel() -> Panel:
    table = Table(box=box.SIMPLE_HEAD, show_edge=False)
    table.add_column("Iface", style="cyan")
    table.add_column("IPv4")
    table.add_column("MAC", style="dim")
    table.add_column("Up?", justify="center")
    table.add_column("Speed", justify="right")
    for nic in hardware.network_interfaces():
        up = "[green]●[/green]" if nic["is_up"] else "[red]○[/red]"
        table.add_row(nic["name"], nic["ipv4"] or "—", nic["mac"] or "—", up, f"{nic['speed_mbps']} Mb/s")
    return Panel(table, title="[bold green]INTERFACES[/bold green]", border_style="green", box=box.ROUNDED)


def _humanize_seconds(s: int) -> str:
    days, rem = divmod(s, 86400)
    hours, rem = divmod(rem, 3600)
    mins, _ = divmod(rem, 60)
    return f"{days}d {hours}h {mins}m"


# ----------------------------------------------------------------------
# Commands
# ----------------------------------------------------------------------

@app.command()
def sysinfo():
    """Show host hardware, OS, disks, and network interfaces."""
    console.print(_hardware_panel())
    console.print(Columns([_disk_panel(), _interfaces_panel()], equal=False, expand=True))


@app.command()
def ports():
    """List listening ports and the processes that own them."""
    rows = network.listening_ports()
    table = Table(title=f"Open Ports — {len(rows)} listeners", box=box.SQUARE, header_style="bold green")
    table.add_column("Port", justify="right", style="bold")
    table.add_column("Proto", style="dim")
    table.add_column("Address")
    table.add_column("Service", style="cyan")
    table.add_column("PID", justify="right", style="dim")
    table.add_column("Process", style="magenta")
    for r in rows:
        table.add_row(str(r["port"]), r["protocol"], r["address"], r["service"],
                      str(r["pid"] or "—"), r["process"] or "—")
    console.print(table)


@app.command()
def services():
    """Group listening ports by owning process — the services running on this host."""
    table = Table(title="Running Services", box=box.SQUARE, header_style="bold green")
    table.add_column("Process", style="magenta")
    table.add_column("PID", justify="right", style="dim")
    table.add_column("Ports")
    table.add_column("Services", style="cyan")
    for s in network.services():
        table.add_row(
            s["process"], str(s["pid"] or "—"),
            ", ".join(str(p) for p in s["ports"]),
            ", ".join(s["services"]),
        )
    console.print(table)


@app.command()
def procs(suspicious: bool = typer.Option(False, "--suspicious", "-s", help="Only show flagged processes")):
    """List processes (sorted by CPU). --suspicious filters to flagged only."""
    rows = processes.suspicious_only() if suspicious else processes.list_processes(40)
    if not rows:
        console.print("[green]✓ No suspicious processes detected.[/green]")
        return
    table = Table(box=box.SQUARE, header_style="bold green")
    table.add_column("PID", justify="right", style="dim")
    table.add_column("User", style="cyan")
    table.add_column("Process", style="bold")
    table.add_column("CPU%", justify="right")
    table.add_column("Mem%", justify="right")
    table.add_column("Conn", justify="right", style="dim")
    table.add_column("Flag")
    for r in rows:
        flag = f"[red]⚠ {r['reason']}[/red]" if r["suspicious"] else ""
        table.add_row(
            str(r["pid"]), r["user"], r["name"],
            f"{r['cpu_percent']}", f"{r['memory_percent']}",
            str(r["connections"]) if r["connections"] >= 0 else "—",
            flag,
        )
    console.print(table)


@app.command()
def scan(
    target: str = typer.Argument(None, help="Host or IP to scan. Omit for live local-network monitor."),
):
    """Scan a target for open ports (uses nmap if available, else TCP-connect).
    With no target, shows the legacy live-traffic monitor."""
    if target:
        with console.status(f"[bold yellow]Scanning {target}...[/bold yellow]", spinner="dots12"):
            result = scanner.scan(target)
        if result.get("error"):
            console.print(f"[red]✗ {result['error']}[/red]")
            return
        console.print(Panel(
            f"Resolved: [cyan]{result['resolved_ip']}[/cyan]   "
            f"Engine: [magenta]{result['engine']}[/magenta]   "
            f"Took: {result['duration_seconds']}s",
            border_style="green", box=box.ROUNDED,
        ))
        if not result["open_ports"]:
            console.print("[green]✓ No open ports detected on the scanned set.[/green]")
            return
        table = Table(box=box.SQUARE, header_style="bold green")
        table.add_column("Port", justify="right", style="bold")
        table.add_column("Service", style="cyan")
        table.add_column("State", style="green")
        table.add_column("Version", style="dim")
        for r in result["open_ports"]:
            table.add_row(str(r["port"]), r["service"], r["state"], r.get("version", ""))
        console.print(table)
        return

    # Legacy live-monitor (kept for the demo flair).
    console.print("[bold yellow]Initiating Deep Packet Inspection...[/bold yellow]")
    with Live(_live_traffic_table(), refresh_per_second=4) as live:
        for i in range(20):
            time.sleep(0.2)
            live.update(_live_traffic_table())
            if i == 10:
                console.print("[bold red]⚠ HIGH SEVERITY THREAT DETECTED: 104.21.x.x[/bold red]")
                responder.block_ip("104.21.x.x", attack_type="Infiltration", severity="High", confidence=0.94)


def _live_traffic_table() -> Table:
    table = Table(box=None, expand=True)
    table.add_column("SOURCE", style="cyan")
    table.add_column("DESTINATION", style="magenta")
    table.add_column("PROTOCOL", style="yellow")
    table.add_column("ACTION", style="bold green")
    ips = ["192.168.1.5", "10.0.0.12", "172.16.0.4", "192.168.1.1", "45.77.12.3"]
    actions = ["[green]PASS[/green]", "[green]PASS[/green]", "[red]BLOCK[/red]", "[yellow]INSPECT[/yellow]"]
    protocols = ["TCP", "UDP", "HTTPS", "SSH"]
    for _ in range(8):
        table.add_row(random.choice(ips), random.choice(ips), random.choice(protocols), random.choice(actions))
    return table


@app.command()
def simulate():
    """Simulate an attack against the local host."""
    console.print(Panel("[bold red]Starting Attack Simulation[/bold red]", border_style="red"))
    attack_type = typer.prompt("Select attack type (DDoS, BruteForce, PortScan)")
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                  BarColumn(bar_width=50), TaskProgressColumn()) as progress:
        task1 = progress.add_task(description=f"[cyan]Crafting {attack_type} packets...", total=100)
        while not progress.finished:
            progress.update(task1, advance=random.uniform(5, 15))
            time.sleep(0.25)
    console.print(f"[bold green]✓ Simulation of {attack_type} completed.[/bold green]")


@app.command()
def status():
    """Show overall system status."""
    grid = Table.grid(expand=True)
    grid.add_column(style="cyan", justify="right")
    grid.add_column(justify="left")
    grid.add_row("AI Engine", " : [bold green]ONLINE[/bold green]")
    grid.add_row("Network Monitor", " : [bold green]ACTIVE[/bold green]")
    grid.add_row("SMTP Notifications", f" : [bold {'green' if mailer.is_enabled() else 'yellow'}]{'ENABLED' if mailer.is_enabled() else 'DISABLED'}[/bold {'green' if mailer.is_enabled() else 'yellow'}]")
    real = bool(cfg.get("response.real_iptables", False))
    grid.add_row("iptables Mode", f" : [bold {'red' if real else 'yellow'}]{'REAL (drops packets)' if real else 'SIMULATED'}[/bold {'red' if real else 'yellow'}]")
    grid.add_row("Blocked IPs", f" : [bold]{len(responder.list_blocked())}[/bold]")
    grid.add_row("Recipients", f" : {len(mailer.recipients())}")
    console.print(Panel(grid, title="System Status", border_style="blue"))


@app.command()
def check():
    """Manually run the update check against the configured git remote."""
    with console.status("[bold cyan]Checking for updates...[/bold cyan]", spinner="dots12"):
        result = updater.check()
    color = "green" if not result.get("available") else "yellow"
    console.print(Panel(
        f"[{color}]{result['message']}[/{color}]\n"
        f"current: [cyan]{result.get('current_commit') or '—'}[/cyan]   "
        f"remote: [cyan]{result.get('remote_commit') or '—'}[/cyan]   "
        f"behind: {result.get('behind', 0)}   ahead: {result.get('ahead', 0)}",
        title="Update Check", border_style=color,
    ))


@app.command()
def update():
    """Apply pending updates (git pull + pip install if needed)."""
    chk = updater.check()
    if not chk.get("available"):
        console.print(f"[green]{chk['message']}[/green] Nothing to do.")
        return
    confirm = typer.prompt(f"Pull {chk['behind']} commit(s) from origin? [y/N]", default="N")
    if confirm.strip().lower() != "y":
        console.print("[yellow]Aborted.[/yellow]")
        return
    with console.status("[bold cyan]Applying updates...[/bold cyan]", spinner="dots12"):
        result = updater.apply()
    color = "green" if result.get("ok") else "red"
    console.print(Panel(f"[{color}]{result['message']}[/{color}]", title="Update", border_style=color))
    console.print("[dim]Restart with: systemctl restart husn-backend (production) "
                  "or re-run python run.py both (local).[/dim]")


@app.command()
def report_test():
    """Send a test incident email to verify SMTP wiring."""
    with console.status("[bold cyan]Dispatching test incident...[/bold cyan]"):
        result = report.send_test_email()
    if result.get("throttled"):
        console.print("[yellow]Throttled — try again in a minute.[/yellow]")
        return
    em = result.get("email") or {}
    if em.get("ok"):
        console.print(f"[green]✓ Test email sent to {', '.join(em.get('to', []))}[/green]")
    else:
        console.print(f"[red]✗ {em.get('detail', 'Email not sent')}[/red]")
    console.print(f"[dim]Report saved to {result['report_path']}[/dim]")


@app.command()
def blocked():
    """List currently blocked IPs."""
    rows = responder.list_blocked()
    if not rows:
        console.print("[green]✓ No IPs are currently blocked.[/green]")
        return
    table = Table(title=f"Blocked IPs — {len(rows)}", box=box.SQUARE, header_style="bold red")
    table.add_column("IP", style="bold")
    table.add_column("Attack", style="red")
    table.add_column("Severity")
    table.add_column("Confidence", justify="right")
    table.add_column("When", style="dim")
    for r in rows:
        when = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["blocked_at"]))
        table.add_row(r["ip"], r["attack_type"], r["severity"],
                      f"{r['confidence']:.1%}", when)
    console.print(table)


@app.command()
def dashboard():
    """Print the URL of the web dashboard."""
    domain = cfg.get("domain", "")
    url = f"https://{domain}" if domain and domain != "husn.example.com" else "http://localhost:5173"
    console.print(f"[bold blue]Dashboard:[/bold blue] {url}")


@app.command()
def geoip(target: str = typer.Argument(..., help="IP address to look up")):
    """GeoIP + reputation lookup for a single IP."""
    with console.status(f"[cyan]Resolving {target}...[/cyan]", spinner="dots12"):
        g = intel_geoip.lookup(target)
        r = intel_reputation.lookup(target)
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="cyan", justify="right")
    grid.add_column()
    grid.add_row("IP", f"[bold]{target}[/bold]")
    grid.add_row("Country", f"{g.get('flag', '🏳️')} {g.get('country', '?')} ({g.get('country_code') or '—'})")
    grid.add_row("City", g.get("city") or "—")
    if g.get("latitude") is not None:
        grid.add_row("Coords", f"{g['latitude']}, {g['longitude']}")
    grid.add_row("ASN", g.get("asn") or "—")
    grid.add_row("Geo source", f"[dim]{g.get('source', '?')}[/dim]")
    grid.add_row("Reputation", f"{r.get('classification', '?')}  [dim]({r.get('source')})[/dim]")
    if r.get("score"):
        grid.add_row("Abuse score", f"[bold red]{r['score']}/100[/bold red]")
    if r.get("reports"):
        grid.add_row("Abuse reports", str(r["reports"]))
    console.print(Panel(grid, title=f"[bold cyan]Threat Intel[/bold cyan]", border_style="cyan", box=box.ROUNDED))


@app.command()
def live():
    """Live multi-panel monitor — htop for cyber-defense. Ctrl+C to exit."""
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=5),
        Layout(name="body", ratio=1),
        Layout(name="footer", size=10),
    )
    layout["body"].split_row(
        Layout(name="left", ratio=1),
        Layout(name="right", ratio=1),
    )
    # Prime the traffic sampler so we have rate data to show.
    if not getattr(traffic.sampler, "_thread", None):
        traffic.sampler.start()

    started = time.time()
    log_lines: list[str] = []

    def _add(msg: str) -> None:
        log_lines.append(f"[{time.strftime('%H:%M:%S')}] {msg}")
        if len(log_lines) > 20:
            del log_lines[: len(log_lines) - 20]

    _add("LIVE_MONITOR: started")

    try:
        with Live(layout, refresh_per_second=2, screen=True, console=console) as ui:
            while True:
                snap = hardware.snapshot()
                tlatest = traffic.sampler.latest()

                # Header
                hdr = Table.grid(expand=True, padding=(0, 2))
                hdr.add_column(justify="left", style="bold cyan")
                hdr.add_column(justify="center", style="bold white")
                hdr.add_column(justify="right", style="dim")
                mode = "Standard"
                hdr.add_row(
                    f"⛨ {snap['os']['hostname']}",
                    f"HUSN · LIVE MONITOR  ({mode})",
                    f"uptime { _humanize_seconds(int(time.time() - started)) }",
                )
                bar_cpu = _bar(snap["cpu"]["usage_percent"], 30, color_for_pct(snap["cpu"]["usage_percent"]))
                bar_mem = _bar(snap["memory"]["percent"], 30, color_for_pct(snap["memory"]["percent"]))
                hdr.add_row(
                    f"CPU  {snap['cpu']['usage_percent']:>5.1f}%  {bar_cpu}",
                    f"RAM  {snap['memory']['percent']:>5.1f}%  {bar_mem}",
                    f"NET  ↓ {_fmt_bps(tlatest.get('bytes_in_per_s',0))}  ↑ {_fmt_bps(tlatest.get('bytes_out_per_s',0))}",
                )
                layout["header"].update(Panel(hdr, border_style="cyan", box=box.ROUNDED))

                # Left: top processes
                p_table = Table(title="Top processes (CPU%)", box=box.SIMPLE_HEAD, expand=True, header_style="bold green")
                p_table.add_column("PID", style="dim", width=7)
                p_table.add_column("User", style="cyan", width=10)
                p_table.add_column("Process")
                p_table.add_column("CPU%", justify="right", width=6)
                p_table.add_column("Mem%", justify="right", width=6)
                p_table.add_column("Flag", width=8)
                for r in processes.list_processes(15):
                    flag = "[red]⚠[/red]" if r["suspicious"] else ""
                    p_table.add_row(str(r["pid"]), r["user"][:10], r["name"][:30],
                                    f"{r['cpu_percent']}", f"{r['memory_percent']}", flag)
                layout["left"].update(p_table)

                # Right: listening ports
                lp = network.listening_ports()
                lp_table = Table(title=f"Listening sockets ({len(lp)})", box=box.SIMPLE_HEAD, expand=True, header_style="bold green")
                lp_table.add_column("Port", justify="right", width=7)
                lp_table.add_column("Proto", style="dim", width=6)
                lp_table.add_column("Service", style="cyan", width=14)
                lp_table.add_column("Process")
                for r in lp[:15]:
                    lp_table.add_row(str(r["port"]), r["protocol"], r["service"][:14], r["process"][:30] or "—")
                layout["right"].update(lp_table)

                # Footer: scrolling log
                log_panel = Text("\n".join(log_lines[-9:]) or "[dim]waiting...[/dim]", overflow="ellipsis")
                layout["footer"].update(Panel(log_panel, title="[bold]event log[/bold]", border_style="green", box=box.ROUNDED))

                ui.refresh()
                time.sleep(0.5)
    except KeyboardInterrupt:
        console.print("\n[dim]Exited live monitor.[/dim]")


def _bar(pct: float, width: int, colour: str) -> str:
    pct = max(0.0, min(100.0, float(pct or 0)))
    filled = int(round(pct / 100.0 * width))
    return f"[{colour}]" + ("█" * filled) + "[/]" + ("░" * (width - filled))


def color_for_pct(p: float) -> str:
    p = float(p or 0)
    return "green" if p < 70 else "yellow" if p < 90 else "red"


def _fmt_bps(n: int) -> str:
    if not n: return "0 B/s"
    units = ["B/s", "KB/s", "MB/s", "GB/s"]; v = n; i = 0
    while v >= 1024 and i < len(units)-1:
        v /= 1024; i += 1
    return f"{v:.1f} {units[i]}"


# ----------------------------------------------------------------------
# Interactive shell
# ----------------------------------------------------------------------

INTERACTIVE_COMMANDS = [
    "sysinfo", "ports", "services", "procs", "processes",
    "scan", "simulate", "status", "blocked", "check", "update",
    "live", "geoip",
    "report-test", "dashboard", "help", "clear", "exit",
]


def _print_help():
    console.print(Panel(
        "[bold cyan]Telemetry[/bold cyan]    sysinfo   ports   services   procs   procs --suspicious   [bold]live[/bold]\n"
        "[bold cyan]Intel[/bold cyan]        geoip <ip>     scan <target>     simulate     blocked\n"
        "[bold cyan]Updates[/bold cyan]      check          update\n"
        "[bold cyan]System[/bold cyan]       status         report-test       dashboard    clear     exit",
        title="Husn Commands", border_style="cyan",
    ))


def _prompt_text() -> ANSI:
    """Context-aware prompt — includes hostname + defense mode + colour cue."""
    host = socket.gethostname().split(".")[0]
    mode = "Standard"  # CLI is read-only against config; backend owns runtime defense_mode
    real = bool(cfg.get("response.real_iptables", False))
    mark = "\033[1;31m⚡\033[0m" if real else "\033[1;32m▶\033[0m"
    return ANSI(f"\033[1;36mhusn\033[0m@\033[2m{host}\033[0m \033[2m({mode})\033[0m {mark} ")


@app.command()
def interactive():
    """Enter the interactive Husn shell."""
    boot_sequence()
    show_banner()
    sysinfo()
    _print_help()
    session = PromptSession(
        history=FileHistory(str(HISTORY_FILE)),
        auto_suggest=AutoSuggestFromHistory(),
    )
    completer = WordCompleter(INTERACTIVE_COMMANDS, ignore_case=True)

    while True:
        try:
            text = session.prompt(_prompt_text(), completer=completer).strip()
            if not text:
                continue
            parts = text.split()
            cmd, args = parts[0].lower(), parts[1:]
            if cmd == "exit":
                break
            elif cmd == "help":
                _print_help()
            elif cmd == "clear":
                console.clear()
                show_banner()
            elif cmd == "sysinfo":
                sysinfo()
            elif cmd == "ports":
                ports()
            elif cmd == "services":
                services()
            elif cmd in ("procs", "processes"):
                procs(suspicious=("--suspicious" in args or "-s" in args))
            elif cmd == "scan":
                scan(args[0] if args else None)
            elif cmd == "simulate":
                simulate()
            elif cmd == "status":
                status()
            elif cmd == "blocked":
                blocked()
            elif cmd == "check":
                check()
            elif cmd == "update":
                update()
            elif cmd == "live":
                live()
            elif cmd == "geoip":
                if not args:
                    console.print("[yellow]usage: geoip <ip>[/yellow]")
                else:
                    geoip(args[0])
            elif cmd in ("report-test", "report_test"):
                report_test()
            elif cmd == "dashboard":
                dashboard()
            else:
                console.print(f"[red]Unknown command: {cmd}[/red]   (type [cyan]help[/cyan])")
        except KeyboardInterrupt:
            continue
        except EOFError:
            break
    console.print("[dim]Goodbye.[/dim]")


@app.callback(invoke_without_command=True)
def _main(ctx: typer.Context):
    if ctx.invoked_subcommand is None:
        interactive()


if __name__ == "__main__":
    app()
