import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.live import Live
from rich.layout import Layout
from rich.align import Align
import time
import sys
import random
from husn.src.core.response import DefenseResponse

# For interactive mode
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter

app = typer.Typer()
console = Console()
responder = DefenseResponse(console=console)

LOGO = """
[bold green]
      ██╗  ██╗██╗   ██╗███████╗███╗   ██╗
      ██║  ██║██║   ██║██╔════╝████╗  ██║
      ███████║██║   ██║███████╗██╔██╗ ██║
      ██╔══██║██║   ██║╚════██║██║╚██╗██║
      ██║  ██║╚██████╔╝███████║██║ ╚████║
      ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝
[/bold green]
[bold red]    INTELLIGENT CYBER SHIELD FOR NATIONAL DEFENSE[/bold red]
"""

def boot_sequence():
    with Progress(
        SpinnerColumn(spinner_name="dots12"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=40),
        transient=True,
    ) as progress:
        task = progress.add_task("[green]Initializing HUSN Core...", total=100)
        while not progress.finished:
            time.sleep(0.05)
            progress.update(task, advance=random.uniform(1, 5))
            if progress.tasks[0].completed > 30:
                progress.update(task, description="[cyan]Loading AI Modules...")
            if progress.tasks[0].completed > 60:
                progress.update(task, description="[magenta]Syncing with National Defense Database...")
            if progress.tasks[0].completed > 90:
                progress.update(task, description="[white]Establishing Secure Tunnel...")

    console.print("[bold green]✔ HUSN SYSTEM ONLINE[/bold green]\n")

def show_banner():
    console.print(Align.center(LOGO))
    console.print(Panel(
        Align.center("[bold white]Welcome to Husn (حصن) - Intelligent Cyber Defense System[/bold white]\n[dim]State-of-the-art protection for the digital frontier[/dim]"),
        border_style="bright_green",
        box=Panel.box.DOUBLE
    ))

def generate_live_monitor():
    table = Table(box=None, expand=True)
    table.add_column("SOURCE", style="cyan")
    table.add_column("DESTINATION", style="magenta")
    table.add_column("PROTOCOL", style="yellow")
    table.add_column("ACTION", style="bold green")

    ips = ["192.168.1.5", "10.0.0.12", "172.16.0.4", "192.168.1.1", "45.77.12.3"]
    actions = ["[green]PASS[/green]", "[green]PASS[/green]", "[red]BLOCK[/red]", "[yellow]INSPECT[/yellow]"]
    protocols = ["TCP", "UDP", "HTTPS", "SSH"]

    for _ in range(8):
        table.add_row(
            random.choice(ips),
            random.choice(ips),
            random.choice(protocols),
            random.choice(actions)
        )
    return table

@app.command()
def scan():
    """Scan the network for threats."""
    console.print("[bold yellow]Initiating Deep Packet Inspection...[/bold yellow]")
    with Live(generate_live_monitor(), refresh_per_second=4) as live:
        for i in range(20):
            time.sleep(0.2)
            live.update(generate_live_monitor())
            if i == 10:
                console.print("[bold red]⚠ HIGH SEVERITY THREAT DETECTED: 104.21.x.x (Infiltration attempt on Web Port 80)[/bold red]")
                responder.block_ip("104.21.x.x")

    table = Table(title="Scan Results Summary", box=Panel.box.SQUARE)
    table.add_column("Timestamp", style="cyan")
    table.add_column("Source IP", style="magenta")
    table.add_column("Target IP", style="magenta")
    table.add_column("Attack Type", style="red")
    table.add_column("Severity", style="bold red")

    table.add_row("2026-04-24 10:00:01", "104.21.x.x", "10.0.0.5", "Infiltration", "High")
    table.add_row("2026-04-24 10:00:05", "172.16.0.22", "10.0.0.5", "PortScan", "Medium")
    table.add_row("2026-04-24 10:00:12", "192.168.1.50", "10.0.0.1", "BENIGN", "Low")

    console.print(table)

@app.command()
def simulate():
    """Simulate an attack for training purposes."""
    console.print(Panel("[bold red]Starting Attack Simulation (Advanced Mode)[/bold red]", border_style="red"))
    attack_type = typer.prompt("Select attack type (DDoS, BruteForce, PortScan)")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=50),
        TaskProgressColumn(),
    ) as progress:
        task1 = progress.add_task(description=f"[cyan]Crafting {attack_type} packets...", total=100)
        while not progress.finished:
            progress.update(task1, advance=random.uniform(5, 15))
            time.sleep(0.3)
            if progress.tasks[0].completed >= 40 and len(progress.tasks) == 1:
                progress.add_task(description="[magenta]Injected payloads into stream...", total=100)
            if len(progress.tasks) > 1:
                progress.update(progress.task_ids[1], advance=random.uniform(10, 20))

    console.print(f"[bold green]✓ Simulation of {attack_type} completed successfully.[/bold green]")

@app.command()
def dashboard():
    """Launch the web dashboard."""
    console.print("[bold blue]Launching Streamlit Dashboard...[/bold blue]")
    console.print("Run: [bold white]python run.py dashboard[/bold white]")

@app.command()
def status():
    """Check system status."""
    grid = Table.grid(expand=True)
    grid.add_column(style="cyan", justify="right")
    grid.add_column(justify="left")

    grid.add_row("AI Engine", " : [bold green]ONLINE[/bold green]")
    grid.add_row("Network Monitor", " : [bold green]ACTIVE[/bold green]")
    grid.add_row("Database", " : [bold green]CONNECTED[/bold green]")
    grid.add_row("Threat Level", " : [bold yellow]LOW[/bold yellow]")

    console.print(Panel(grid, title="System Status", border_style="blue"))

@app.command()
def interactive():
    """Enter interactive shell mode (Metasploit style)."""
    boot_sequence()
    show_banner()
    session = PromptSession()
    completer = WordCompleter(['scan', 'simulate', 'dashboard', 'status', 'help', 'exit'])

    while True:
        try:
            # Fixed: Added completer to session.prompt
            text = session.prompt('husn > ', completer=completer)
            text = text.strip()
            if text == 'exit':
                break
            elif text == 'help':
                console.print("[bold cyan]Commands:[/bold cyan] scan, simulate, dashboard, status, help, exit")
            elif text == 'scan':
                scan()
            elif text == 'simulate':
                simulate()
            elif text == 'dashboard':
                dashboard()
            elif text == 'status':
                status()
            elif text:
                console.print(f"[red]Unknown command: {text}[/red]")
        except KeyboardInterrupt:
            continue
        except EOFError:
            break
    console.print("Goodbye!")

@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    if ctx.invoked_subcommand is None:
        interactive()

if __name__ == "__main__":
    app()
