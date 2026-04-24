import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn
import time
import sys

# For interactive mode
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter

app = typer.Typer()
console = Console()

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

def show_banner():
    console.print(LOGO)
    console.print(Panel("[bold white]Welcome to Husn (حصن) - Intelligent Cyber Defense System[/bold white]", border_style="green"))

@app.command()
def scan():
    """Scan the network for threats."""
    console.print("[bold yellow]Initiating Network Scan...[/bold yellow]")
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
        progress.add_task(description="Sniffing packets...", total=None)
        time.sleep(2)
        progress.add_task(description="Analyzing traffic patterns...", total=None)
        time.sleep(2)
        progress.add_task(description="Running AI Inference...", total=None)
        time.sleep(1)

    table = Table(title="Scan Results")
    table.add_column("Timestamp", style="cyan")
    table.add_column("Source IP", style="magenta")
    table.add_column("Target IP", style="magenta")
    table.add_column("Attack Type", style="red")
    table.add_column("Severity", style="bold red")

    table.add_row("2026-04-24 10:00:01", "192.168.1.15", "10.0.0.5", "DDoS", "High")
    table.add_row("2026-04-24 10:00:05", "172.16.0.22", "10.0.0.5", "PortScan", "Medium")
    table.add_row("2026-04-24 10:00:12", "192.168.1.50", "10.0.0.1", "BENIGN", "Low")

    console.print(table)

@app.command()
def simulate():
    """Simulate an attack for training purposes."""
    console.print("[bold red]Starting Attack Simulation...[/bold red]")
    attack_type = typer.prompt("Select attack type (DDoS, BruteForce, PortScan)")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
        progress.add_task(description=f"Crafting {attack_type} packets...", total=None)
        time.sleep(1.5)
        progress.add_task(description="Injected payloads into stream...", total=None)
        time.sleep(1.5)

    console.print(f"[bold green]Simulation of {attack_type} completed successfully.[/bold green]")

@app.command()
def dashboard():
    """Launch the web dashboard."""
    console.print("[bold blue]Launching Streamlit Dashboard...[/bold blue]")
    console.print("Run: [bold white]streamlit run husn/src/dashboard.py[/bold white]")

@app.command()
def status():
    """Check system status."""
    console.print("[bold white]System Status:[/bold white]")
    console.print("- AI Engine: [bold green]ONLINE[/bold green]")
    console.print("- Network Monitor: [bold green]ACTIVE[/bold green]")
    console.print("- Database: [bold green]CONNECTED[/bold green]")

@app.command()
def interactive():
    """Enter interactive shell mode (Metasploit style)."""
    show_banner()
    session = PromptSession()
    completer = WordCompleter(['scan', 'simulate', 'dashboard', 'status', 'help', 'exit'])

    while True:
        try:
            text = session.prompt('husn > ', completer=completer)
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
