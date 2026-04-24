import time

class DefenseResponse:
    def __init__(self, console=None):
        self.console = console

    def block_ip(self, ip_address):
        """Simulate blocking an IP address using iptables."""
        msg = f"ACTIVE DEFENSE: Blocking malicious IP {ip_address}..."
        if self.console:
            self.console.print(f"[bold red]{msg}[/bold red]")
        else:
            print(msg)

        # In a real system: subprocess.run(["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"])
        time.sleep(1)

        success_msg = f"✓ IP {ip_address} has been isolated from the network."
        if self.console:
            self.console.print(f"[bold green]{success_msg}[/bold green]")
        else:
            print(success_msg)

    def terminate_session(self, session_id):
        """Simulate terminating a malicious session."""
        print(f"ACTIVE DEFENSE: Terminating suspicious session {session_id}...")
        time.sleep(0.5)
        print(f"✓ Session {session_id} killed.")

    def alert_admin(self, threat_details):
        """Simulate alerting the administrator via SMS/Email."""
        print(f"CRITICAL ALERT: Sending threat report to National Security Center...")
        time.sleep(1)
        print("✓ Alert dispatched.")
