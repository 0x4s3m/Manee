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
        print(f"Simulating DDoS attack on {self.target_ip}...")
        for _ in range(count):
            pkt = IP(src=RandIP(), dst=self.target_ip) / TCP(sport=RandShort(), dport=80, flags="S")
            self._send_packet(pkt)
        print("DDoS simulation completed.")

    def port_scan_simulation(self):
        print(f"Simulating Port Scan on {self.target_ip}...")
        for port in range(20, 100):
            pkt = IP(dst=self.target_ip) / TCP(dport=port, flags="S")
            self._send_packet(pkt)
        print("Port scan simulation completed.")

    def brute_force_simulation(self):
        print(f"Simulating Brute Force (SSH) on {self.target_ip}...")
        for _ in range(20):
            pkt = IP(dst=self.target_ip) / TCP(dport=22, flags="PA")
            self._send_packet(pkt)
            time.sleep(0.1)
        print("Brute force simulation completed.")

if __name__ == "__main__":
    # Use loopback for testing
    sim = AttackSimulator("127.0.0.1")
    sim.brute_force_simulation()
