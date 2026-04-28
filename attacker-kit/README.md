# Husn — Attacker Kit (Teammate Edition)

You're the **red team** for the Husn contest demo. Your job: launch the
exploit script from your laptop against Husn (running on the mini PC
or another box on the same Wi-Fi). Husn's job: detect, block, and email
about you within seconds.

## What's in this folder

```
attacker-kit/
├── exploit.py          single-file kill-chain (recon → SQLi → RCE)
├── requirements.txt    one dep: requests
├── setup.sh            installs requests into a local .venv
└── README.md           you're reading it
```

## One-time setup on your laptop

```bash
cd attacker-kit
chmod +x setup.sh
./setup.sh
```

That installs `requests` into a tiny `.venv/` here so nothing global gets
touched on your laptop.

> Windows users: open **PowerShell**, then:
> `python -m venv .venv ; .\.venv\Scripts\pip install -r requirements.txt`

## Before the demo — sanity check

Both laptops on **the same Wi-Fi**. Get Husn's IP from your team-mate
(the one running Husn). Then:

```bash
./setup.sh 192.168.1.50         # replace with the Husn IP
```

If you see `✓ port 9000 reachable — exploit will work` you're good.

If you see `✗ cannot reach`:
- confirm both laptops are on the same Wi-Fi (no VPN, no different SSID)
- confirm the Husn IP is correct (`ip addr` on the Husn box)
- check the Husn box's firewall (`sudo ufw status` — if active, ports 9000, 8000, 5173 should be allowed)
- if Husn runs in WSL2 instead of a real Linux box, the team-mate needs Windows port-forwarding (see below)

## Showtime

Tell the team-mate when the projector is showing the Husn dashboard, then run:

```bash
./.venv/bin/python exploit.py <husn-ip>
```

The exploit waits 3 seconds (so judges can switch to the dashboard),
then walks through six attack stages with deliberate pauses between
them. Each stage is real network traffic — the team-mate's dashboard
will react in real time.

The whole show takes **~45 seconds**.

## What you'll see on your terminal

```
    ╔════════════════════════════════════════════════════════════╗
    ║            ⚠   K I L L   C H A I N   D E M O   ⚠           ║
    ╚════════════════════════════════════════════════════════════╝

  target: http://192.168.1.50:9000
  attacker source: 192.168.1.42

[Stage 1] RECONNAISSANCE — TCP port scan
  [+] port 21    OPEN          ← honeypot
  [+] port 23    OPEN          ← honeypot
  [+] port 6379  OPEN          ← honeypot
  [+] port 9000  OPEN          ← real vulnerable target
  ↳ pausing 3s — honeypot probably already blocked us

[Stage 2] FINGERPRINT — banner grab the web service
  [+] portal identified — legacy 2019 build, unpatched

[Stage 3] AUTHENTICATION BYPASS — SQL injection on /login
  [+] AUTH BYPASSED — server returned valid session
       session  demo-session-admin
       user     'admin'      role=admin
       user     'minister'   role=admin

[Stage 4] DATA LEAK — path traversal on /file
  [+] EXFILTRATED 2048 bytes from ../../../etc/passwd

[Stage 5] REMOTE CODE EXECUTION — command injection on /ping
  [!] BLOCKED — connection failed (ConnectTimeout)     ← Husn's iptables wins

[Stage 6] PRIVILEGE ESCALATION — legacy debug-header bypass
  [!] connection refused — Husn blocked us             ← still blocked

                  KILL CHAIN COMPLETE
```

When you see "BLOCKED — connection refused" in stages 5 and 6, that's
the punchline: Husn has already iptables-DROP'd your IP at the kernel
level. The vulnerable app never even sees those requests.

## Pre-flight checklist (do this 30 min before going on stage)

- [ ] Both laptops on the same Wi-Fi (no VPN, no LTE failover)
- [ ] `./setup.sh <husn-ip>` returns reachable
- [ ] Test-run the full exploit once: `./.venv/bin/python exploit.py <husn-ip>`
- [ ] Team-mate confirms an email landed in `t.m.j.a.r3@gmail.com` after stage 1
- [ ] Team-mate **manually unblocks your IP** before the real demo (you got blocked during the test run): in the Husn dashboard → Defense tab → click the Unblock button next to your IP

## If something goes wrong on stage

| symptom | quick fix |
|---|---|
| `connection refused` on every stage | You were already blocked from a test run. Team-mate: open dashboard → Defense → Unblock all your IPs. |
| Exploit hangs on stage 1 | Wrong target IP. Press Ctrl+C, double-check with the team-mate. |
| Half the ports show OPEN, half don't | That's fine — those are the honeypot ports vs real vuln_app port. Keep going. |
| Team-mate can't see your IP in their dashboard | They forgot to remove `127.0.0.1` from the whitelist? Or maybe iptables is in simulated mode. Either way, the exploit still runs — it just won't visually pop. |

## When Husn is running in WSL2 (not on a real Linux box)

WSL has its own private IP that isn't reachable from the LAN. The
team-mate has to set up Windows port-forwarding, in **admin PowerShell
on their Windows host**:

```powershell
$wslIp = (wsl hostname -I).Trim().Split()[0]
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=9000 connectaddress=$wslIp connectport=9000
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=8000 connectaddress=$wslIp connectport=8000
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=5173 connectaddress=$wslIp connectport=5173
New-NetFirewallRule -DisplayName "Husn demo" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8000,9000,5173
```

Then you target the **Windows host's LAN IP**, not the WSL IP. Get it
on the Windows host with `ipconfig`.

To undo afterwards:

```powershell
netsh interface portproxy reset
```

That's it. You're ready.
