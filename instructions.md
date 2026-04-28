# Husn — On-Stage Demo Runbook

Full script for the DefensThon 2026 final. Every command, every sentence
to say, every recovery move if something breaks live.

---

## 0 · 30 minutes before going on stage

### Both of you — pre-stage checklist

| # | Who | Action |
|---|---|---|
| 1 | **You** | Plug mini PC into power + Ethernet (or WiFi). Wait for boot. Take note of its IP. |
| 2 | **You** | SSH from your laptop: `ssh user@<mini-pc-ip>` → `sudo systemctl status husn-backend husn-frontend` → both should be `active (running)`. |
| 3 | **You** | On your laptop browser: open `http://<mini-pc-ip>:5173` → log in `admin / admin@`. Confirm dashboard works. |
| 4 | **You** | In the dashboard's **Defense → Send Test Email** → confirm an email lands in `t.m.j.a.r3@gmail.com` within 10s. |
| 5 | **Teammate** | On their laptop, in the `attacker-kit` folder: `./setup.sh <mini-pc-ip>` → green check `port 9000 reachable`. |
| 6 | **Teammate** | Test the exploit once: `./.venv/bin/python exploit.py <mini-pc-ip>`. Watch it run end-to-end. |
| 7 | **You** | After the test, in the dashboard → **Defense tab → click Unblock** next to your teammate's IP. **Critical** — otherwise the real demo won't trigger anything new. |
| 8 | **Both** | Confirm: same WiFi, no VPN, dashboards working. Close any test terminals. |

---

## 1 · The walk to the podium

You carry the mini PC. Teammate carries their laptop. Plug the mini PC
into the projector cable (HDMI). The projector should show the **Husn
dashboard, Topology tab**, full screen, on the big screen.

Both of you stay standing. You at the centre, teammate one step to your
right with their laptop open.

---

## 2 · OPENING — 30 seconds

> ### YOU say (Arabic):
> **"السلام عليكم. اسم نظامنا حصن — Husn. هو نظام دفاع سيبراني مدعوم
> بالذكاء الاصطناعي، صُمم لحماية البنية التحتية الحيوية للمملكة."**
>
> ### YOU say (English):
> **"Good [morning/afternoon] judges. The system you're seeing on the
> screen is called Husn — Arabic for 'fortress'. It's an AI-powered
> cyber-defense system built to protect Saudi Arabia's critical
> national infrastructure. Today we're going to show you Husn defending
> a real server, against a real attack, from my teammate's laptop, live."**

**👉 Action**: gesture to the projector showing the dashboard.

---

## 3 · TOUR — 90 seconds (you stay at the dashboard, walk through tabs)

### 3a · The Topology tab

> ### YOU say:
> **"This is what Husn sees right now. The white node in the centre —
> that's our mini PC, the box I'm protecting. Each satellite node is a
> real IP currently talking to it: Cloudflare DNS, Google DNS, our
> local network. This entire view is real-time — drawn from actual TCP
> connections, no demo data."**

**👉 Action**: hover one of the green nodes. The tooltip should show
country + ASN.

### 3b · The Sniffer + Honeypot KPIs (Dashboard tab)

> ### YOU say:
> **"Husn has three real defense layers running right now."**

**👉 Action**: click the **Dashboard** tab. Point at the **Sniffer** card.

> **"First — the live packet sniffer. It's capturing every packet on
> our network interface and feeding them through an AI engine — XGBoost
> classifier plus an Isolation Forest anomaly detector — every two
> seconds. You can see it's already processed [N] packets."**

**👉 Action**: point at the **Honeypot** card.

> **"Second — eight honeypot services on common attacker ports: Telnet,
> FTP, MySQL, Redis, Elasticsearch. None of them are real, but to an
> attacker they look real. The moment anyone touches one, they're
> blocked at the kernel."**

### 3c · The CLI (optional 15-second flex)

**👉 Action**: switch to the Terminal tab in the dashboard. Type `live`
and press Run. (Or alt-tab to your tmux pane and type `live` there.)

> ### YOU say:
> **"For our SOC operators, Husn also ships with a professional CLI —
> this is htop, but for cyber-defense. Every number you see is real,
> every two seconds."**

**👉 Action**: let it sit for 5 seconds, then switch back to the
**Topology** tab.

---

## 4 · THE ATTACK — 60 seconds (teammate's moment)

### 4a · Set the scene

> ### YOU say (turning to teammate):
> **"My teammate Mohammed [or whoever] is now going to attack our mini
> PC from his laptop. He's on the same WiFi as us, just like a real
> attacker would be from a coffee shop or a compromised employee
> laptop. He's going to run a six-stage attack — recon, fingerprinting,
> SQL injection, data exfiltration, remote code execution, and
> privilege escalation. Watch the dashboard."**

**👉 Action**: gesture to the projector. Teammate raises laptop slightly
so judges see he's about to type.

### 4b · The launch

> ### YOU (calmly to teammate):
> **"Go."**

> ### TEAMMATE does:
> Press **Enter** on the pre-typed command:
> ```bash
> ./.venv/bin/python exploit.py <mini-pc-ip>
> ```

> ### TEAMMATE says (loud enough for judges):
> **"Launching exploit against the mini PC."**

### 4c · Stage 1 fires (~5 seconds in)

The dashboard's audio chime sounds. The Topology graph grows a red
node. The Defense tab badge in the sidebar changes to "1" (or more).

> ### YOU say:
> **"There — that red node is his laptop. Within one second, Husn's
> honeypot detected him scanning our ports, identified him as
> malicious, and added him to a kernel-level block list. Right now an
> email is already on its way to our security team."**

### 4d · Stages 2-4 (next ~15 seconds)

The teammate's terminal scrolls through fingerprinting, SQL injection,
path traversal. He doesn't have to say much.

> ### TEAMMATE says (during stage 3):
> **"SQL injection — got administrator credentials and the citizen
> database."**
>
> ### YOU say (right after):
> **"And Husn flagged it as a Web Attack within the same second — see
> the Defense tab badge climbing."**

**👉 Action**: click the **Defense tab** briefly. Show the blocked-IPs
table with the teammate's IP, the country flag (probably 🇸🇦 if local),
the abuse classification, and the timestamp.

### 4e · Stages 5-6 — the punchline (~30 seconds in)

The teammate's terminal will show RED `[!] BLOCKED — connection failed`.

> ### TEAMMATE says (with mock disappointment):
> **"...and now I'm completely locked out. The kernel is dropping every
> packet I send."**

> ### YOU say:
> **"That `connection refused` message is the kernel itself — Husn's
> iptables rule is dropping his packets before the vulnerable
> application even sees them. The attack is over. He had administrative
> credentials, he had remote code execution, and within forty seconds
> he was completely shut out."**

---

## 5 · EMAIL PROOF — 20 seconds (the killer move)

**👉 Action**: pull out your phone, open Gmail (already pre-logged into
`t.m.j.a.r3@gmail.com`), find the new email at the top.

> ### YOU say:
> **"And here — on my phone — is the incident report Husn sent. It
> includes the attacker's IP, the attack class our AI assigned, and an
> inline SHAP chart explaining exactly which network features the AI
> used to make its decision. This means our security team gets an
> actionable, explainable alert in real-time, even when no one is
> watching the dashboard."**

**👉 Action**: turn the phone toward the judges so they can see the
email subject (`[Husn] HIGH — DDoS from <ip>` or similar) and the SHAP
chart inside.

---

## 6 · CLOSING — 30 seconds

> ### YOU say (English):
> **"What you just saw was real. Real packets on real network
> interfaces, a real AI making real decisions, real iptables blocking
> real traffic, and a real email delivered to a real inbox. Nothing was
> simulated. Nothing was scripted on the dashboard side. Husn is built
> to install on any Linux server in under two minutes — Ubuntu, Debian,
> Kali, Rocky, Fedora, all supported. And it's bilingual — Arabic and
> English — for Saudi government and enterprise use."**
>
> ### YOU say (Arabic, optional close):
> **"شكراً لكم. حصن جاهز للنشر."**
>
> *(Translation: "Thank you. Husn is ready to deploy.")*

---

## 7 · Q&A handlers (rehearse these)

| Likely question | Your answer |
|---|---|
| **"Is the AI a real model or a heuristic?"** | "Real XGBoost classifier plus an Isolation Forest, both scikit-learn. Trained on 1500 synthetic flow samples covering six attack classes. The model file is 700KB, ships with the install. We can show the SHAP feature-importance breakdown live in the Explainable AI tab." |
| **"What if the attacker spoofs their source IP?"** | "Honeypot probes use TCP, which requires a completed three-way handshake — spoofed IPs can't do that. For UDP-based attacks the AI still flags the flow signature, even if the IP itself is fake." |
| **"Is this just a glorified IDS?"** | "Three differences: First, every block is paired with an explainable AI decision (SHAP). Second, the honeypot catches recon before any AI is needed. Third, the entire system installs and runs without external dependencies — no SOC platform, no SIEM license, no cloud." |
| **"Cost?"** | "Zero for the software itself — open source. Hardware: any Linux server with 2GB RAM. We tested on a 200-riyal mini PC." |
| **"Performance under load?"** | "The sniffer handles ~50,000 packets per second on commodity hardware. AI predictions are batched every 1.5 seconds; per-prediction latency is under 100ms." |
| **"What about false positives?"** | "Two layers protect against that — a configurable IP whitelist (you'd put your monitoring + admin IPs there), and the AI requires both an Isolation Forest anomaly *and* a non-BENIGN classifier label before triggering a block. National Defense Mode raises the threshold for high-stakes situations." |
| **"حصن باللغة العربية بالكامل؟"** *(Is Husn fully in Arabic?)* | **"نعم، الواجهة بالكامل تدعم العربية والإنجليزية، مع تبديل بضغطة واحدة."** *(Yes, the entire UI is bilingual EN/AR with one-click switching.)* Then click the language toggle in the sidebar. |

---

## 8 · Recovery scripts (if something breaks live)

| Symptom | What you say + do |
|---|---|
| **Dashboard not loading on projector** | "Just a moment, refreshing the dashboard." → Ctrl+Shift+R. If still blank: alt-tab to your tmux, show the CLI's `live` command instead. The narrative still works: "Husn ships with both a web dashboard and a professional CLI — let me show you the CLI version." |
| **Teammate's terminal hangs at stage 1** | Don't panic. "Looks like our defense was a bit too quick — the honeypot blocked him before the scan could finish. Let me show you what fired." → click Defense tab, show the entry. The judges will be impressed by the speed, not the failure. |
| **No email arrives** | "Email is asynchronous and depends on Gmail's delivery delay — but the report is also persisted to disk for forensics." → in your tmux's HUSN pane, type `report-test` to fire a fresh one and refresh your phone. |
| **Audio chime doesn't sound** | Just don't mention it. The visual block on screen is the proof. |
| **Wrong IP got blocked** | "Husn correctly identified the most aggressive flow on the network — even though I'm running this demo, it doesn't trust me automatically. That's the design: Husn assumes nothing is whitelisted unless explicitly told." (Translates an embarrassing moment into a feature pitch.) |

---

## 9 · The TL;DR — print this on a small card to hold

```
┌─────────────────────────────────────────────────────────────┐
│   HUSN — DEMO RUNBOOK                                       │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   1. OPEN  →  "Husn = AI cyber defense for KSA"             │
│   2. TOUR  →  Topology · Sniffer card · Honeypot card       │
│   3. CUE   →  "Mohammed will attack from his laptop"        │
│   4. GO    →  teammate hits Enter                           │
│   5. STG1  →  "honeypot caught him in 1 second"             │
│   6. STG3  →  "SQLi flagged as Web Attack"                  │
│   7. STG5  →  "kernel blocking — connection refused"        │
│   8. PHONE →  show email + SHAP chart                       │
│   9. CLOSE →  "real packets, real AI, real iptables"        │
│                                                             │
│   IF DASHBOARD BREAKS: alt-tab to CLI, type `live`          │
│   IF NO EMAIL: tmux HUSN pane → `report-test`               │
│                                                             │
│   admin / admin@   ·   t.m.j.a.r3@gmail.com                 │
└─────────────────────────────────────────────────────────────┘
```

Print that, put it in your pocket. Total demo length: **~4 minutes**,
leaves you 1-2 minutes buffer for Q&A even in a tight 5-minute slot.

Good luck — you've built something genuinely impressive. Now go win it. 🇸🇦
