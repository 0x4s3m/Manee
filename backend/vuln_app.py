"""Intentionally vulnerable HTTP service — the "target" Husn defends.

Spawns a fake "Saudi National Identity Verification Portal" on port 9000.
Multiple deliberate bugs are baked in so the contest exploit script can
walk judges through a realistic kill chain.

NEW: ACTIVE DECEPTION LAYER. When a request comes from an IP currently
in Husn's blocked-IPs registry (read from a shared JSON file the
responder maintains), the endpoints don't 403 — they keep responding,
but with FAKE realistic-looking data:

  * /login    → "session granted" + 50 fake citizen records
  * /file     → synthetic /etc/passwd
  * /ping     → fake successful ping; injected commands return nothing
  * /admin/users → 50 synthetic Saudi-style names with fake national IDs

The attacker thinks they're succeeding. They exfiltrate fake data while
Husn alerts our SOC. We waste their time and gather TTP intelligence.
"""
from __future__ import annotations

import json
import os
import random
import sqlite3
import subprocess
import time
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

app = FastAPI(title="National Government Portal (Legacy)")

SHARED_STATE = os.environ.get("HUSN_SHARED_STATE", "/tmp/husn_blocked.json")

# ---------- shared blocked-IPs cache (read from responder's JSON file)
_state_cache: dict = {"updated_at": 0.0, "blocked_ips": set(), "loaded_at": 0.0}


def _is_attacker(ip: str) -> bool:
    """Refresh the cache at most once per second, then check membership."""
    now = time.time()
    if now - _state_cache["loaded_at"] > 1.0:
        try:
            data = json.loads(Path(SHARED_STATE).read_text())
            _state_cache["blocked_ips"] = {b["ip"] for b in data.get("blocked", [])}
            _state_cache["updated_at"] = data.get("updated_at", 0)
        except (FileNotFoundError, json.JSONDecodeError):
            _state_cache["blocked_ips"] = set()
        _state_cache["loaded_at"] = now
    return ip in _state_cache["blocked_ips"]


def _client_ip(request: Request) -> str:
    # Honour X-Forwarded-For when behind nginx; otherwise direct.
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        return xff.split(",")[0].strip()
    return (request.client.host if request.client else "") or ""


# ---------- in-memory "real" user database (for normal requests)
_DB = sqlite3.connect(":memory:", check_same_thread=False)
_DB.execute("CREATE TABLE users (id INTEGER, username TEXT, password TEXT, role TEXT, ssn TEXT)")
_DB.executemany(
    "INSERT INTO users VALUES (?,?,?,?,?)",
    [
        (1, "admin",      "P@ssw0rd2024",  "admin",    "1234567890"),
        (2, "fahad",      "fahad123",      "employee", "1011223344"),
        (3, "noura",      "summer!42",     "employee", "1055667788"),
        (4, "minister",   "TopSecret#88",  "admin",    "1099887766"),
        (5, "operator",   "operator2024",  "employee", "1033445566"),
    ],
)
_DB.commit()


# ---------- DECEPTION DATA — fake but plausible Saudi-style records ----------
# These are entirely synthetic. Names are common Saudi first/last name pairs;
# national IDs are random and fail the real SAU national-ID checksum so they
# can't be confused with real ones if leaked.
_FAKE_FIRST = ["Mohammed","Abdullah","Khalid","Faisal","Salman","Saud","Omar","Yousef","Bandar","Sultan","Nawaf","Turki","Hamad","Majed","Naif","Saad","Bader","Ziyad"]
_FAKE_LAST = ["Al-Saud","Al-Rashid","Al-Otaibi","Al-Qahtani","Al-Ghamdi","Al-Harbi","Al-Shehri","Al-Dosari","Al-Subaie","Al-Mutairi","Al-Anezi","Al-Zahrani"]
_FAKE_DEPTS = ["MOI","MOD","MoFA","MoH","MOE","MOC","MoTr","SAMA","NCA","STC","Aramco","SABIC"]
_FAKE_ROLES = ["analyst","officer","engineer","director","clerk","supervisor"]


def _fake_citizens(n: int = 50) -> list[dict]:
    rng = random.Random(0xC0DE)  # deterministic so judges see consistent fakes
    out = []
    for i in range(1000, 1000 + n):
        out.append({
            "id": i,
            "national_id": "9" + str(rng.randint(10**8, 10**9 - 1)),  # bogus prefix
            "name": f"{rng.choice(_FAKE_FIRST)} {rng.choice(_FAKE_LAST)}",
            "department": rng.choice(_FAKE_DEPTS),
            "role": rng.choice(_FAKE_ROLES),
            "email": f"emp{i}@gov.sa",
            "clearance": rng.choice(["public", "internal", "restricted", "secret"]),
        })
    return out


_FAKE_PASSWD = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sshd:x:101:65534::/run/sshd:/usr/sbin/nologin
postgres:x:108:117:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
mysql:x:109:118:MySQL Server,,,:/nonexistent:/bin/false
gov-portal:x:1000:1000:Portal Service,,,:/opt/gov-portal:/bin/bash
admin-bckp:x:1001:1001:Legacy backup admin,,,:/home/admin-bckp:/bin/bash
"""


# ---------- 1. homepage

@app.get("/", response_class=HTMLResponse)
def home():
    return """
    <!doctype html><html><head><title>National Identity Verification Portal</title>
    <style>body{font-family:Helvetica;background:#f4f4f0;color:#222;text-align:center;padding:80px}
    h1{color:#006c35}h2{color:#777}small{color:#aaa}</style></head>
    <body>
      <h1>🟢 National Identity Verification Portal</h1>
      <h2>Government of Saudi Arabia — Citizen Services</h2>
      <p>Server: <b>nginx/1.18.0</b> · API: <b>v3.2.1-legacy</b> · Region: <b>Riyadh</b></p>
      <small>Build: legacy-2019.04 · Last patch: 2019-08-12 · Maintainer: hosam@example.gov.sa</small>
    </body></html>
    """


# ---------- 2. command injection (with deception)

@app.get("/ping")
def ping_service(request: Request, host: str = Query(...)):
    if _is_attacker(_client_ip(request)):
        # Deception — pretend the ping succeeded but injected commands return nothing.
        clean_host = host.split(";")[0].split("&")[0].split("|")[0].strip() or "127.0.0.1"
        fake = (
            f"PING {clean_host} ({clean_host}): 56 data bytes\n"
            f"64 bytes from {clean_host}: icmp_seq=0 ttl=64 time=0.045 ms\n"
            f"\n--- {clean_host} ping statistics ---\n"
            f"1 packets transmitted, 1 packets received, 0.0% packet loss\n"
        )
        return {"status": "success", "output": fake}
    # Real vuln path
    command = f"ping -c 1 {host}"
    try:
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True, timeout=5)
        return {"status": "success", "output": output}
    except subprocess.CalledProcessError as e:
        return {"status": "error", "output": e.output}


# ---------- 3. SQL injection (with deception)

class LoginReq(BaseModel):
    username: str
    password: str


@app.post("/login")
def login(req: LoginReq, request: Request):
    if _is_attacker(_client_ip(request)):
        # Deception — always "succeed", return fake citizen-style users.
        fake = _fake_citizens(50)
        return {
            "status": "ok",
            "matched_users": [{"id": u["id"], "username": u["name"].lower().replace(" ", "."), "role": u["role"]} for u in fake[:5]],
            "session_token": f"sess-{int(time.time())}-{req.username}",
            "_debug_full_dump": fake,  # extra "leak" so the attacker thinks they hit the jackpot
        }
    # Real vuln path
    query = f"SELECT id, username, role FROM users WHERE username='{req.username}' AND password='{req.password}'"
    try:
        rows = list(_DB.execute(query))
    except sqlite3.Error as e:
        raise HTTPException(status_code=500, detail=f"SQL: {e}")
    if not rows:
        raise HTTPException(status_code=401, detail="invalid credentials")
    matched = [{"id": r[0], "username": r[1], "role": r[2]} for r in rows]
    return {"status": "ok", "matched_users": matched, "session_token": "demo-session-" + matched[0]["username"]}


# ---------- 4. path traversal (with deception)

@app.get("/file")
def fetch_file(request: Request, name: str = Query(...)):
    if _is_attacker(_client_ip(request)):
        # Deception — "exfiltrate" synthetic /etc/passwd no matter what they ask for.
        return {
            "name": name,
            "size": len(_FAKE_PASSWD),
            "preview": _FAKE_PASSWD,
        }
    # Real vuln path
    base = "/tmp"
    target = os.path.join(base, name)
    try:
        with open(target, "rb") as f:
            data = f.read(2048)
        return {"name": name, "size": len(data), "preview": data[:1024].decode("utf-8", errors="replace")}
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="not found")
    except IsADirectoryError:
        raise HTTPException(status_code=400, detail="is a directory")
    except PermissionError:
        raise HTTPException(status_code=403, detail="permission denied")


# ---------- 5. auth bypass (with deception)

@app.get("/admin/users")
def admin_users(request: Request, x_auth_bypass: str | None = Header(default=None)):
    if _is_attacker(_client_ip(request)):
        # Deception — full fake citizen DB.
        return JSONResponse(_fake_citizens(50))
    if x_auth_bypass != "yes":
        raise HTTPException(status_code=403, detail="forbidden")
    rows = list(_DB.execute("SELECT id, username, role, ssn FROM users"))
    return JSONResponse([
        {"id": r[0], "username": r[1], "role": r[2], "national_id": r[3]} for r in rows
    ])


@app.get("/_deception/state")
def deception_state():
    """Diagnostic — judges can curl this to see who's currently being deceived."""
    _is_attacker("0.0.0.0")  # force cache refresh
    return {
        "shared_state_file": SHARED_STATE,
        "currently_deceived": sorted(_state_cache["blocked_ips"]),
        "updated_at": _state_cache["updated_at"],
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9000)
