from fastapi import FastAPI, Query
import subprocess
import os

app = FastAPI(title="National Government Portal (Legacy)")

@app.get("/")
def home():
    return {"status": "online", "service": "National Identity Verification"}

@app.get("/ping")
def ping_service(host: str = Query(..., description="Target host to ping for health check")):
    """
    VULNERABLE ENDPOINT: Intentional Command Injection for DefensThon Demo.
    The host parameter is passed directly to the shell.
    """
    # DEMO VULNERABILITY: User input is not sanitized.
    # An attacker can use: ; ls / or ; cat /etc/passwd
    command = f"ping -c 1 {host}"
    try:
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)
        return {"status": "success", "output": output}
    except subprocess.CalledProcessError as e:
        return {"status": "error", "output": e.output}

if __name__ == "__main__":
    import uvicorn
    # Running on a separate port for the demo
    uvicorn.run(app, host="0.0.0.0", port=9000)
