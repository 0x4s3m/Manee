"""JWT issue + verify.

Token payload:
    {
      "sub": "<username>",
      "role": "admin" | "employee",
      "iat": <unix>,
      "exp": <unix>
    }

Signed HS256 with the secret stored in users.yml's `jwt_secret` key
(generated on first run, persistent across restarts).
"""
from __future__ import annotations

import time
from dataclasses import dataclass

import jwt

from husn.src import config
from husn.src.auth import users

ALGORITHM = "HS256"


def _ttl_seconds() -> int:
    return int(config.get("auth.token_ttl_seconds", 8 * 3600))  # default 8h


@dataclass
class TokenPayload:
    username: str
    role: str
    issued_at: int
    expires_at: int


def issue(username: str, role: str) -> str:
    now = int(time.time())
    payload = {
        "sub": username,
        "role": role,
        "iat": now,
        "exp": now + _ttl_seconds(),
    }
    return jwt.encode(payload, users.jwt_secret(), algorithm=ALGORITHM)


def verify(token: str) -> TokenPayload | None:
    if not token:
        return None
    try:
        decoded = jwt.decode(token, users.jwt_secret(), algorithms=[ALGORITHM])
    except jwt.PyJWTError:
        return None
    return TokenPayload(
        username=decoded.get("sub", ""),
        role=decoded.get("role", ""),
        issued_at=int(decoded.get("iat", 0)),
        expires_at=int(decoded.get("exp", 0)),
    )
