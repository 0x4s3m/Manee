"""FastAPI dependencies for authentication and role-based access.

Usage:
    @app.get("/something", dependencies=[Depends(require_user)])     # any logged-in user
    @app.post("/dangerous", dependencies=[Depends(require_admin)])   # admin only

To read the current user inside a handler:
    @app.get("/me")
    def me(user: dict = Depends(require_user)):
        return user
"""
from __future__ import annotations

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from husn.src.auth import tokens, users

_bearer = HTTPBearer(auto_error=False)


def _extract_token(request: Request, creds: HTTPAuthorizationCredentials | None) -> str:
    if creds and creds.credentials:
        return creds.credentials
    # Allow ?token=... as a fallback for EventSource/img tags etc. (not used today).
    return request.query_params.get("token", "")


def require_user(request: Request, creds: HTTPAuthorizationCredentials | None = Depends(_bearer)) -> dict:
    token = _extract_token(request, creds)
    payload = tokens.verify(token)
    if payload is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid or expired token")
    user = users.find(payload.username)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="user no longer exists")
    return {"username": user["username"], "role": user["role"]}


def require_admin(user: dict = Depends(require_user)) -> dict:
    if user.get("role") != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="admin role required")
    return user
