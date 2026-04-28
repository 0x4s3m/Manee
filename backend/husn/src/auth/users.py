"""User store — YAML-backed, bcrypt-hashed passwords.

The store is a single file:

    jwt_secret: <hex>          # generated on first run, persisted across restarts
    users:
      - username: admin
        password_hash: $2b$12$...
        role: admin
        created_at: 2026-04-26T10:00:00Z

Mutations (`create`, `delete`, `set_password`) flush the file on every
change. Reads hold an in-memory cache that's invalidated on flush.
"""
from __future__ import annotations

import os
import secrets
import threading
import time
from pathlib import Path
from typing import Any, Iterable

import bcrypt
import yaml

from husn.src import config

_VALID_ROLES = {"admin", "employee"}
_DEFAULT_ADMIN = ("admin", "admin@", "admin")  # username, password, role

_lock = threading.RLock()
_cache: dict[str, Any] | None = None
_path_cache: Path | None = None


# ---------------------------------------------------------------- file path

def store_path() -> Path:
    """Resolve the users-file location. Falls back to <repo>/config/users.yml."""
    explicit = config.get("auth.users_file")
    if explicit:
        return Path(explicit)
    # Same directory as the active config; that way dev uses repo config/, prod uses /etc/husn/.
    cfg_path = config.loaded_from()
    if cfg_path:
        return cfg_path.parent / "users.yml"
    # Final fallback — sibling to this code's repo root.
    return Path(__file__).resolve().parents[4] / "config" / "users.yml"


# ---------------------------------------------------------------- load / save

def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _hash(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("ascii")


def _verify(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("ascii"))
    except (ValueError, TypeError):
        return False


def _load_or_seed() -> dict[str, Any]:
    """Load users.yml. If it doesn't exist, seed with a default admin and a fresh JWT secret."""
    path = store_path()
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        seeded = {
            "jwt_secret": secrets.token_hex(32),
            "users": [{
                "username": _DEFAULT_ADMIN[0],
                "password_hash": _hash(_DEFAULT_ADMIN[1]),
                "role": _DEFAULT_ADMIN[2],
                "created_at": _now_iso(),
            }],
        }
        _write(path, seeded)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return seeded
    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    # Ensure required keys exist even on a partial / hand-edited file.
    if not data.get("jwt_secret"):
        data["jwt_secret"] = secrets.token_hex(32)
        _write(path, data)
    data.setdefault("users", [])
    return data


def _write(path: Path, data: dict[str, Any]) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, sort_keys=False, allow_unicode=True)
    tmp.replace(path)


def _state() -> dict[str, Any]:
    global _cache, _path_cache
    with _lock:
        path = store_path()
        if _cache is None or _path_cache != path:
            _cache = _load_or_seed()
            _path_cache = path
        return _cache


def _flush() -> None:
    """Persist the in-memory cache back to disk."""
    with _lock:
        if _cache is None:
            return
        _write(_path_cache or store_path(), _cache)


def reload() -> None:
    """Drop the cache so the next read pulls fresh data from disk."""
    global _cache
    with _lock:
        _cache = None


# ---------------------------------------------------------------- public API

def jwt_secret() -> str:
    return _state()["jwt_secret"]


def list_users(include_hashes: bool = False) -> list[dict[str, Any]]:
    rows = list(_state().get("users", []))
    if include_hashes:
        return rows
    # Strip password_hash from outbound responses.
    return [{k: v for k, v in r.items() if k != "password_hash"} for r in rows]


def find(username: str) -> dict[str, Any] | None:
    username = (username or "").strip().lower()
    for u in _state().get("users", []):
        if u.get("username", "").lower() == username:
            return u
    return None


def authenticate(username: str, password: str) -> dict[str, Any] | None:
    """Return the user record (without hash) on success, None on failure."""
    u = find(username)
    if u is None:
        return None
    if not _verify(password, u.get("password_hash", "")):
        return None
    return {k: v for k, v in u.items() if k != "password_hash"}


def create(username: str, password: str, role: str) -> dict[str, Any]:
    username = (username or "").strip()
    role = (role or "").strip().lower()
    if not username:
        raise ValueError("username required")
    if role not in _VALID_ROLES:
        raise ValueError(f"role must be one of {sorted(_VALID_ROLES)}")
    if not password or len(password) < 4:
        raise ValueError("password must be at least 4 characters")
    if find(username) is not None:
        raise ValueError(f"user {username!r} already exists")
    record = {
        "username": username,
        "password_hash": _hash(password),
        "role": role,
        "created_at": _now_iso(),
    }
    with _lock:
        _state()["users"].append(record)
        _flush()
    return {k: v for k, v in record.items() if k != "password_hash"}


def delete(username: str) -> bool:
    username = (username or "").strip().lower()
    with _lock:
        users: list[dict[str, Any]] = _state().get("users", [])
        before = len(users)
        # Refuse to delete the last admin — would lock everyone out.
        admins = [u for u in users if u.get("role") == "admin"]
        target = next((u for u in users if u.get("username", "").lower() == username), None)
        if target is not None and target.get("role") == "admin" and len(admins) <= 1:
            raise ValueError("cannot delete the last remaining admin")
        users[:] = [u for u in users if u.get("username", "").lower() != username]
        if len(users) == before:
            return False
        _flush()
        return True


def set_password(username: str, new_password: str) -> bool:
    username = (username or "").strip().lower()
    if not new_password or len(new_password) < 4:
        raise ValueError("password must be at least 4 characters")
    with _lock:
        for u in _state().get("users", []):
            if u.get("username", "").lower() == username:
                u["password_hash"] = _hash(new_password)
                _flush()
                return True
        return False


def set_role(username: str, role: str) -> bool:
    role = (role or "").strip().lower()
    if role not in _VALID_ROLES:
        raise ValueError(f"role must be one of {sorted(_VALID_ROLES)}")
    username = (username or "").strip().lower()
    with _lock:
        users = _state().get("users", [])
        target = next((u for u in users if u.get("username", "").lower() == username), None)
        if target is None:
            return False
        # Same protection as delete — don't demote the last admin.
        admins = [u for u in users if u.get("role") == "admin"]
        if target.get("role") == "admin" and role != "admin" and len(admins) <= 1:
            raise ValueError("cannot demote the last remaining admin")
        target["role"] = role
        _flush()
        return True


def roles() -> Iterable[str]:
    return tuple(sorted(_VALID_ROLES))
