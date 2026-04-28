"""Husn configuration loader.

Resolves config from (in order of precedence):
  1. $HUSN_CONFIG               (explicit override)
  2. /etc/husn/config.yml       (production install)
  3. <repo>/config/config.yml   (local copy, if you made one)
  4. <repo>/config/config.example.yml (last-resort defaults)

Secrets never live in the YAML. Any key ending in `_env` is read as an
environment-variable name, and the resolved value is exposed under the
same key with the `_env` suffix stripped — e.g. `password_env: FOO`
becomes `password: <value of $FOO>`.

The loader caches the result; call `reload()` to pick up edits at runtime.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

# This file lives at: <repo>/backend/husn/src/config.py
# parents[0]=src  [1]=husn  [2]=backend  [3]=<repo>
_REPO_ROOT = Path(__file__).resolve().parents[3]
_CANDIDATE_PATHS = [
    Path(os.environ["HUSN_CONFIG"]) if os.environ.get("HUSN_CONFIG") else None,
    Path("/etc/husn/config.yml"),
    _REPO_ROOT / "config" / "config.yml",
    _REPO_ROOT / "config" / "config.example.yml",
]

_cache: dict[str, Any] | None = None
_loaded_from: Path | None = None


def _resolve_env_keys(node: Any) -> Any:
    """Recursively replace `*_env: VARNAME` entries with the env-var value."""
    if isinstance(node, dict):
        out: dict[str, Any] = {}
        for key, value in node.items():
            if key.endswith("_env") and isinstance(value, str):
                resolved_key = key[:-4]  # strip "_env"
                out[resolved_key] = os.environ.get(value, "")
                out[key] = value  # keep the pointer too, for debugging
            else:
                out[key] = _resolve_env_keys(value)
        return out
    if isinstance(node, list):
        return [_resolve_env_keys(item) for item in node]
    return node


def _first_existing(paths: list[Path | None]) -> Path | None:
    for p in paths:
        if p is not None and p.exists():
            return p
    return None


def reload() -> dict[str, Any]:
    """Re-read the config file from disk and refresh the cache."""
    global _cache, _loaded_from
    path = _first_existing(_CANDIDATE_PATHS)
    if path is None:
        _cache = {}
        _loaded_from = None
        return _cache
    with path.open("r", encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}
    _cache = _resolve_env_keys(raw)
    _loaded_from = path
    return _cache


def get_config() -> dict[str, Any]:
    """Return the cached config, loading on first call."""
    if _cache is None:
        return reload()
    return _cache


def get(path: str, default: Any = None) -> Any:
    """Dotted-path lookup, e.g. get('smtp.host', 'localhost')."""
    node: Any = get_config()
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            return default
        node = node[part]
    return node


def loaded_from() -> Path | None:
    """The file the active config was read from, or None if defaults are in use."""
    if _cache is None:
        reload()
    return _loaded_from


if __name__ == "__main__":
    import json
    cfg = get_config()
    print(f"# loaded from: {loaded_from()}")
    # Strip resolved secrets before printing
    sanitized = json.loads(json.dumps(cfg))
    if "smtp" in sanitized and sanitized["smtp"].get("password"):
        sanitized["smtp"]["password"] = "***"
    print(json.dumps(sanitized, indent=2, ensure_ascii=False))
