"""On-demand project backups.

Snapshot the source tree (backend/ frontend/src/ config/ deploy/) into
a single .tar.gz that can be downloaded or restored manually with `tar
-xzf`. Every Auto Patch action already writes per-file `.husn-bak.<ts>`
backups; this module is for *whole-project* recovery — the kind of
backup you take BEFORE running a bulk AI fix.

Stored under /etc/husn/backups/ (writable via the existing
ReadWritePaths drop-in). No venv, no node_modules, no build artefacts —
just source.
"""
from __future__ import annotations

import logging
import re
import tarfile
import time
from pathlib import Path
from typing import Any

from .scanner import project_root

log = logging.getLogger("husn.autopatch.backups")

# Subtrees included in the snapshot — anything outside these is skipped.
_INCLUDE = (
    "backend/husn",
    "backend/main.py",
    "backend/vuln_app.py",
    "backend/requirements.txt",
    "frontend/src",
    "frontend/index.html",
    "frontend/package.json",
    "frontend/vite.config.ts",
    "frontend/tsconfig.json",
    "frontend/tsconfig.app.json",
    "frontend/tsconfig.node.json",
    "config",
    "deploy",
    "install.sh",
    "vps-setup.sh",
    "uninstall.sh",
    "run.py",
    "CLAUDE.md",
    "README.md",
)

# Path-component blocklist — these never end up in the archive.
_SKIP_PARTS = {
    "__pycache__", "node_modules", "venv", ".venv",
    "dist", ".vite", ".vite-temp", ".git",
}

_NAME_RX = re.compile(r"^husn-backup-\d{8}-\d{6}\.tar\.gz$")


def _backups_dir() -> Path:
    from husn.src import config
    base = Path(config.get("paths.state_dir") or "/etc/husn")
    d = base / "backups"
    d.mkdir(parents=True, exist_ok=True)
    return d


def create() -> dict[str, Any]:
    """Build a fresh tar.gz of the source tree. Returns metadata."""
    root = project_root()
    ts = time.strftime("%Y%m%d-%H%M%S")
    out = _backups_dir() / f"husn-backup-{ts}.tar.gz"

    file_count = 0
    bytes_in = 0
    started = time.time()

    try:
        with tarfile.open(out, "w:gz", compresslevel=6) as tar:
            for inc in _INCLUDE:
                base = root / inc
                if not base.exists():
                    continue
                if base.is_file():
                    if any(part in _SKIP_PARTS for part in base.parts):
                        continue
                    arcname = str(base.relative_to(root))
                    tar.add(base, arcname=arcname)
                    file_count += 1
                    try:
                        bytes_in += base.stat().st_size
                    except OSError:
                        pass
                else:
                    for path in sorted(base.rglob("*")):
                        if not path.is_file():
                            continue
                        if any(part in _SKIP_PARTS for part in path.parts):
                            continue
                        try:
                            arcname = str(path.relative_to(root))
                        except ValueError:
                            continue
                        try:
                            tar.add(path, arcname=arcname)
                            file_count += 1
                            bytes_in += path.stat().st_size
                        except (OSError, tarfile.TarError):
                            log.warning("[backup] skipped %s", path, exc_info=True)
                            continue
    except Exception as exc:
        # Clean up any partial archive
        try:
            out.unlink(missing_ok=True)
        except OSError:
            pass
        log.exception("[backup] create failed")
        return {"ok": False, "error": str(exc)}

    try:
        size = out.stat().st_size
    except OSError:
        size = 0

    return {
        "ok": True,
        "filename": out.name,
        "path": str(out),
        "size_bytes": size,
        "files": file_count,
        "raw_bytes": bytes_in,
        "took_seconds": round(time.time() - started, 2),
        "created_at": time.time(),
        "created_at_iso": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
    }


def list_all() -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for p in _backups_dir().glob("husn-backup-*.tar.gz"):
        try:
            st = p.stat()
        except OSError:
            continue
        items.append({
            "filename": p.name,
            "size_bytes": st.st_size,
            "created_at": st.st_mtime,
            "created_at_iso": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(st.st_mtime)),
        })
    items.sort(key=lambda x: -x["created_at"])
    return items


def delete(filename: str) -> dict[str, Any]:
    """Delete a single backup by filename. Refuses anything that isn't a
    proper husn-backup-* name to prevent path traversal."""
    if not _NAME_RX.match(filename):
        return {"ok": False, "error": "invalid backup filename"}
    p = _backups_dir() / filename
    if not p.is_file():
        return {"ok": False, "error": "backup not found"}
    try:
        p.unlink()
        return {"ok": True, "filename": filename}
    except OSError as e:
        return {"ok": False, "error": str(e)}


def get_path(filename: str) -> Path | None:
    """Resolve a backup filename to a safe path (or None if invalid).
    Used by the download endpoint."""
    if not _NAME_RX.match(filename):
        return None
    p = _backups_dir() / filename
    return p if p.is_file() else None
