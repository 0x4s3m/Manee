"""Scan the project tree for issues. Caches the most recent scan in
memory so the dashboard can re-render without re-walking the disk."""
from __future__ import annotations

import hashlib
import logging
import os
import threading
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Iterator

from .rules import RULES, Rule, by_id

log = logging.getLogger("husn.autopatch.scanner")

# ───────────── Scan boundaries ───────────────────────────────────────
# Only walk inside these subtrees of the Husn project root, never the
# whole filesystem. Limits blast radius of scanner+patch combined.
SCAN_SUBTREES = ("backend", "frontend/src", "config", "deploy")
SKIP_DIRS = {
    "node_modules", "venv", ".venv", "__pycache__", ".git",
    "dist", "build", ".vite", ".vite-temp", "htmlcov",
}
MAX_FILE_BYTES = 256 * 1024  # skip massive generated files


@dataclass
class Issue:
    id: str               # stable hash (rule_id + file + line + match)
    rule_id: str
    rule_name: str
    severity: str
    confidence: float
    file: str             # path relative to husn project root
    line_number: int
    line_content: str     # the matched line, stripped of trailing newline
    suggested_fix: str | None        # auto-template fix; None = needs LLM/manual
    rationale: str
    description: str
    detected_at: float = field(default_factory=time.time)
    can_auto_fix: bool = False

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["detected_at_iso"] = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(self.detected_at))
        return d


# ───────────── Cache + project root ──────────────────────────────────

_cache_lock = threading.RLock()
_cache: list[Issue] = []
_cache_at: float = 0.0


def _project_root() -> Path:
    """Husn lives at .../husn/ — backend imports from .../husn/backend.
    Walk up from this file until we find one of the canonical markers."""
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "backend").is_dir() and (parent / "frontend").is_dir():
            return parent
    # Fallback for unusual layouts (Docker, dev): walk up to /opt/husn or cwd
    if Path("/opt/husn").is_dir():
        return Path("/opt/husn")
    return Path.cwd()


def _walk_files(root: Path) -> Iterator[Path]:
    for sub in SCAN_SUBTREES:
        base = root / sub
        if not base.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
            for fn in filenames:
                p = Path(dirpath) / fn
                try:
                    if p.stat().st_size > MAX_FILE_BYTES:
                        continue
                except OSError:
                    continue
                yield p


def _scan_file(path: Path, root: Path) -> list[Issue]:
    rel = str(path.relative_to(root))
    suffix = path.suffix.lower()
    rules_for_file = [r for r in RULES if suffix in r.applies_to]
    if not rules_for_file:
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    issues: list[Issue] = []
    for lineno, line in enumerate(text.splitlines(keepends=True), start=1):
        # Skip lines we've already patched — avoids the scanner re-flagging
        # a TODO marker the previous run wrote.
        if "AUTOPATCH-TODO" in line or "AUTOPATCH-NOTE" in line:
            continue
        for rule in rules_for_file:
            m = rule.pattern.search(line)
            if not m:
                continue
            suggested = None
            can_auto = False
            if rule.suggest_fix is not None:
                try:
                    suggested = rule.suggest_fix(line, m)
                    can_auto = suggested is not None and suggested != line
                except Exception:
                    log.exception("[autopatch] suggest_fix crashed on rule=%s file=%s:%d", rule.id, rel, lineno)
                    suggested = None
            issues.append(_issue(rule, rel, lineno, line, suggested, can_auto))
    return issues


def _issue(rule: Rule, rel_path: str, lineno: int, line: str, suggested: str | None, can_auto: bool) -> Issue:
    h = hashlib.sha1(f"{rule.id}|{rel_path}|{lineno}|{line.strip()}".encode("utf-8")).hexdigest()[:12]
    return Issue(
        id=h,
        rule_id=rule.id,
        rule_name=rule.name,
        severity=rule.severity,
        confidence=rule.confidence,
        file=rel_path,
        line_number=lineno,
        line_content=line.rstrip("\n"),
        suggested_fix=suggested.rstrip("\n") if suggested else None,
        rationale=rule.rationale,
        description=rule.description,
        can_auto_fix=can_auto,
    )


# ───────────── Public API ───────────────────────────────────────────

def scan(force: bool = False) -> dict[str, Any]:
    """Run the scan. Cached for 30s unless `force=True`."""
    global _cache, _cache_at
    with _cache_lock:
        if not force and (time.time() - _cache_at) < 30 and _cache:
            return _summary()

        root = _project_root()
        all_issues: list[Issue] = []
        files_scanned = 0
        t0 = time.time()
        for f in _walk_files(root):
            files_scanned += 1
            try:
                all_issues.extend(_scan_file(f, root))
            except Exception:
                log.exception("[autopatch] scan_file crashed on %s", f)
        # Sort: most severe + highest-confidence first
        sev_rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
        all_issues.sort(key=lambda i: (-sev_rank.get(i.severity, 0), -i.confidence, i.file, i.line_number))
        _cache = all_issues
        _cache_at = time.time()
        log.info("[autopatch] scan complete: %d files, %d issues, %.2fs",
                 files_scanned, len(all_issues), time.time() - t0)
        return _summary(files_scanned=files_scanned, took=time.time() - t0)


def _summary(files_scanned: int | None = None, took: float | None = None) -> dict[str, Any]:
    sev_counts: dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for i in _cache:
        sev_counts[i.severity] = sev_counts.get(i.severity, 0) + 1
    return {
        "scanned_at": _cache_at,
        "scanned_at_iso": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(_cache_at)),
        "files_scanned": files_scanned,
        "issues_total": len(_cache),
        "by_severity": sev_counts,
        "rules_loaded": len(RULES),
        "took_seconds": round(took, 3) if took is not None else None,
        "issues": [i.to_dict() for i in _cache],
    }


def list_issues() -> list[dict[str, Any]]:
    with _cache_lock:
        return [i.to_dict() for i in _cache]


def get_issue(issue_id: str) -> Issue | None:
    with _cache_lock:
        for i in _cache:
            if i.id == issue_id:
                return i
        return None


def project_root() -> Path:
    return _project_root()


def rule_for(issue: Issue) -> Rule | None:
    return by_id(issue.rule_id)
