"""Apply / reject / manually-edit / LLM-suggest patches.

Safety contract:
  • Patches only inside the project root subtrees we scanned.
  • Every write makes a `.husn-bak.<ts>` of the original file first.
  • SHA-256 of before/after both recorded in the audit log.
  • LLM suggestions are returned to the admin — *never* auto-applied.
"""
from __future__ import annotations

import hashlib
import logging
import shutil
import time
from pathlib import Path
from typing import Any

from . import history
from .scanner import get_issue, project_root, rule_for, scan, Issue

log = logging.getLogger("husn.autopatch.engine")


# ───────────── Helpers ─────────────────────────────────────────────

def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def _resolve_safe_path(rel_path: str) -> Path | None:
    """Resolve `rel_path` under the scanner's project root and refuse
    anything that escapes via `..` or absolute paths."""
    root = project_root().resolve()
    candidate = (root / rel_path).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return None
    if not candidate.is_file():
        return None
    return candidate


def _backup(path: Path) -> Path:
    bak = path.with_suffix(path.suffix + f".husn-bak.{int(time.time())}")
    shutil.copy2(path, bak)
    return bak


def _leading_whitespace(line: str) -> str:
    i = 0
    while i < len(line) and line[i] in " \t":
        i += 1
    return line[:i]


def _file_header(lines: list[str], max_lines: int = 30) -> str:
    """Return the docstring + imports block at the top of the file.
    Stops at the first def/class so the LLM sees the file's purpose and
    available imports without paying for the whole body."""
    out: list[str] = []
    for i, line in enumerate(lines[:max_lines * 2]):  # scan a bit further but cap output
        stripped = line.lstrip()
        # Stop once we hit the first real definition
        if stripped.startswith(("def ", "class ", "async def ")):
            break
        out.append(line)
        if len(out) >= max_lines:
            break
    return "\n".join(out).rstrip()


def _enclosing_function_block(lines: list[str], lineno: int, padding: int = 6) -> str:
    """Return the function or class block that contains line `lineno`.
    Detection is indent-based for Python; for non-Python files we fall
    back to a window of `padding * 4` lines around the target. Lines are
    numbered in the output so the LLM can refer to them."""
    if lineno < 1 or lineno > len(lines):
        return ""
    target = lines[lineno - 1]
    target_indent = len(_leading_whitespace(target))

    # Walk backwards to find the opening def/class at any shallower indent.
    start = lineno - 1
    for i in range(lineno - 1, -1, -1):
        line = lines[i]
        stripped = line.lstrip()
        indent = len(_leading_whitespace(line))
        if (stripped.startswith(("def ", "class ", "async def ")) and indent < target_indent) or i == 0:
            start = i
            break

    # Walk forward until we leave the block (line at the same-or-shallower indent than the def)
    block_indent = len(_leading_whitespace(lines[start]))
    end = lineno - 1
    for j in range(start + 1, len(lines)):
        line = lines[j]
        if line.strip() == "":
            end = j
            continue
        indent = len(_leading_whitespace(line))
        stripped = line.lstrip()
        # New top-level def/class at the same indent as the opening def → block ended
        if indent <= block_indent and stripped.startswith(("def ", "class ", "async def ", "@")) and j > start + 1:
            break
        end = j

    # Pad slightly so the LLM sees a couple of neighbouring lines too
    lo = max(0, start - padding // 2)
    hi = min(len(lines), end + 1 + padding)
    out = []
    for k in range(lo, hi):
        marker = " >>" if (k + 1) == lineno else "   "
        out.append(f"{k + 1:>5}{marker} {lines[k]}")
    return "\n".join(out)


def _swap_line(text: str, lineno: int, new_line: str) -> tuple[str, str]:
    """Replace 1-indexed line `lineno` in `text` with `new_line` (which
    may include its own trailing newline). Returns (new_text, old_line)."""
    lines = text.splitlines(keepends=True)
    if lineno < 1 or lineno > len(lines):
        raise IndexError(f"line {lineno} out of range (1..{len(lines)})")
    old = lines[lineno - 1]
    # Ensure the new line ends with a newline so we don't merge into the
    # next one.
    if not new_line.endswith("\n"):
        new_line = new_line + "\n"
    lines[lineno - 1] = new_line
    return "".join(lines), old


# ───────────── Public API ─────────────────────────────────────────

def apply_patch(issue_id: str, actor: str) -> dict[str, Any]:
    """Apply the auto-suggested patch for `issue_id`. Refuses if the
    rule has no template fix or the issue has no `suggested_fix`."""
    issue = get_issue(issue_id)
    if issue is None:
        return {"ok": False, "error": "unknown issue id (run /autopatch/scan first)"}
    if not issue.can_auto_fix or not issue.suggested_fix:
        history.record(
            "apply", actor, issue.id, issue.rule_id, issue.file, issue.line_number,
            "skipped", reason="no auto-fix available",
        )
        return {"ok": False, "error": "this issue has no template fix; use Manual Edit or LLM Suggest"}

    path = _resolve_safe_path(issue.file)
    if path is None:
        return {"ok": False, "error": f"refused — file is outside project root: {issue.file}"}

    try:
        original = path.read_text(encoding="utf-8")
        before_hash = _sha256(original)
        new_text, old_line = _swap_line(original, issue.line_number, issue.suggested_fix)
        after_hash = _sha256(new_text)
        if before_hash == after_hash:
            history.record(
                "apply", actor, issue.id, issue.rule_id, issue.file, issue.line_number,
                "skipped", reason="patch is identical to current file",
            )
            return {"ok": False, "error": "patch produces no change"}
        bak = _backup(path)
        path.write_text(new_text, encoding="utf-8")
        history.record(
            "apply", actor, issue.id, issue.rule_id, issue.file, issue.line_number,
            "ok",
            before_hash=before_hash, after_hash=after_hash,
            detail=f"backup={bak.name}",
        )
        # Force the next scan to re-read disk
        scan(force=True)
        return {
            "ok": True, "file": issue.file, "backup": bak.name,
            "before_hash": before_hash, "after_hash": after_hash,
            "before_line": old_line.rstrip("\n"),
            "after_line": issue.suggested_fix,
        }
    except Exception as exc:
        log.exception("[autopatch] apply failed")
        history.record(
            "apply", actor, issue.id, issue.rule_id, issue.file, issue.line_number,
            "failed", reason=str(exc),
        )
        return {"ok": False, "error": str(exc)}


def save_manual(issue_id: str, actor: str, new_line: str, reason: str = "") -> dict[str, Any]:
    """Replace the line with the admin's hand-written edit. Same safety
    contract as apply_patch (backup, hashes, audit)."""
    issue = get_issue(issue_id)
    if issue is None:
        return {"ok": False, "error": "unknown issue id"}
    if not new_line:
        return {"ok": False, "error": "empty manual edit"}
    path = _resolve_safe_path(issue.file)
    if path is None:
        return {"ok": False, "error": "refused — file outside project root"}
    try:
        original = path.read_text(encoding="utf-8")
        before_hash = _sha256(original)
        new_text, old_line = _swap_line(original, issue.line_number, new_line)
        after_hash = _sha256(new_text)
        if before_hash == after_hash:
            return {"ok": False, "error": "manual edit produces no change"}
        bak = _backup(path)
        path.write_text(new_text, encoding="utf-8")
        history.record(
            "manual", actor, issue.id, issue.rule_id, issue.file, issue.line_number,
            "ok",
            reason=reason, before_hash=before_hash, after_hash=after_hash,
            detail=f"backup={bak.name}",
        )
        scan(force=True)
        return {
            "ok": True, "file": issue.file, "backup": bak.name,
            "before_line": old_line.rstrip("\n"),
            "after_line": new_line.rstrip("\n"),
        }
    except Exception as exc:
        log.exception("[autopatch] manual save failed")
        history.record(
            "manual", actor, issue.id, issue.rule_id, issue.file, issue.line_number,
            "failed", reason=str(exc),
        )
        return {"ok": False, "error": str(exc)}


def reject_patch(issue_id: str, actor: str, reason: str) -> dict[str, Any]:
    """Mark an issue as deliberately ignored. No file is touched."""
    issue = get_issue(issue_id)
    if issue is None:
        return {"ok": False, "error": "unknown issue id"}
    history.record(
        "reject", actor, issue.id, issue.rule_id, issue.file, issue.line_number,
        "ok", reason=reason or "(no reason given)",
    )
    return {"ok": True, "issue_id": issue.id, "reason": reason}


def llm_suggest(issue_id: str, actor: str, extra_context: str = "") -> dict[str, Any]:
    """Ask the configured LLM (DeepSeek by default) for a one-line patch.

    Returned to the admin as *advice* — not auto-applied. The admin can
    then paste it into Manual Edit if they like it.
    """
    issue = get_issue(issue_id)
    if issue is None:
        return {"ok": False, "error": "unknown issue id"}
    rule = rule_for(issue)

    try:
        from husn.src import llm
    except Exception as e:
        return {"ok": False, "error": f"llm module unavailable: {e}"}
    if not llm.is_configured():
        return {"ok": False, "error": "LLM not configured (set HUSN_DEEPSEEK_KEY)"}

    # ---- Assemble rich context for the LLM --------------------------------
    # Three layers: project-level (what Husn is), file-level (header
    # docstring + imports), function-level (the enclosing block). The
    # tighter the picture, the less likely the LLM is to hallucinate a
    # fix that breaks invariants it can't see.
    path = _resolve_safe_path(issue.file)
    file_header = ""
    enclosing_block = ""
    flagged_indent = ""
    flagged_line_text = issue.line_content
    if path is not None:
        try:
            text = path.read_text(encoding="utf-8")
            lines = text.splitlines()
            file_header = _file_header(lines, max_lines=30)
            enclosing_block = _enclosing_function_block(lines, issue.line_number, padding=6)
            flagged_indent = _leading_whitespace(lines[issue.line_number - 1]) if 0 < issue.line_number <= len(lines) else ""
            flagged_line_text = lines[issue.line_number - 1] if 0 < issue.line_number <= len(lines) else issue.line_content
        except OSError:
            pass

    project_context = (
        "PROJECT: Husn (حصن) — production cyber-defense system for the "
        "DefensThon 2026 contest. The codebase has three processes: a "
        "FastAPI backend (this Python tree), a React/Vite frontend, and a "
        "deliberately-vulnerable target app for demos. Modules of note:\n"
        "  husn.src.ai           — XGBoost/IsolationForest/SHAP detector\n"
        "  husn.src.auth         — bcrypt + JWT users/login/rate-limit\n"
        "  husn.src.core         — DefenseResponse + iptables block_ip\n"
        "  husn.src.notify       — SMTP alerts + SHAP-inlined HTML emails\n"
        "  husn.src.sniffer      — live scapy packet capture\n"
        "  husn.src.autopatch    — this static-analyser/auto-fixer module\n"
        "Critical invariants you must NOT break:\n"
        "  * bcrypt password hashing in auth.users (never replace with sha/md5)\n"
        "  * JWT secret resolution + token verify path\n"
        "  * IP whitelist short-circuit in DefenseResponse.block_ip\n"
        "  * The 17 named features HusnAI consumes\n"
        "  * Rate-limit middleware on /auth/login\n"
    )

    system = (
        "You are a senior security engineer making a surgical patch in a "
        "production codebase. Your job is to produce a SAFE, MINIMAL "
        "ONE-LINE replacement for ONE flagged source line.\n\n"
        "ABSOLUTE RULES — violating any of these means you must reply "
        "with the literal string NEEDS_MULTI_LINE instead:\n"
        "  1. Reply with ONLY the new line of code. No markdown, no fenced\n"
        "     block, no commentary, no quotes around it.\n"
        "  2. Match the EXACT leading whitespace of the original line.\n"
        "  3. Do NOT add new imports — your line must work with what the\n"
        "     file already imports.\n"
        "  4. Do NOT change function/method signatures, return types, or\n"
        "     argument names of the line being patched.\n"
        "  5. Do NOT remove any security operation (bcrypt, JWT verify,\n"
        "     allowlist check, rate-limit decorator, CSRF token, etc).\n"
        "  6. Do NOT introduce a new dependency, library, or third-party\n"
        "     call that isn't already in the file.\n"
        "  7. Do NOT alter behaviour beyond what the rule requires. If\n"
        "     the rule says 'replace md5 with sha256', do exactly that —\n"
        "     do not also rename variables, change constants, or refactor.\n"
        "  8. If the flagged line is a continuation (open paren, backslash\n"
        "     continuation, multi-line string) → NEEDS_MULTI_LINE.\n"
        "  9. If you cannot tell what the surrounding code does, what the\n"
        "     function returns, or what callers depend on → NEEDS_MULTI_LINE.\n"
        " 10. If the fix risks breaking the project invariants listed in\n"
        "     PROJECT context → NEEDS_MULTI_LINE.\n"
        " 11. When in doubt, refuse with NEEDS_MULTI_LINE. A refusal is\n"
        "     ALWAYS safer than a guess. The admin can then handle it\n"
        "     manually.\n\n"
        "Treat this as a code review of YOUR OWN production system: every\n"
        "patch you suggest will be applied to a running server with one\n"
        "click. Be conservative."
    )

    user = (
        f"{project_context}\n\n"
        f"FILE: {issue.file}\n"
        f"FLAGGED LINE NUMBER: {issue.line_number}\n"
        f"RULE TRIPPED: {rule.id if rule else issue.rule_id} — {issue.rule_name}\n"
        f"SEVERITY: {issue.severity}\n"
        f"WHY THIS IS RISKY: {issue.description}\n"
        f"WHY THE SUGGESTED FIX STYLE IS SAFER: {issue.rationale}\n\n"
        f"FILE HEADER (docstring + imports — tells you what this file is for):\n"
        f"```\n{file_header or '(no header captured)'}\n```\n\n"
        f"ENCLOSING FUNCTION / BLOCK CONTAINING THE FLAGGED LINE:\n"
        f"```\n{enclosing_block or '(could not extract block)'}\n```\n\n"
        f"FLAGGED LINE (line {issue.line_number}, leading whitespace = {len(flagged_indent)} chars):\n"
        f"{flagged_line_text}\n\n"
        f"ADMIN'S EXTRA CONTEXT: {extra_context or '(none)'}\n\n"
        f"Reply now with ONLY the replacement line, preserving the leading "
        f"whitespace exactly. Or reply NEEDS_MULTI_LINE."
    )

    result = llm.complete(system=system, messages=[{"role": "user", "content": user}],
                          temperature_override=0.1, max_tokens_override=384)

    history.record(
        "llm-suggest", actor, issue.id, issue.rule_id, issue.file, issue.line_number,
        "ok" if result.get("ok") else "failed",
        detail=(result.get("reply") or result.get("error") or "")[:200],
    )

    if not result.get("ok"):
        return {"ok": False, "error": result.get("error") or "llm failed"}

    reply = (result.get("reply") or "").strip()
    if reply.upper().startswith("NEEDS_MULTI_LINE"):
        return {"ok": False, "error": "LLM says a one-line fix isn't possible — open Manual Edit."}
    # Strip accidental markdown / quotes from the LLM
    if reply.startswith("```"):
        reply = "\n".join(reply.splitlines()[1:-1]) if reply.count("\n") >= 2 else reply.strip("`")
    return {"ok": True, "suggestion": reply, "model": result.get("model")}
