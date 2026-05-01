"""Auto Patch rule library.

Each rule has:
  id              stable kebab-case identifier (used in audit log)
  name            human-readable vulnerability name
  description     1-line explanation
  severity        Critical | High | Medium | Low
  confidence      0.0-1.0 — pattern-based, so high is fine for unambiguous matches
  pattern         compiled regex matched against each LINE of code
  applies_to      tuple of file extensions where this rule is meaningful
  suggest_fix     callable(line: str, match: re.Match) -> str | None
                  returns the replacement line, or None if a safe template
                  fix isn't possible (caller should fall back to LLM)
  rationale       why the suggested fix is safer (shown in the diff dialog)

Adding a rule is a 6-line append to RULES below. Keep patterns tight —
loose patterns produce false positives that destroy admin trust.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Optional, Sequence


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    description: str
    severity: str            # Critical / High / Medium / Low
    confidence: float        # 0.0 - 1.0
    pattern: re.Pattern
    applies_to: tuple[str, ...]
    suggest_fix: Optional[Callable[[str, re.Match], Optional[str]]]
    rationale: str


# ───────────── Patch helpers ─────────────────────────────────────────

def _comment_out(line: str, _m: re.Match) -> str:
    """Drop the dangerous line into a comment with a TODO marker."""
    return f"# AUTOPATCH-TODO ({_m.re.pattern!r}): {line.rstrip()}\n"


def _python_eval_to_literal(line: str, m: re.Match) -> str:
    # eval(x) → ast.literal_eval(x) — safe for literals, raises on code.
    return line[:m.start()] + line[m.start():].replace("eval(", "__import__('ast').literal_eval(", 1)


def _python_pickle_to_json(line: str, m: re.Match) -> Optional[str]:
    # pickle.loads(...) → json.loads(...). Only safe if payload is JSON;
    # leave a TODO so the admin verifies the data shape.
    if "pickle.loads" not in line:
        return None
    return line.replace("pickle.loads(", "__import__('json').loads(") + "  # AUTOPATCH-NOTE: verify payload was JSON not pickle\n".rstrip("\n") + "\n"


def _python_random_to_secrets(line: str, m: re.Match) -> str:
    # random.random() → secrets.SystemRandom().random()
    return line.replace("random.random(", "__import__('secrets').SystemRandom().random(")


def _python_md5_to_sha256(line: str, m: re.Match) -> str:
    return line.replace("hashlib.md5(", "hashlib.sha256(").replace(".md5(", ".sha256(")


def _subprocess_shell_true(line: str, m: re.Match) -> str:
    # shell=True is the dangerous flag. Flip to shell=False — the admin
    # may still need to switch from a string command to a list arg.
    return re.sub(r"shell\s*=\s*True", "shell=False", line) + (
        "" if "AUTOPATCH-NOTE" in line else "  # AUTOPATCH-NOTE: ensure args is a list\n".rstrip("\n") + "\n"
    )


def _yaml_permissive_cors(line: str, m: re.Match) -> str:
    # allow_origins: ["*"] → leave a placeholder list
    return re.sub(r'\["\*"\]|- ["\']\*["\']', '["https://your-domain.example"]  # AUTOPATCH-NOTE: replace with real origins', line)


def _ts_eval(line: str, m: re.Match) -> str:
    # JavaScript eval(x) → JSON.parse(x). Comment out as fallback.
    return line.replace("eval(", "JSON.parse(") + "  // AUTOPATCH-NOTE: only safe if input is JSON\n".rstrip("\n") + "\n"


def _ts_innerhtml(line: str, m: re.Match) -> str:
    return line.replace(".innerHTML", ".textContent")


def _python_open_user_path(line: str, m: re.Match) -> Optional[str]:
    # We can't auto-fix this safely — leave a marker.
    return None


def _hardcoded_secret(line: str, m: re.Match) -> Optional[str]:
    # We can't guess the env-var name; leave a marker that the admin fills in.
    var = (m.group(1) or "SECRET").upper()
    return f"# AUTOPATCH-TODO move secret to env var. Old line below:\n# {line.rstrip()}\n{var.lower()} = __import__('os').environ['{var}']\n"


# ───────────── The rule library ──────────────────────────────────────

RULES: Sequence[Rule] = (

    # ---- Python: eval / exec -------------------------------------------------
    Rule(
        id="py-eval",
        name="Use of eval() in Python",
        description="`eval()` runs arbitrary Python — never use it on input you don't fully trust.",
        severity="Critical", confidence=0.97,
        pattern=re.compile(r"(?<!\.)\beval\s*\("),
        applies_to=(".py",),
        suggest_fix=_python_eval_to_literal,
        rationale="`ast.literal_eval` only parses literals (str / int / dict / list / tuple) — it cannot execute code, removing the RCE risk.",
    ),
    Rule(
        id="py-exec",
        name="Use of exec() in Python",
        description="`exec()` runs arbitrary Python statements.",
        severity="Critical", confidence=0.96,
        pattern=re.compile(r"(?<!\.)\bexec\s*\("),
        applies_to=(".py",),
        suggest_fix=_comment_out,
        rationale="`exec()` has no safe equivalent — comment out and design an explicit state-machine instead.",
    ),

    # ---- Python: pickle ----------------------------------------------------
    Rule(
        id="py-pickle-loads",
        name="Insecure deserialization via pickle.loads",
        description="`pickle.loads` on untrusted input is RCE. Use `json.loads` for cross-system data.",
        severity="Critical", confidence=0.95,
        pattern=re.compile(r"\bpickle\.loads\s*\("),
        applies_to=(".py",),
        suggest_fix=_python_pickle_to_json,
        rationale="`json.loads` only parses JSON values — no class instantiation, no `__reduce__` callbacks, no RCE.",
    ),

    # ---- Python: subprocess shell=True --------------------------------------
    Rule(
        id="py-subprocess-shell",
        name="subprocess() with shell=True",
        description="Shell-mode subprocess calls invite command injection.",
        severity="High", confidence=0.92,
        pattern=re.compile(r"subprocess\.[A-Za-z_]+\s*\([^)]*shell\s*=\s*True"),
        applies_to=(".py",),
        suggest_fix=_subprocess_shell_true,
        rationale="`shell=False` (the default) prevents a `;` or `&&` in any argument from escaping into shell metacharacters.",
    ),

    # ---- Python: weak crypto ------------------------------------------------
    Rule(
        id="py-md5",
        name="Weak hash (MD5)",
        description="MD5 is broken — use SHA-256+ for any security-sensitive hashing.",
        severity="Medium", confidence=0.95,
        pattern=re.compile(r"\bhashlib\.md5\s*\(|\bmd5\s*\("),
        applies_to=(".py",),
        suggest_fix=_python_md5_to_sha256,
        rationale="SHA-256 has no known practical collisions; same API in `hashlib`.",
    ),
    Rule(
        id="py-random-secrets",
        name="random.random() in security context",
        description="`random.random()` is predictable — use `secrets` for tokens / nonces / keys.",
        severity="High", confidence=0.85,
        pattern=re.compile(r"\brandom\.random\s*\("),
        applies_to=(".py",),
        suggest_fix=_python_random_to_secrets,
        rationale="`secrets.SystemRandom()` reads from `/dev/urandom` — cryptographically strong.",
    ),

    # ---- Python: hardcoded secrets ------------------------------------------
    Rule(
        id="py-hardcoded-secret",
        name="Possible hardcoded secret",
        description="An API key or password literal in source code.",
        severity="High", confidence=0.80,
        pattern=re.compile(
            r'^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*[\'"]'
            r'(sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|xoxb-[A-Za-z0-9-]{20,})'
            r'[\'"]'
        ),
        applies_to=(".py", ".js", ".ts", ".tsx", ".yaml", ".yml", ".sh"),
        suggest_fix=_hardcoded_secret,
        rationale="Secrets in code leak via git history. Read from environment so deployments rotate cleanly.",
    ),

    # ---- Python: SQL string formatting --------------------------------------
    Rule(
        id="py-sql-fstring",
        name="SQL built with f-string",
        description="`f\"SELECT ... WHERE id={uid}\"` is SQL injection bait.",
        severity="Critical", confidence=0.88,
        pattern=re.compile(r'f["\'].*\b(SELECT|INSERT|UPDATE|DELETE|DROP)\b.*\{.*\}.*["\']', re.IGNORECASE),
        applies_to=(".py",),
        suggest_fix=None,  # Too contextual — punt to LLM
        rationale="Use parameterised queries (`cursor.execute(\"... WHERE id=%s\", (uid,))`) so user input can never escape the value position.",
    ),

    # ---- Python / FastAPI: open CORS ----------------------------------------
    Rule(
        id="py-cors-wildcard",
        name="Permissive CORS (allow_origins=['*'])",
        description="A `*` wildcard with credentials lets any site read your authenticated responses.",
        severity="High", confidence=0.95,
        pattern=re.compile(r'allow_origins\s*=\s*\[\s*[\'"]\*[\'"]\s*\]'),
        applies_to=(".py",),
        suggest_fix=lambda line, m: line.replace('["*"]', '["https://your-domain.example"]  # AUTOPATCH-NOTE: replace with real origins').replace("['*']", "['https://your-domain.example']"),
        rationale="Restrict to the actual front-end origins — wildcard CORS is fine for public APIs without cookies, but Husn uses bearer tokens.",
    ),

    # ---- YAML: insecure config flags ----------------------------------------
    Rule(
        id="yaml-debug-true",
        name="Debug mode enabled in config",
        description="`debug: true` in production exposes stack traces and source.",
        severity="Medium", confidence=0.90,
        pattern=re.compile(r'^\s*debug\s*:\s*true\s*$', re.IGNORECASE),
        applies_to=(".yaml", ".yml"),
        suggest_fix=lambda line, m: re.sub(r'true', 'false', line, count=1, flags=re.IGNORECASE),
        rationale="Production should never run with `debug: true`. Use a separate dev override file.",
    ),
    Rule(
        id="yaml-cors-wildcard",
        name="Wildcard CORS in YAML config",
        description="`allowed_origins: ['*']` lets any site call this API.",
        severity="High", confidence=0.93,
        pattern=re.compile(r'(allow|allowed)_origins\s*:\s*(\[\s*[\'"]?\*[\'"]?\s*\]|\*)', re.IGNORECASE),
        applies_to=(".yaml", ".yml"),
        suggest_fix=_yaml_permissive_cors,
        rationale="See py-cors-wildcard.",
    ),

    # ---- TypeScript / JavaScript: eval --------------------------------------
    Rule(
        id="ts-eval",
        name="Use of eval() in JavaScript",
        description="`eval()` runs arbitrary JS — same RCE risk as Python's.",
        severity="Critical", confidence=0.96,
        pattern=re.compile(r"(?<![\w.])eval\s*\("),
        applies_to=(".js", ".ts", ".tsx"),
        suggest_fix=_ts_eval,
        rationale="If parsing a JSON string, use `JSON.parse`. If you need dynamic code, redesign — there's no safe `eval` shim.",
    ),

    # ---- TypeScript / JavaScript: innerHTML XSS sink ------------------------
    Rule(
        id="ts-innerhtml",
        name=".innerHTML assignment (XSS sink)",
        description="Assigning to `.innerHTML` lets any HTML in the value execute.",
        severity="High", confidence=0.85,
        pattern=re.compile(r"\.innerHTML\s*="),
        applies_to=(".js", ".ts", ".tsx"),
        suggest_fix=_ts_innerhtml,
        rationale="`.textContent` HTML-escapes the value — XSS-safe. Use a sanitizer (DOMPurify) only if you genuinely need HTML.",
    ),
)


def by_id(rule_id: str) -> Optional[Rule]:
    for r in RULES:
        if r.id == rule_id:
            return r
    return None


def all_ids() -> list[str]:
    return [r.id for r in RULES]
