"""Auto Patch — static analysis + assisted remediation.

Architecture:
  scanner   walks files, runs `rules` against each line/block, returns Issues.
  rules     declarative library of patterns + suggested-fix templates.
  engine    apply / reject / save manual edit, with on-disk backup.
  history   YAML-backed audit log of every action (admin, ts, file, hashes).

The XGBoost AI in Husn analyses *network packets*, not source code, so we
do **not** pretend it's the source-code auditor. Auto Patch uses honest
rule-based pattern matching (the same approach Bandit/Semgrep use) plus
optional LLM polish (DeepSeek via husn.src.llm) for complex cases.
"""
from .scanner   import scan, list_issues, get_issue
from .engine    import apply_patch, reject_patch, save_manual, llm_suggest
from .history   import recent as history_recent, count as history_count
from . import backups

__all__ = [
    "scan", "list_issues", "get_issue",
    "apply_patch", "reject_patch", "save_manual", "llm_suggest",
    "history_recent", "history_count",
    "backups",
]
