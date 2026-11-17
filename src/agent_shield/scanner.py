"""Scan orchestration: discovery -> YAML rules -> structural checks -> optional judge."""

from __future__ import annotations

from pathlib import Path

from .checks import check_agent_configs, check_mcp, check_model_files, check_unicode
from .discovery import discover
from .models import ScanResult
from .rules_engine import Rule, apply_rules, load_rules

_SORT = lambda f: (-int(f.severity), f.file, f.line, f.rule_id)  # noqa: E731


def scan(path: str | Path, rules: list[Rule] | None = None, judge=None) -> ScanResult:
    root = Path(path)
    if not root.exists():
        raise FileNotFoundError(path)
    rules = rules if rules is not None else load_rules()
    files = discover(root)

    findings = apply_rules(rules, files)
    findings += check_unicode(files)
    findings += check_mcp(files)
    findings += check_agent_configs(files)
    findings += check_model_files(files)

    # de-duplicate identical rule hits on the same line
    seen: set[tuple] = set()
    unique = []
    for f in findings:
        key = (f.rule_id, f.file, f.line)
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)

    kinds = sorted({k for f in files for k in f.kinds} - {"other"})
    result = ScanResult(root=str(root), kinds=kinds, files_scanned=len(files), findings=unique)

    if judge is not None and any(f.ambiguous for f in unique):
        from .judge import apply_judge

        texts = {f.rel: f.text() for f in files if f.is_text}
        apply_judge(unique, texts, judge)
        result.judge_used = True
        if judge.stats.errors:
            result.errors.append(f"judge: {judge.stats.errors} call(s) failed; static severity kept")

    result.findings.sort(key=_SORT)
    return result
