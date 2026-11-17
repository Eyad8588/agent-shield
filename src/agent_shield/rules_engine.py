"""Load the YAML rule set and apply regex rules to discovered files."""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path

import yaml

from .discovery import ScanFile
from .models import Finding, Severity

MAX_MATCHES_PER_RULE_PER_FILE = 5
VALID_KINDS = {"skill", "mcp", "agent_config", "model", "any"}


@dataclass
class Rule:
    id: str
    title: str
    severity: Severity
    category: str
    kinds: set[str]
    pattern: re.Pattern
    files: list[str] = field(default_factory=lambda: ["*"])
    exclude: re.Pattern | None = None
    ambiguous: bool = False
    help: str = ""

    def applies_to(self, f: ScanFile) -> bool:
        if not f.is_text:
            return False
        if "any" not in self.kinds and not (self.kinds & f.kinds):
            return False
        return any(fnmatch.fnmatch(f.path.name, g) for g in self.files)


def load_rules(path: Path | None = None) -> list[Rule]:
    if path is None:
        text = resources.files("agent_shield").joinpath("rules/default.yaml").read_text("utf-8")
    else:
        text = Path(path).read_text("utf-8")
    data = yaml.safe_load(text) or {}
    rules: list[Rule] = []
    seen: set[str] = set()
    for raw in data.get("rules", []):
        rid = raw["id"]
        if rid in seen:
            raise ValueError(f"duplicate rule id {rid}")
        seen.add(rid)
        kinds = set(raw.get("kinds", ["any"]))
        if not kinds <= VALID_KINDS:
            raise ValueError(f"rule {rid}: unknown kinds {kinds - VALID_KINDS}")
        rules.append(
            Rule(
                id=rid,
                title=raw["title"],
                severity=Severity.parse(raw["severity"]),
                category=raw.get("category", "general"),
                kinds=kinds,
                pattern=re.compile(raw["pattern"], re.MULTILINE),
                files=raw.get("files", ["*"]),
                exclude=re.compile(raw["exclude"]) if raw.get("exclude") else None,
                ambiguous=bool(raw.get("ambiguous", False)),
                help=raw.get("help", ""),
            )
        )
    return rules


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _line_text(text: str, offset: int) -> str:
    start = text.rfind("\n", 0, offset) + 1
    end = text.find("\n", offset)
    return text[start : end if end != -1 else len(text)]


def snippet_around(text: str, start: int, end: int, pad: int = 80) -> str:
    s = max(0, start - pad)
    e = min(len(text), end + pad)
    return text[s:e].strip()


def apply_rules(rules: list[Rule], files: list[ScanFile]) -> list[Finding]:
    findings: list[Finding] = []
    for f in files:
        applicable = [r for r in rules if r.applies_to(f)]
        if not applicable:
            continue
        text = f.text()
        for rule in applicable:
            n = 0
            for m in rule.pattern.finditer(text):
                if rule.exclude and rule.exclude.search(_line_text(text, m.start())):
                    continue
                kind = next(iter(sorted(rule.kinds & f.kinds)), "any")
                findings.append(
                    Finding(
                        rule_id=rule.id,
                        title=rule.title,
                        severity=rule.severity,
                        category=rule.category,
                        file=f.rel,
                        line=_line_of(text, m.start()),
                        message=rule.help,
                        snippet=snippet_around(text, m.start(), m.end())[:400],
                        kind=kind,
                        ambiguous=rule.ambiguous,
                    )
                )
                n += 1
                if n >= MAX_MATCHES_PER_RULE_PER_FILE:
                    break
    return findings
