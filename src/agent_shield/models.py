"""Core data types shared by scanners, the judge and the reporters."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str | int | "Severity") -> "Severity":
        if isinstance(value, Severity):
            return value
        if isinstance(value, int):
            return cls(value)
        return cls[value.strip().upper()]

    @property
    def label(self) -> str:
        return self.name.lower()


# Score penalty per finding, by severity. Capped per rule so one noisy rule
# cannot dominate the score on its own.
PENALTY = {
    Severity.INFO: 0,
    Severity.LOW: 2,
    Severity.MEDIUM: 8,
    Severity.HIGH: 20,
    Severity.CRITICAL: 40,
}


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    category: str
    file: str  # path relative to the scan root
    line: int = 1
    message: str = ""
    snippet: str = ""
    kind: str = "any"  # skill | mcp | agent_config | model | any
    ambiguous: bool = False  # eligible for LLM-judge review
    judge: dict | None = None  # verdict from the LLM judge, if consulted
    original_severity: Severity | None = None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.label
        d["original_severity"] = (
            self.original_severity.label if self.original_severity is not None else None
        )
        return d


@dataclass
class ScanResult:
    root: str
    kinds: list[str]
    files_scanned: int
    findings: list[Finding] = field(default_factory=list)
    judge_used: bool = False
    errors: list[str] = field(default_factory=list)

    @property
    def score(self) -> int:
        penalty_by_rule: dict[str, int] = {}
        for f in self.findings:
            penalty_by_rule[f.rule_id] = penalty_by_rule.get(f.rule_id, 0) + PENALTY[f.severity]
        total = sum(min(p, 60) for p in penalty_by_rule.values())
        return max(0, 100 - total)

    @property
    def max_severity(self) -> Severity | None:
        return max((f.severity for f in self.findings), default=None)

    @property
    def verdict(self) -> str:
        """block / warn / pass.

        block: any critical finding, any high finding, or score < 50
        warn:  any medium finding or score < 85
        pass:  otherwise
        """
        top = self.max_severity
        if top is not None and top >= Severity.HIGH:
            return "block"
        if self.score < 50:
            return "block"
        if (top is not None and top >= Severity.MEDIUM) or self.score < 85:
            return "warn"
        return "pass"

    def counts(self) -> dict[str, int]:
        out = {s.label: 0 for s in sorted(Severity, reverse=True)}
        for f in self.findings:
            out[f.severity.label] += 1
        return out

    def to_dict(self) -> dict:
        return {
            "root": self.root,
            "kinds": self.kinds,
            "files_scanned": self.files_scanned,
            "score": self.score,
            "verdict": self.verdict,
            "counts": self.counts(),
            "judge_used": self.judge_used,
            "errors": self.errors,
            "findings": [f.to_dict() for f in self.findings],
        }
