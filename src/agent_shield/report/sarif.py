"""SARIF 2.1.0 output for GitHub code scanning."""

from __future__ import annotations

from .. import __version__
from ..models import ScanResult, Severity

LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
# GitHub uses security-severity (0-10) to bucket alerts as critical/high/medium/low.
SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "1.0",
}


def to_sarif(result: ScanResult, uri_prefix: str = "") -> dict:
    rules: dict[str, dict] = {}
    results = []
    for f in result.findings:
        if f.rule_id not in rules:
            rules[f.rule_id] = {
                "id": f.rule_id,
                "name": f.title.replace(" ", ""),
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.message or f.title},
                "help": {"text": f.message or f.title},
                "defaultConfiguration": {"level": LEVEL[f.severity]},
                "properties": {
                    "tags": ["security", f.category, f.kind],
                    "security-severity": SECURITY_SEVERITY[f.severity],
                },
            }
        props = {"category": f.category, "artifactKind": f.kind, "severity": f.severity.label}
        if f.judge:
            props["judge"] = f.judge
        if f.original_severity is not None:
            props["originalSeverity"] = f.original_severity.label
        results.append({
            "ruleId": f.rule_id,
            "level": LEVEL[f.severity],
            "message": {"text": f"{f.title}: {f.message}"[:1000]},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": (uri_prefix + f.file).replace("\\", "/")},
                    "region": {"startLine": max(1, f.line)},
                }
            }],
            "partialFingerprints": {"agentShield/v1": f"{f.rule_id}:{f.file}:{f.snippet[:80]}"},
            "properties": props,
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "agent-shield",
                "version": __version__,
                "informationUri": "https://github.com/eyad/agent-shield",
                "rules": list(rules.values()),
            }},
            "results": results,
            "properties": {"score": result.score, "verdict": result.verdict, "kinds": result.kinds},
        }],
    }
