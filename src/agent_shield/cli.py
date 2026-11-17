"""agent-shield command line."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .models import Severity


def _make_judge(args):
    if not args.judge:
        return None
    from .judge import OllamaJudge

    judge = OllamaJudge(model=args.judge_model)
    if not judge.available():
        print(f"[agent-shield] LLM judge unavailable (model {args.judge_model!r} not served by Ollama); "
              "continuing with static rules only.", file=sys.stderr)
        return None
    return judge


def cmd_scan(args) -> int:
    from .report.html import to_html
    from .report.sarif import to_sarif
    from .rules_engine import load_rules
    from .scanner import scan

    rules = load_rules(Path(args.rules) if args.rules else None)
    result = scan(args.path, rules=rules, judge=_make_judge(args))
    min_sev = Severity.parse(args.min_severity)
    result.findings = [f for f in result.findings if f.severity >= min_sev]

    formats = {f.strip() for f in args.format.split(",") if f.strip()}
    out = Path(args.out)
    if formats - {"text"}:
        out.mkdir(parents=True, exist_ok=True)
    if "html" in formats:
        (out / "agent-shield.html").write_text(to_html(result), "utf-8")
    if "sarif" in formats:
        (out / "agent-shield.sarif").write_text(json.dumps(to_sarif(result, args.uri_prefix), indent=2), "utf-8")
    if "json" in formats:
        (out / "agent-shield.json").write_text(json.dumps(result.to_dict(), indent=2), "utf-8")

    _print_summary(result, verbose=args.verbose)
    if formats - {"text"}:
        print(f"reports written to {out}/")
    fail_on = {"block": {"block"}, "warn": {"block", "warn"}, "never": set()}[args.fail_on]
    return 1 if result.verdict in fail_on else 0


def _print_summary(result, verbose: bool = False) -> None:
    colors = {"critical": "\033[31m", "high": "\033[33m", "medium": "\033[35m", "low": "\033[36m", "info": ""}
    reset = "\033[0m" if sys.stdout.isatty() else ""
    if not sys.stdout.isatty():
        colors = {k: "" for k in colors}
    print(f"agent-shield {__version__}  {result.root}")
    print(f"  kinds: {', '.join(result.kinds) or 'none'}   files: {result.files_scanned}   "
          f"judge: {'on' if result.judge_used else 'off'}")
    print(f"  score: {result.score}/100   verdict: {result.verdict.upper()}   "
          + "  ".join(f"{k}={v}" for k, v in result.counts().items() if v))
    shown = result.findings if verbose else [f for f in result.findings if f.severity >= Severity.MEDIUM]
    for f in shown[:200]:
        c = colors[f.severity.label]
        extra = ""
        if f.judge and "verdict" in f.judge:
            extra = f"  [judge: {f.judge['verdict']} {f.judge['confidence']:.2f}]"
        print(f"  {c}{f.severity.label.upper():8}{reset} {f.rule_id:9} {f.file}:{f.line}  {f.title}{extra}")
    hidden = len(result.findings) - len(shown)
    if hidden > 0:
        print(f"  (+{hidden} low/info findings; use -v to show)")
    for e in result.errors:
        print(f"  note: {e}")


def cmd_rules(args) -> int:
    from .rules_engine import load_rules

    for r in load_rules(Path(args.rules) if args.rules else None):
        amb = " (ambiguous -> judge)" if r.ambiguous else ""
        print(f"{r.id:7} {r.severity.label:8} {','.join(sorted(r.kinds)):24} {r.title}{amb}")
    return 0


def cmd_eval(args) -> int:
    from .evaluate import run_eval

    return run_eval(Path(args.corpus), Path(args.out), use_judge=args.judge, judge_model=args.judge_model,
                    ablation=args.ablation)


def cmd_harness(args) -> int:
    from .harness.runner import run_harness

    return run_harness(agent=args.agent, cases_path=Path(args.cases) if args.cases else None,
                       out_dir=Path(args.out), model=args.model, sandbox=not args.no_sandbox,
                       limit=args.limit)


def build_parser() -> argparse.ArgumentParser:
    from .judge import DEFAULT_MODEL

    p = argparse.ArgumentParser(prog="agent-shield", description="Scan AI artifacts before you install or run them.")
    p.add_argument("--version", action="version", version=f"agent-shield {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="scan a skill, MCP server, agent config or model directory/file")
    s.add_argument("path")
    s.add_argument("--format", default="text,html,sarif", help="comma list of text,html,sarif,json")
    s.add_argument("--out", default="agent-shield-report", help="output directory for report files")
    s.add_argument("--judge", action="store_true", help="send ambiguous findings to the local Ollama judge")
    s.add_argument("--judge-model", default=DEFAULT_MODEL)
    s.add_argument("--rules", help="custom YAML rule file (replaces the default rules)")
    s.add_argument("--min-severity", default="info", choices=[x.label for x in Severity])
    s.add_argument("--fail-on", default="block", choices=["block", "warn", "never"],
                   help="exit 1 when the verdict reaches this level (default: block)")
    s.add_argument("--uri-prefix", default="", help="prefix for SARIF file URIs (path of the target in the repo)")
    s.add_argument("-v", "--verbose", action="store_true")
    s.set_defaults(func=cmd_scan)

    r = sub.add_parser("rules", help="list the loaded rules")
    r.add_argument("--rules")
    r.set_defaults(func=cmd_rules)

    e = sub.add_parser("eval", help="measure precision/recall on the labelled corpus")
    e.add_argument("--corpus", default="corpus")
    e.add_argument("--out", default="reports/eval.md")
    e.add_argument("--judge", action="store_true")
    e.add_argument("--judge-model", default=DEFAULT_MODEL)
    e.add_argument("--ablation", action="store_true", help="also run the judge with hardening disabled")
    e.set_defaults(func=cmd_eval)

    h = sub.add_parser("harness", help="run an agent against prompt-injection cases with mock tools")
    h.add_argument("--agent", default="ollama",
                   help="ollama | naive | guarded | cmd:<command> (external agent speaking the JSONL protocol)")
    h.add_argument("--model", default=DEFAULT_MODEL)
    h.add_argument("--cases", help="YAML file of injection cases (default: built-in set)")
    h.add_argument("--out", default="reports")
    h.add_argument("--limit", type=int, default=0)
    h.add_argument("--no-sandbox", action="store_true", help="do not wrap cmd: agents in sandbox-exec")
    h.set_defaults(func=cmd_harness)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except FileNotFoundError as exc:
        print(f"agent-shield: not found: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
