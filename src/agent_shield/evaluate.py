"""Precision / recall on the labelled corpus.

Each direct sub-directory of corpus/malicious and corpus/clean is one sample.
A sample counts as *flagged* when its scan verdict is `block`.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path

from .models import ScanResult
from .rules_engine import load_rules
from .scanner import scan

KIND_PREFIX = {"skill": "skill", "mcp": "mcp", "agent": "agent config", "model": "model file"}


@dataclass
class SampleResult:
    name: str
    label: str  # malicious | clean
    kind: str
    result: ScanResult
    seconds: float

    @property
    def flagged(self) -> bool:
        return self.result.verdict == "block"


def _kind(name: str) -> str:
    return KIND_PREFIX.get(name.split("-")[0], "other")


def run_samples(corpus: Path, judge=None) -> list[SampleResult]:
    rules = load_rules()
    out = []
    for label in ("malicious", "clean"):
        for d in sorted(p for p in (corpus / label).iterdir() if p.is_dir()):
            t0 = time.perf_counter()
            res = scan(d, rules=rules, judge=judge)
            out.append(SampleResult(d.name, label, _kind(d.name), res, time.perf_counter() - t0))
    return out


def metrics(samples: list[SampleResult]) -> dict:
    tp = sum(s.flagged and s.label == "malicious" for s in samples)
    fp = sum(s.flagged and s.label == "clean" for s in samples)
    fn = sum(not s.flagged and s.label == "malicious" for s in samples)
    tn = sum(not s.flagged and s.label == "clean" for s in samples)
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": precision, "recall": recall, "f1": f1}


def _metrics_table(rows: list[tuple[str, dict]]) -> str:
    lines = ["| Set | TP | FP | FN | TN | Precision | Recall | F1 |", "|---|---:|---:|---:|---:|---:|---:|---:|"]
    for name, m in rows:
        lines.append(f"| {name} | {m['tp']} | {m['fp']} | {m['fn']} | {m['tn']} | "
                     f"{m['precision']:.2f} | {m['recall']:.2f} | {m['f1']:.2f} |")
    return "\n".join(lines)


def _sample_table(samples: list[SampleResult], judged: list[SampleResult] | None) -> str:
    head = "| Sample | Label | Kind | Static verdict | Score | Key rules |"
    sep = "|---|---|---|---|---:|---|"
    if judged:
        head = "| Sample | Label | Kind | Static verdict | Score | With judge | Key rules |"
        sep = "|---|---|---|---|---:|---|---|"
    lines = [head, sep]
    jmap = {s.name: s for s in judged or []}
    for s in samples:
        top = []
        for f in s.result.findings:
            if f.rule_id not in top and f.severity >= 2:
                top.append(f.rule_id)
        ok = "ok" if s.flagged == (s.label == "malicious") else "**miss**"
        verdict = f"{s.result.verdict} ({ok})"
        cols = [s.name, s.label, s.kind, verdict, str(s.result.score)]
        if judged:
            j = jmap[s.name]
            jok = "ok" if j.flagged == (j.label == "malicious") else "**miss**"
            cols.append(f"{j.result.verdict} ({jok})")
        cols.append(", ".join(top[:6]) or "-")
        lines.append("| " + " | ".join(cols) + " |")
    return "\n".join(lines)


def _by_kind(samples: list[SampleResult]) -> list[tuple[str, dict]]:
    kinds = sorted({s.kind for s in samples})
    return [(k, metrics([s for s in samples if s.kind == k])) for k in kinds]


def judge_finding_stats(samples: list[SampleResult]) -> dict:
    """Finding-level view of the judge: downgrades on malicious samples are errors."""
    st = {"mal_reviewed": 0, "mal_downgraded": 0, "clean_reviewed": 0, "clean_downgraded": 0}
    for s in samples:
        for f in s.result.findings:
            if not (f.judge and "verdict" in f.judge):
                continue
            side = "mal" if s.label == "malicious" else "clean"
            st[f"{side}_reviewed"] += 1
            if f.original_severity is not None and f.severity < f.original_severity:
                st[f"{side}_downgraded"] += 1
    return st


def _judge_stats_table(rows: list[tuple[str, dict]]) -> str:
    lines = ["| Judge | Ambiguous findings on malicious samples | Wrongly downgraded | "
             "Ambiguous findings on clean samples | Correctly downgraded |", "|---|---:|---:|---:|---:|"]
    for name, st in rows:
        lines.append(f"| {name} | {st['mal_reviewed']} | {st['mal_downgraded']} | "
                     f"{st['clean_reviewed']} | {st['clean_downgraded']} |")
    return "\n".join(lines)


def render_report(static: list[SampleResult], judged: list[SampleResult] | None, judge_info: str,
                  ablation: list[SampleResult] | None = None) -> str:
    ms = metrics(static)
    n_mal = sum(s.label == "malicious" for s in static)
    n_clean = len(static) - n_mal
    parts = [
        "# Agent Shield evaluation",
        "",
        "Generated by `agent-shield eval`. Each sub-directory of `corpus/malicious` and `corpus/clean` is one "
        "sample; a sample is **flagged** when its verdict is `block` (any high/critical finding or score < 50).",
        "",
        f"Corpus: **{n_mal} malicious** (inert stubs) and **{n_clean} clean** samples across skills, MCP servers, "
        "agent configs and model files.",
        "",
        "## Overall",
        "",
    ]
    rows = [("Static rules only", ms)]
    if ablation:
        rows.append(("Static + judge, hardening OFF (ablation)", metrics(ablation)))
    if judged:
        rows.append((f"Static + LLM judge, hardened ({judge_info})", metrics(judged)))
    parts += [_metrics_table(rows), ""]
    if judged:
        jrows = []
        if ablation:
            jrows.append(("hardening off", judge_finding_stats(ablation)))
        jrows.append(("hardened", judge_finding_stats(judged)))
        parts += ["## Judge quality (finding level)", "",
                  "Sample-level numbers hide judge mistakes when a malicious sample has other non-ambiguous "
                  "findings. This table counts every finding the judge reviewed.", "",
                  _judge_stats_table(jrows), "",
                  "Hardening that matters here: artifacts often describe themselves as safe (\"inert test sample\", "
                  "\"for documentation only\"). The 4B judge took those self-descriptions as evidence and "
                  "downgraded real findings. The hardened judge redacts self-attestation before the model sees "
                  "the data and refuses any downgrade when such a claim is present. See `judge.py` for the full "
                  "list of measures (nonce-delimited data, structured output, fail-closed, anti-judge regex, "
                  "least authority).", ""]
    parts += ["## By artifact kind (static rules)", "", _metrics_table(_by_kind(static)), ""]
    if judged:
        parts += ["## By artifact kind (static + judge)", "", _metrics_table(_by_kind(judged)), ""]
        changed = []
        for s in judged:
            for f in s.result.findings:
                if f.judge and "verdict" in f.judge:
                    orig = f.original_severity.label if f.original_severity is not None else f.severity.label
                    changed.append(f"| {s.name} | {f.rule_id} | {orig} -> {f.severity.label} | "
                                   f"{f.judge['verdict']} ({f.judge['confidence']:.2f}) | "
                                   f"{f.judge.get('reason', '').replace('|', '/')[:140]} |")
        parts += ["## Judge decisions", "",
                  "Only findings from rules marked `ambiguous` are sent to the judge. "
                  "Benign verdicts with confidence >= 0.7 downgrade the finding to `low`; nothing is deleted.", "",
                  "| Sample | Rule | Severity | Verdict | Reason |", "|---|---|---|---|---|", *changed, ""]
        t_static = sum(s.seconds for s in static)
        t_judge = sum(s.seconds for s in judged)
        parts += [f"Runtime: static {t_static:.2f}s total, static+judge {t_judge:.1f}s total.", ""]
    parts += ["## Per sample", "", _sample_table(static, judged), ""]
    misses = [s for s in (judged or static) if s.flagged != (s.label == "malicious")]
    parts += ["## Errors and limits", ""]
    if misses:
        for s in misses:
            parts.append(f"- `{s.name}` ({s.label}) was {'flagged' if s.flagged else 'not flagged'}.")
    else:
        parts.append("- No misclassified samples in the final configuration.")
    parts += [
        "- The corpus is small and was written alongside the rules, so these numbers are an optimistic "
        "upper bound; treat them as a regression test, not a benchmark.",
        "- Static rules are pattern-based: novel phrasing of an injection, or logic split across files, can "
        "evade them. The LLM judge only reviews rule hits; it does not search for new issues.",
        "",
    ]
    return "\n".join(parts)


def run_eval(corpus: Path, out: Path, use_judge: bool = False, judge_model: str | None = None,
             ablation: bool = False) -> int:
    static = run_samples(corpus)
    judged = None
    abl = None
    info = ""
    if use_judge:
        from .judge import DEFAULT_MODEL, OllamaJudge

        judge = OllamaJudge(model=judge_model or DEFAULT_MODEL)
        if judge.available():
            judged = run_samples(corpus, judge=judge)
            st = judge.stats
            if ablation:
                abl = run_samples(corpus, judge=OllamaJudge(model=judge.model, hardened=False))
            info = f"{judge.model}; {st.calls} calls, {st.downgraded} downgraded, {st.errors} errors"
        else:
            print(f"judge model {judge.model} not available; static only")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render_report(static, judged, info, abl), "utf-8")
    runs = [("static", static), ("judge-unhardened", abl), ("static+judge", judged)]
    for name, samples in [(n, s) for n, s in runs if s]:
        m = metrics(samples)
        print(f"{name:13} precision={m['precision']:.2f} recall={m['recall']:.2f} f1={m['f1']:.2f} "
              f"(tp={m['tp']} fp={m['fp']} fn={m['fn']} tn={m['tn']})")
    print(f"report written to {out}")
    return 0
