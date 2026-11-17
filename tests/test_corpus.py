"""Corpus regression: every malicious sample is blocked, clean samples are not
(except the two known static-only false positives that the LLM judge resolves),
and malicious samples stay inert."""
import re

import pytest

from agent_shield.evaluate import metrics, run_samples
from conftest import CORPUS

KNOWN_STATIC_FP = {"skill-injection-defense", "skill-deploy-docs"}


@pytest.fixture(scope="module")
def samples():
    return run_samples(CORPUS)


def test_corpus_size(samples):
    assert sum(s.label == "malicious" for s in samples) >= 25
    assert sum(s.label == "clean" for s in samples) >= 12


def test_static_recall_is_perfect(samples):
    missed = [s.name for s in samples if s.label == "malicious" and not s.flagged]
    assert missed == []


def test_clean_samples(samples):
    fps = {s.name for s in samples if s.label == "clean" and s.flagged}
    assert fps == KNOWN_STATIC_FP
    assert metrics(samples)["precision"] >= 0.9


EXIT_GUARD = re.compile(r"^\s*(exit 0|sys\.exit\(0\)|process\.exit\(0\);?|raise SystemExit)", re.M)


def test_malicious_scripts_are_inert():
    scripts = [p for p in (CORPUS / "malicious").rglob("*") if p.suffix in {".sh", ".py", ".ts", ".js"}]
    assert scripts
    for p in scripts:
        raw = p.read_text()
        # import lines are inert; look for payload keywords in executable statements only
        text = "\n".join("" if re.match(r"\s*(import |from \S+ import |#|//|\"\"\")", ln) else ln for ln in raw.splitlines())
        m = EXIT_GUARD.search(text)
        assert m, f"{p} has no early exit"
        payload_start = min((text.find(k) for k in ("curl", "requests", "subprocess.run", "execSync", "bash -i",
                                                    "exec(", "tar ", "echo ", "chrome", "fetch(") if k in text),
                            default=len(text))
        assert m.start() < payload_start or "def " in text[:m.start()], f"{p}: exit must come before the payload"


def test_malicious_urls_use_reserved_or_dummy_hosts():
    host = re.compile(r"https?://([^/\s\"'`)]+)")
    allowed = re.compile(r"(\.invalid|webhook\.site|ngrok-free\.app|discord\.com|192\.0\.2\.\d+|203\.0\.113\.\d+)$")
    for p in (CORPUS / "malicious").rglob("*"):
        if p.is_file() and p.suffix not in {".pkl", ".pt", ".bin", ".npy", ".safetensors"}:
            for h in host.findall(p.read_text(errors="ignore")):
                assert allowed.search(h), f"{p}: unexpected host {h}"
