from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "corpus"


@pytest.fixture
def write(tmp_path):
    def _write(rel: str, content):
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            p.write_bytes(content)
        else:
            p.write_text(content, "utf-8")
        return p
    return _write


def rule_ids(result):
    return {f.rule_id for f in result.findings}
