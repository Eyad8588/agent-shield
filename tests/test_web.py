"""Tests for the local upload-and-scan GUI server."""

from __future__ import annotations

import io
import json
import threading
import urllib.error
import urllib.request
import uuid
import zipfile
from pathlib import Path

import pytest

from agent_shield.web.server import UploadError, extract_zip, make_server, safe_relpath, stage_upload

CORPUS = Path(__file__).resolve().parents[1] / "corpus"
MAL_SKILL = CORPUS / "malicious" / "skill-hidden-comment"


@pytest.mark.parametrize("name,expected", [
    ("SKILL.md", "SKILL.md"),
    ("my-skill/scripts/run.sh", "my-skill/scripts/run.sh"),
    ("./a/./b.txt", "a/b.txt"),
    ("a\\b.txt", "a/b.txt"),
    ("../etc/passwd", None),
    ("a/../../x", None),
    ("/etc/passwd", None),
    ("C:/Windows/x", None),
    ("", None),
])
def test_safe_relpath(name, expected):
    assert safe_relpath(name) == expected


def _zip(entries: dict[str, bytes], symlink: str | None = None) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
        if symlink:
            info = zipfile.ZipInfo(symlink)
            info.external_attr = (0o120777 << 16)
            zf.writestr(info, "/etc/passwd")
    return buf.getvalue()


def test_zip_traversal_rejected(tmp_path):
    with pytest.raises(UploadError):
        extract_zip(_zip({"../escape.txt": b"x"}), tmp_path)
    assert not (tmp_path.parent / "escape.txt").exists()


def test_zip_symlinks_skipped(tmp_path):
    n = extract_zip(_zip({"skill/SKILL.md": b"# hi"}, symlink="skill/link"), tmp_path)
    assert n == 1
    assert (tmp_path / "skill" / "SKILL.md").is_file()
    assert not (tmp_path / "skill" / "link").exists()


def test_stage_upload_rejects_unsafe_names(tmp_path):
    with pytest.raises(UploadError):
        stage_upload([("../../x.md", b"x")], tmp_path)


@pytest.fixture()
def server():
    httpd = make_server(port=0)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield httpd.server_address[1]
    httpd.shutdown()
    httpd.server_close()


_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _req(port, path, data=None, headers=None, method=None):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=data, headers=headers or {}, method=method)
    try:
        with _opener.open(req, timeout=30) as r:
            return r.status, r.read(), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(e.headers)


def _multipart(files: list[tuple[str, bytes]], fields: dict[str, str] | None = None):
    boundary = uuid.uuid4().hex
    out = io.BytesIO()
    for k, v in (fields or {}).items():
        out.write(f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode())
    for name, data in files:
        out.write(f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{name}"\r\n'
                  f"Content-Type: application/octet-stream\r\n\r\n".encode())
        out.write(data + b"\r\n")
    out.write(f"--{boundary}--\r\n".encode())
    return out.getvalue(), f"multipart/form-data; boundary={boundary}"


def test_index_served_with_csp(server):
    status, body, headers = _req(server, "/")
    assert status == 200 and b"Agent Shield" in body
    assert "script-src 'self'" in headers["Content-Security-Policy"]


def test_foreign_host_refused(server):
    status, _, _ = _req(server, "/api/status", headers={"Host": "evil.example"})
    assert status == 403


def test_cross_origin_post_refused(server):
    body, ctype = _multipart([("SKILL.md", b"# hi")])
    status, _, _ = _req(server, "/api/scan", data=body,
                        headers={"Content-Type": ctype, "Origin": "http://evil.example"})
    assert status == 403


def test_upload_scan_blocks_malicious_skill(server):
    files = [(f"skill-hidden-comment/{p.relative_to(MAL_SKILL)}", p.read_bytes())
             for p in sorted(MAL_SKILL.rglob("*")) if p.is_file()]
    body, ctype = _multipart(files)
    status, raw, _ = _req(server, "/api/scan", data=body, headers={"Content-Type": ctype})
    assert status == 200, raw
    r = json.loads(raw)
    assert r["verdict"] == "block"
    assert r["label"] == "skill-hidden-comment"
    assert any(f["rule_id"] == "SE001" for f in r["findings"])
    # reports for the scan are downloadable
    s, html, h = _req(server, f"/report/{r['id']}.html")
    assert s == 200 and b"Agent Shield report" in html and "default-src 'none'" in h["Content-Security-Policy"]
    s, sarif, _ = _req(server, f"/report/{r['id']}.sarif")
    assert s == 200 and json.loads(sarif)["version"] == "2.1.0"


def test_upload_zip_scan(server):
    data = _zip({f"pkg/{p.relative_to(MAL_SKILL)}": p.read_bytes() for p in MAL_SKILL.rglob("*") if p.is_file()})
    body, ctype = _multipart([("bundle.zip", data)])
    status, raw, _ = _req(server, "/api/scan", data=body, headers={"Content-Type": ctype})
    assert status == 200, raw
    assert json.loads(raw)["verdict"] == "block"


def test_sample_scan_and_unknown_sample(server):
    status, raw, _ = _req(server, "/api/scan-sample", data=json.dumps({"path": "malicious/skill-hidden-comment"}).encode(),
                          headers={"Content-Type": "application/json"})
    assert status == 200 and json.loads(raw)["verdict"] == "block"
    status, _, _ = _req(server, "/api/scan-sample", data=json.dumps({"path": "../../etc"}).encode(),
                        headers={"Content-Type": "application/json"})
    assert status == 400
