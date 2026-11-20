"""Local web GUI: upload skills, MCP servers, agent configs or model files and scan them.

Run with `agent-shield gui`. The server binds to 127.0.0.1 only and uses the
standard library (no extra dependencies).

Uploaded content is attacker-controlled by design, so:
  * nothing uploaded is executed or deserialized (the scanner never does);
  * every upload path is normalised and must stay inside a fresh temp directory
    (absolute paths, `..`, and zip symlinks are rejected);
  * upload size and file count are capped;
  * requests must name this server as Host (DNS-rebinding guard), and POSTs from
    another Origin are refused;
  * the browser UI renders all text with textContent, never as HTML.
"""

from __future__ import annotations

import io
import json
import shutil
import tempfile
import threading
import time
import urllib.request
import uuid
import webbrowser
import zipfile
from email import policy
from email.parser import BytesParser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from pathlib import Path, PurePosixPath

from .. import __version__
from ..judge import DEFAULT_HOST, DEFAULT_MODEL
from ..report.html import to_html
from ..report.sarif import to_sarif
from ..scanner import scan

MAX_UPLOAD_BYTES = 200 * 1024 * 1024  # whole request body
MAX_FILES = 2000
MAX_ZIP_UNCOMPRESSED = 500 * 1024 * 1024
MAX_HISTORY = 50
CORPUS = Path(__file__).resolve().parents[3] / "corpus"  # present in a repo checkout only

_STATIC = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
}
_APP_CSP = ("default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "connect-src 'self'; img-src 'self' data:; frame-src 'self'; base-uri 'none'; form-action 'none'")
_REPORT_CSP = "default-src 'none'; style-src 'unsafe-inline'"


class UploadError(ValueError):
    pass


# ---------------------------------------------------------------- uploads ----

def safe_relpath(name: str) -> str | None:
    """Normalise an uploaded path. Returns None for anything that could escape the upload dir."""
    if not name:
        return None
    name = name.replace("\\", "/")
    if name.startswith("/") or (len(name) > 1 and name[1] == ":"):
        return None
    parts = [p for p in PurePosixPath(name).parts if p not in ("", ".")]
    if not parts or any(p == ".." for p in parts):
        return None
    if any("\x00" in p for p in parts):
        return None
    return "/".join(parts)


def _write(dest_root: Path, rel: str, data: bytes) -> None:
    target = (dest_root / rel).resolve()
    if dest_root.resolve() not in target.parents:
        raise UploadError(f"path escapes upload dir: {rel}")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)


def extract_zip(data: bytes, dest_root: Path, prefix: str = "") -> int:
    """Extract a zip safely (no symlinks, no traversal, size-capped). Returns files written."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as e:
        raise UploadError(f"not a valid zip: {e}") from e
    total = written = 0
    with zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            if (info.external_attr >> 16) & 0o170000 == 0o120000:  # symlink entry
                continue
            rel = safe_relpath(info.filename)
            if rel is None:
                raise UploadError(f"unsafe path inside zip: {info.filename!r}")
            total += info.file_size
            if total > MAX_ZIP_UNCOMPRESSED:
                raise UploadError("zip expands beyond the size limit")
            written += 1
            if written > MAX_FILES:
                raise UploadError(f"more than {MAX_FILES} files")
            _write(dest_root, f"{prefix}/{rel}" if prefix else rel, zf.read(info))
    return written


def parse_multipart(content_type: str, body: bytes) -> tuple[list[tuple[str, bytes]], dict[str, str]]:
    """Return ([(filename, bytes)], {field: value}) from a multipart/form-data body."""
    msg = BytesParser(policy=policy.HTTP).parsebytes(
        b"Content-Type: " + content_type.encode("latin-1") + b"\r\n\r\n" + body
    )
    if not msg.is_multipart():
        raise UploadError("expected multipart/form-data")
    files: list[tuple[str, bytes]] = []
    fields: dict[str, str] = {}
    for part in msg.iter_parts():
        name = part.get_param("name", header="content-disposition")
        filename = part.get_param("filename", header="content-disposition")
        payload = part.get_payload(decode=True) or b""
        if filename is not None:
            files.append((str(filename), payload))
        elif name:
            fields[str(name)] = payload.decode("utf-8", errors="replace")
    return files, fields


def stage_upload(files: list[tuple[str, bytes]], dest_root: Path) -> int:
    """Write uploaded files (and the contents of uploaded zips) under dest_root."""
    if not files:
        raise UploadError("no files uploaded")
    if len(files) > MAX_FILES:
        raise UploadError(f"more than {MAX_FILES} files")
    count = 0
    for filename, data in files:
        rel = safe_relpath(filename)
        if rel is None:
            raise UploadError(f"unsafe file path: {filename!r}")
        if rel.lower().endswith(".zip"):
            count += extract_zip(data, dest_root, prefix=rel[:-4])
        else:
            _write(dest_root, rel, data)
            count += 1
    return count


def upload_label(files: list[tuple[str, bytes]]) -> str:
    tops = sorted({(safe_relpath(n) or n).split("/")[0] for n, _ in files})
    if len(tops) == 1:
        return tops[0]
    return f"{tops[0]} + {len(tops) - 1} more"


# ---------------------------------------------------------------- scanning ---

class ScanStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._items: dict[str, dict] = {}

    def add(self, label: str, result) -> dict:
        sid = uuid.uuid4().hex[:12]
        result.root = label
        item = {
            "id": sid,
            "label": label,
            "time": time.strftime("%H:%M:%S"),
            "result": result.to_dict(),
            "html": to_html(result),
            "sarif": to_sarif(result),
        }
        with self._lock:
            self._items[sid] = item
            while len(self._items) > MAX_HISTORY:
                self._items.pop(next(iter(self._items)))
        return item

    def get(self, sid: str) -> dict | None:
        with self._lock:
            return self._items.get(sid)

    def history(self) -> list[dict]:
        with self._lock:
            items = list(self._items.values())
        return [{"id": i["id"], "label": i["label"], "time": i["time"],
                 "score": i["result"]["score"], "verdict": i["result"]["verdict"]} for i in reversed(items)]


def _no_proxy_open(url: str, timeout: float = 3):
    return urllib.request.build_opener(urllib.request.ProxyHandler({})).open(url, timeout=timeout)


def ollama_models() -> list[str] | None:
    """Model names served by the local Ollama, or None when it isn't reachable."""
    try:
        with _no_proxy_open(f"{DEFAULT_HOST}/api/tags") as r:
            return sorted(m["name"] for m in json.load(r).get("models", []))
    except Exception:  # noqa: BLE001
        return None


def make_judge(enabled: bool, model: str):
    if not enabled:
        return None, None
    from ..judge import OllamaJudge

    judge = OllamaJudge(model=model or DEFAULT_MODEL)
    if not judge.available():
        return None, f"LLM judge unavailable: model {judge.model!r} is not served by Ollama; static severities kept"
    return judge, None


def run_scan(root: Path, label: str, judge_on: bool, judge_model: str, store: ScanStore) -> dict:
    judge, note = make_judge(judge_on, judge_model)
    result = scan(root, judge=judge)
    if note:
        result.errors.append(note)
    return store.add(label, result)


def list_samples() -> list[dict]:
    out = []
    for group in ("malicious", "clean"):
        d = CORPUS / group
        if d.is_dir():
            out += [{"group": group, "name": p.name, "path": f"{group}/{p.name}"}
                    for p in sorted(d.iterdir()) if not p.name.startswith(".")]
    return out


# ---------------------------------------------------------------- HTTP -------

class Handler(BaseHTTPRequestHandler):
    server_version = f"agent-shield-gui/{__version__}"
    store: ScanStore  # set by make_server

    def log_message(self, fmt, *args):  # quieter console
        pass

    # -- helpers --
    def _allowed_hosts(self) -> set[str]:
        port = self.server.server_address[1]
        return {f"127.0.0.1:{port}", f"localhost:{port}"}

    def _guard(self, post: bool = False) -> bool:
        host = self.headers.get("Host", "")
        if host not in self._allowed_hosts():
            self._send(HTTPStatus.FORBIDDEN, b"bad host", "text/plain")
            return False
        origin = self.headers.get("Origin")
        if post and origin is not None and origin not in {f"http://{h}" for h in self._allowed_hosts()}:
            self._send(HTTPStatus.FORBIDDEN, b"cross-origin request refused", "text/plain")
            return False
        return True

    def _send(self, status, body: bytes, ctype: str, csp: str | None = None, download: str | None = None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        if csp:
            self.send_header("Content-Security-Policy", csp)
        if download:
            self.send_header("Content-Disposition", f'attachment; filename="{download}"')
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, status=HTTPStatus.OK):
        self._send(status, json.dumps(obj).encode(), "application/json")

    def _error(self, msg: str, status=HTTPStatus.BAD_REQUEST):
        self._json({"error": msg}, status)

    # -- GET --
    def do_GET(self):  # noqa: N802
        if not self._guard():
            return
        path = self.path.split("?", 1)[0]
        if path in _STATIC:
            name, ctype = _STATIC[path]
            body = resources.files(__package__).joinpath(name).read_bytes()
            return self._send(HTTPStatus.OK, body, ctype, csp=_APP_CSP)
        if path == "/api/status":
            models = ollama_models()
            return self._json({
                "version": __version__,
                "ollama": models is not None,
                "models": models or [],
                "default_model": DEFAULT_MODEL,
                "samples": bool(list_samples()),
            })
        if path == "/api/samples":
            return self._json(list_samples())
        if path == "/api/history":
            return self._json(self.store.history())
        if path.startswith("/api/scan/"):
            item = self.store.get(path.rsplit("/", 1)[-1])
            if not item:
                return self._error("scan not found", HTTPStatus.NOT_FOUND)
            return self._json({"id": item["id"], "label": item["label"], **item["result"]})
        if path.startswith("/report/"):
            sid, _, ext = path[len("/report/"):].partition(".")
            item = self.store.get(sid)
            if not item:
                return self._error("scan not found", HTTPStatus.NOT_FOUND)
            dl = "agent-shield"
            if ext == "html":
                return self._send(HTTPStatus.OK, item["html"].encode(), "text/html; charset=utf-8", csp=_REPORT_CSP)
            if ext == "sarif":
                return self._send(HTTPStatus.OK, json.dumps(item["sarif"], indent=2).encode(),
                                  "application/json", download=f"{dl}.sarif")
            if ext == "json":
                return self._send(HTTPStatus.OK, json.dumps(item["result"], indent=2).encode(),
                                  "application/json", download=f"{dl}.json")
        self._error("not found", HTTPStatus.NOT_FOUND)

    # -- POST --
    def do_POST(self):  # noqa: N802
        if not self._guard(post=True):
            return
        path = self.path.split("?", 1)[0]
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return self._error("bad Content-Length")
        if length > MAX_UPLOAD_BYTES:
            return self._error(f"upload larger than {MAX_UPLOAD_BYTES // (1024 * 1024)} MB",
                               HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
        body = self.rfile.read(length)
        try:
            if path == "/api/scan":
                return self._scan_upload(body)
            if path == "/api/scan-sample":
                return self._scan_sample(body)
        except UploadError as e:
            return self._error(str(e))
        except Exception as e:  # noqa: BLE001
            return self._error(f"scan failed: {type(e).__name__}: {e}", HTTPStatus.INTERNAL_SERVER_ERROR)
        self._error("not found", HTTPStatus.NOT_FOUND)

    def _scan_upload(self, body: bytes):
        files, fields = parse_multipart(self.headers.get("Content-Type", ""), body)
        tmp = Path(tempfile.mkdtemp(prefix="agent-shield-gui-"))
        try:
            root = tmp / "upload"
            root.mkdir()
            stage_upload(files, root)
            item = run_scan(root, upload_label(files), fields.get("judge") == "on",
                            fields.get("judge_model", ""), self.store)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        self._json({"id": item["id"], "label": item["label"], **item["result"]})

    def _scan_sample(self, body: bytes):
        req = json.loads(body or b"{}")
        rel = safe_relpath(str(req.get("path", "")))
        known = {s["path"] for s in list_samples()}
        if rel is None or rel not in known:
            raise UploadError("unknown sample")
        item = run_scan(CORPUS / rel, f"sample: {rel}", bool(req.get("judge")),
                        str(req.get("judge_model", "")), self.store)
        self._json({"id": item["id"], "label": item["label"], **item["result"]})


def make_server(port: int = 8765) -> ThreadingHTTPServer:
    handler = type("BoundHandler", (Handler,), {"store": ScanStore()})
    return ThreadingHTTPServer(("127.0.0.1", port), handler)


def serve(port: int = 8765, open_browser: bool = True) -> int:
    httpd = make_server(port)
    url = f"http://127.0.0.1:{httpd.server_address[1]}/"
    print(f"agent-shield GUI on {url}  (Ctrl+C to stop)", flush=True)
    if open_browser:
        threading.Timer(0.5, webbrowser.open, args=(url,)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0
