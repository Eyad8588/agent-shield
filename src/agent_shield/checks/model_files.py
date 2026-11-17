"""Model-file checks.

Pickle-based weights (.pt/.pth/.bin/.pkl/.ckpt/.joblib) are scanned with
`pickletools.genops`, which *parses* the opcode stream without executing it.
Nothing here ever calls pickle.load / torch.load.

Checks
  PKL001 dangerous import in pickle (os.system, subprocess, eval, ...)  critical
  PKL002 non-allow-listed import in pickle                              medium
  PKL003 pickle-based format (prefer safetensors)                        low
  PKL004 unparseable / truncated pickle stream                           high
  MDL001 malformed safetensors header                                    high
  MDL002 hash mismatch against a checksum manifest                       critical
  MDL003 no checksum / provenance record for a model file                low
  MDL004 object-dtype .npy (embeds a pickle)                             high
"""

from __future__ import annotations

import hashlib
import io
import json
import pickletools
import struct
import zipfile
from pathlib import Path

import yaml

from ..discovery import ScanFile
from ..models import Finding, Severity

PICKLE_SUFFIXES = {".pt", ".pth", ".bin", ".pkl", ".pickle", ".ckpt", ".joblib"}

DANGEROUS_MODULES = {
    "os", "posix", "nt", "subprocess", "sys", "shutil", "socket", "runpy", "importlib", "pty",
    "webbrowser", "requests", "urllib", "urllib.request", "http", "http.client", "ctypes", "pickle",
    "_pickle", "marshal", "code", "commands", "platform", "asyncio", "multiprocessing", "signal",
    "tempfile", "glob", "pathlib", "io", "builtins.open", "aiohttp", "httpx", "ftplib", "smtplib",
    "telnetlib", "pdb", "bdb", "timeit", "cProfile", "profile", "trace", "torch.hub",
}
DANGEROUS_BUILTINS = {
    "eval", "exec", "compile", "__import__", "open", "getattr", "setattr", "delattr", "globals",
    "locals", "vars", "breakpoint", "input", "memoryview", "help", "exit", "quit",
}
GADGETS = {
    ("operator", "attrgetter"), ("operator", "methodcaller"), ("operator", "itemgetter"),
    ("functools", "partial"), ("functools", "reduce"), ("types", "CodeType"), ("types", "FunctionType"),
    ("numpy", "load"), ("numpy.lib.npyio", "load"), ("torch", "load"), ("torch.serialization", "load"),
    ("numpy.testing._private.utils", "runstring"), ("joblib", "load"),
}
SAFE_GLOBALS = {
    ("collections", "OrderedDict"), ("collections", "defaultdict"), ("collections", "Counter"),
    ("torch._utils", "_rebuild_tensor"), ("torch._utils", "_rebuild_tensor_v2"),
    ("torch._utils", "_rebuild_parameter"), ("torch._utils", "_rebuild_parameter_with_state"),
    ("torch._utils", "_rebuild_qtensor"), ("torch._utils", "_rebuild_sparse_tensor"),
    ("torch", "Size"), ("torch", "device"), ("torch._tensor", "_rebuild_from_type_v2"),
    ("torch.nn.parameter", "Parameter"),
    ("numpy.core.multiarray", "_reconstruct"), ("numpy._core.multiarray", "_reconstruct"),
    ("numpy.core.multiarray", "scalar"), ("numpy._core.multiarray", "scalar"),
    ("numpy", "ndarray"), ("numpy", "dtype"), ("_codecs", "encode"),
    ("builtins", "set"), ("builtins", "frozenset"), ("builtins", "slice"), ("builtins", "complex"),
    ("builtins", "bytearray"), ("builtins", "range"), ("builtins", "tuple"), ("builtins", "list"),
    ("builtins", "dict"), ("builtins", "int"), ("builtins", "float"), ("builtins", "bool"),
    ("builtins", "str"), ("builtins", "bytes"), ("__builtin__", "set"),
    ("datetime", "datetime"), ("datetime", "date"), ("datetime", "timedelta"),
}
_TORCH_UNSAFE = {"load", "hub", "jit", "ops", "_C", "classes", "compile"}

STRING_OPS = {
    "SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8", "UNICODE", "SHORT_BINSTRING", "BINSTRING", "STRING",
}
MEMO_PUT = {"PUT", "BINPUT", "LONG_BINPUT"}
MEMO_GET = {"GET", "BINGET", "LONG_BINGET"}
CALL_OPS = {"REDUCE", "INST", "OBJ", "NEWOBJ", "NEWOBJ_EX", "BUILD"}


def classify_global(module: str, name: str) -> str:
    """Return 'dangerous', 'safe' or 'unknown' for an imported global."""
    module = module.strip()
    name = name.strip()
    if module in {"builtins", "__builtin__", "__builtins__"}:
        if name in DANGEROUS_BUILTINS:
            return "dangerous"
        return "safe" if (module, name) in SAFE_GLOBALS or name in {"set", "frozenset", "slice"} else "unknown"
    root = module.split(".")[0]
    if module in DANGEROUS_MODULES or root in DANGEROUS_MODULES or (module, name) in GADGETS:
        return "dangerous"
    if (module, name) in SAFE_GLOBALS:
        return "safe"
    if module == "torch":
        if name in _TORCH_UNSAFE:
            return "dangerous"
        # storage classes (FloatStorage) and dtypes (float32, bfloat16)
        if name.endswith("Storage") or (name[:1].islower() and name.isidentifier() and not name.startswith("_")):
            return "safe"
    return "unknown"


def scan_pickle_bytes(data: bytes) -> tuple[list[tuple[str, str, bool]], str | None]:
    """Parse one or more concatenated pickles.

    Returns ([(module, name, called)], error). `called` is True when a call
    opcode (REDUCE/OBJ/NEWOBJ/INST/BUILD) appears after the import, i.e. the
    pickle would invoke it on load.
    """
    imports: list[tuple[str, str, bool]] = []
    stream = io.BytesIO(data)
    error = None
    while stream.tell() < len(data):
        start = stream.tell()
        strings: list[str] = []
        memo: dict[int, str] = {}
        pending: list[int] = []
        last_was_string = False
        try:
            for op, arg, _pos in pickletools.genops(stream):
                name = op.name
                if name in STRING_OPS:
                    strings.append(str(arg))
                    last_was_string = True
                    continue
                if name in MEMO_PUT:
                    if last_was_string and strings:
                        memo[arg] = strings[-1]
                    continue
                if name == "MEMOIZE":
                    if last_was_string and strings:
                        memo[len(memo)] = strings[-1]
                    continue
                if name in MEMO_GET:
                    if arg in memo:
                        strings.append(memo[arg])
                        last_was_string = True
                    continue
                last_was_string = False
                if name in {"GLOBAL", "INST"}:
                    mod, _, attr = str(arg).partition(" ")
                    imports.append((mod, attr, name == "INST"))
                    if name == "GLOBAL":
                        pending.append(len(imports) - 1)
                elif name == "STACK_GLOBAL":
                    if len(strings) >= 2:
                        imports.append((strings[-2], strings[-1], False))
                    else:
                        imports.append(("<unknown>", "<unknown>", False))
                    pending.append(len(imports) - 1)
                elif name in CALL_OPS and pending:
                    for idx in pending:
                        m, a, _ = imports[idx]
                        imports[idx] = (m, a, True)
                    pending.clear()
        except Exception as exc:  # malformed / truncated stream
            error = f"{type(exc).__name__}: {exc}"
            break
        if stream.tell() == start:
            break
        # Legacy torch files concatenate several pickles; continue only if the
        # next byte starts a new protocol-2+ pickle.
        nxt = data[stream.tell() : stream.tell() + 1]
        if nxt != b"\x80":
            break
    return imports, error


def _pickle_payloads(path: Path) -> list[tuple[str, bytes]]:
    """Return (member-name, bytes) pairs that hold pickle streams."""
    raw = path.read_bytes()
    if raw[:4] == b"PK\x03\x04":
        out = []
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            for info in zf.infolist():
                if info.filename.endswith((".pkl", ".pickle")) or info.filename.endswith("/data.pkl"):
                    if info.file_size > 512 * 1024 * 1024:
                        continue
                    out.append((info.filename, zf.read(info)))
        return out
    if raw[:1] == b"\x80" or raw[:1] in {b"(", b"c", b"}", b"]"}:
        return [("", raw)]
    return []


def _npy_payload(path: Path) -> tuple[bool, bytes]:
    raw = path.read_bytes()
    if raw[:6] != b"\x93NUMPY":
        return False, b""
    major = raw[6]
    if major == 1:
        hlen = struct.unpack("<H", raw[8:10])[0]
        hstart = 10
    else:
        hlen = struct.unpack("<I", raw[8:12])[0]
        hstart = 12
    header = raw[hstart : hstart + hlen].decode("latin1", errors="replace")
    is_object = "'descr': '|O'" in header or "'descr': 'O'" in header
    return is_object, raw[hstart + hlen :]


def check_safetensors(path: Path) -> str | None:
    """Validate a safetensors header without loading tensors. Returns an error or None."""
    size = path.stat().st_size
    with path.open("rb") as fh:
        head = fh.read(8)
        if len(head) < 8:
            return "file shorter than the 8-byte header length"
        (n,) = struct.unpack("<Q", head)
        if n > min(size - 8, 100 * 1024 * 1024):
            return f"header length {n} exceeds file size"
        try:
            header = json.loads(fh.read(n))
        except ValueError as exc:
            return f"header is not valid JSON ({exc})"
    if not isinstance(header, dict):
        return "header is not a JSON object"
    data_len = size - 8 - n
    for key, meta in header.items():
        if key == "__metadata__":
            if not isinstance(meta, dict) or not all(isinstance(v, str) for v in meta.values()):
                return "__metadata__ must map strings to strings"
            continue
        if not isinstance(meta, dict) or not {"dtype", "shape", "data_offsets"} <= meta.keys():
            return f"tensor {key!r} missing dtype/shape/data_offsets"
        start, end = meta["data_offsets"]
        if not (0 <= start <= end <= data_len):
            return f"tensor {key!r} offsets out of bounds"
    return None


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _load_manifests(files: list[ScanFile]) -> dict[Path, dict]:
    """Collect expected hashes + provenance from SHA256SUMS / *.sha256 / provenance.(json|yaml)."""
    expected: dict[Path, dict] = {}
    for f in files:
        name = f.path.name.lower()
        try:
            if name in {"sha256sums", "sha256sums.txt", "checksums.txt"} or name.endswith(".sha256"):
                for line in f.path.read_text("utf-8", errors="replace").splitlines():
                    parts = line.strip().split()
                    if len(parts) >= 2 and len(parts[0]) == 64:
                        target = (f.path.parent / parts[-1].lstrip("*")).resolve()
                        expected.setdefault(target, {})["sha256"] = parts[0].lower()
                    elif len(parts) == 1 and len(parts[0]) == 64 and name.endswith(".sha256"):
                        target = (f.path.parent / f.path.name[: -len(".sha256")]).resolve()
                        expected.setdefault(target, {})["sha256"] = parts[0].lower()
            elif name in {"provenance.json", "provenance.yaml", "provenance.yml"}:
                data = yaml.safe_load(f.path.read_text("utf-8")) or {}
                for entry in data.get("files", []):
                    target = (f.path.parent / entry["path"]).resolve()
                    rec = expected.setdefault(target, {})
                    if entry.get("sha256"):
                        rec["sha256"] = str(entry["sha256"]).lower()
                    if entry.get("source"):
                        rec["source"] = entry["source"]
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            continue
    return expected


def check_model_files(files: list[ScanFile]) -> list[Finding]:
    findings: list[Finding] = []
    manifests = _load_manifests(files)
    for f in files:
        if "model" not in f.kinds:
            continue
        suffix = f.path.suffix.lower()

        def add(rule_id, title, sev, msg, snippet="", line=1, category="model-file"):
            findings.append(
                Finding(rule_id=rule_id, title=title, severity=sev, category=category, file=f.rel,
                        line=line, message=msg, snippet=snippet, kind="model")
            )

        if suffix == ".safetensors":
            err = check_safetensors(f.path)
            if err:
                add("MDL001", "Malformed safetensors header", Severity.HIGH,
                    "The file claims to be safetensors but its header is invalid; it may be disguised.", err)
        elif suffix in {".npy"}:
            is_obj, rest = _npy_payload(f.path)
            if is_obj:
                add("MDL004", "Object-dtype NumPy array (embedded pickle)", Severity.HIGH,
                    "np.load(allow_pickle=True) would unpickle this array.")
                findings.extend(_pickle_findings(f, rest, member="(npy payload)"))
        elif suffix in PICKLE_SUFFIXES:
            try:
                payloads = _pickle_payloads(f.path)
            except (OSError, zipfile.BadZipFile) as exc:
                add("PKL004", "Unreadable model archive", Severity.HIGH, str(exc))
                payloads = []
            if payloads:
                add("PKL003", "Pickle-based model format", Severity.LOW,
                    "Pickle can execute code on load. Prefer .safetensors, or load with "
                    "torch.load(weights_only=True).", category="unsafe-format")
                for member, data in payloads:
                    findings.extend(_pickle_findings(f, data, member))
            elif suffix != ".bin":
                add("PKL004", "Unrecognised model serialization", Severity.MEDIUM,
                    "Not a pickle, zip-pickle or safetensors file; review its loader.")

        rec = manifests.get(f.path.resolve())
        if rec and rec.get("sha256"):
            actual = _sha256(f.path)
            if actual != rec["sha256"]:
                add("MDL002", "Model hash does not match its manifest", Severity.CRITICAL,
                    "The file was modified after the checksum was recorded.",
                    f"expected {rec['sha256']}, got {actual}", category="provenance")
        else:
            add("MDL003", "No checksum / provenance record", Severity.LOW,
                "Record a SHA-256 and source URL (SHA256SUMS or provenance.yaml) so tampering is detectable.",
                f"sha256={_sha256(f.path)}", category="provenance")
        if rec and rec.get("source") and not str(rec["source"]).startswith("https://"):
            add("MDL005", "Model source is not an HTTPS URL", Severity.MEDIUM,
                "Provenance source should be a verifiable HTTPS location.", str(rec["source"]),
                category="provenance")
    return findings


def _pickle_findings(f: ScanFile, data: bytes, member: str) -> list[Finding]:
    out: list[Finding] = []
    imports, error = scan_pickle_bytes(data)
    where = f" in {member}" if member else ""
    seen: set[tuple[str, str]] = set()
    for module, name, called in imports:
        if (module, name) in seen:
            continue
        seen.add((module, name))
        cls = classify_global(module, name)
        if cls == "dangerous":
            out.append(Finding(
                rule_id="PKL001", title="Dangerous import in pickle", severity=Severity.CRITICAL,
                category="code-execution", file=f.rel, line=1, kind="model",
                message=f"The pickle{where} imports {module}.{name}"
                + (" and calls it on load." if called else " (would be importable on load)."),
                snippet=f"{module}.{name} called={called}",
            ))
        elif cls == "unknown":
            out.append(Finding(
                rule_id="PKL002", title="Non-allow-listed import in pickle", severity=Severity.MEDIUM,
                category="code-execution", file=f.rel, line=1, kind="model",
                message=f"The pickle{where} imports {module}.{name}, which is not on the safe list. Review it.",
                snippet=f"{module}.{name} called={called}",
            ))
    if error:
        out.append(Finding(
            rule_id="PKL004", title="Malformed pickle stream", severity=Severity.HIGH,
            category="code-execution", file=f.rel, line=1, kind="model",
            message=f"Pickle{where} could not be fully parsed; scanners may be evaded by malformed streams.",
            snippet=error[:200],
        ))
    return out
