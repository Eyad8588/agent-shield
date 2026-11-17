"""Invisible and bidirectional Unicode detection.

- Tag characters (U+E0000-U+E007F) can encode a full hidden ASCII message
  ("ASCII smuggling"); we decode it so the reviewer can read it.
- Bidi controls (U+202A-U+202E, U+2066-U+2069) reorder text so what a human
  sees differs from what a model or compiler reads ("Trojan Source").
- Zero-width characters hide text boundaries or carry binary payloads.
"""

from __future__ import annotations

from ..discovery import ScanFile
from ..models import Finding, Severity

TAG_RANGE = range(0xE0000, 0xE0080)
VS_SUPPLEMENT = range(0xE0100, 0xE01F0)
BIDI = {0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069, 0x200E, 0x200F, 0x061C}
ZERO_WIDTH = {0x200B, 0x200C, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0x180E, 0xFEFF, 0x00AD}
ZWJ = 0x200D
CODE_SUFFIXES = {".py", ".js", ".mjs", ".cjs", ".ts", ".sh", ".go", ".rb", ".ps1"}
MAX_PER_FILE = 5


def _is_ascii_letter(ch: str) -> bool:
    return ch.isascii() and ch.isalnum()


def check_unicode(files: list[ScanFile]) -> list[Finding]:
    findings: list[Finding] = []
    for f in files:
        if not f.is_text:
            continue
        text = f.text()
        if text.isascii():
            continue
        is_code = f.path.suffix.lower() in CODE_SUFFIXES
        kind = next(iter(sorted(f.kinds)), "any")
        per_file = 0
        line = 1
        i = 0
        reported_lines: dict[str, set[int]] = {"tag": set(), "bidi": set(), "zw": set(), "vs": set()}
        n = len(text)
        while i < n:
            ch = text[i]
            cp = ord(ch)
            if ch == "\n":
                line += 1
                i += 1
                continue
            if cp in TAG_RANGE:
                j = i
                hidden = []
                while j < n and ord(text[j]) in TAG_RANGE:
                    c = ord(text[j]) - 0xE0000
                    if 0x20 <= c < 0x7F:
                        hidden.append(chr(c))
                    j += 1
                if line not in reported_lines["tag"] and per_file < MAX_PER_FILE:
                    reported_lines["tag"].add(line)
                    per_file += 1
                    decoded = "".join(hidden)
                    findings.append(
                        Finding(
                            rule_id="UNI001",
                            title="Hidden Unicode tag characters (ASCII smuggling)",
                            severity=Severity.CRITICAL,
                            category="hidden-instructions",
                            file=f.rel,
                            line=line,
                            message="Invisible tag characters encode text a human cannot see but a model reads. "
                            "Decoded hidden text is shown in the snippet.",
                            snippet=f"decoded: {decoded[:300]!r}",
                            kind=kind,
                        )
                    )
                i = j
                continue
            if cp in BIDI and line not in reported_lines["bidi"] and per_file < MAX_PER_FILE:
                reported_lines["bidi"].add(line)
                per_file += 1
                findings.append(
                    Finding(
                        rule_id="UNI002",
                        title="Bidirectional control character",
                        severity=Severity.CRITICAL if is_code else Severity.HIGH,
                        category="hidden-instructions",
                        file=f.rel,
                        line=line,
                        message="Bidi controls make displayed text differ from the logical text a model or "
                        "interpreter reads (Trojan Source). Remove them.",
                        snippet=_visible_line(text, i),
                        kind=kind,
                    )
                )
            elif cp in VS_SUPPLEMENT and line not in reported_lines["vs"] and per_file < MAX_PER_FILE:
                reported_lines["vs"].add(line)
                per_file += 1
                findings.append(
                    Finding(
                        rule_id="UNI003",
                        title="Variation-selector payload",
                        severity=Severity.HIGH,
                        category="hidden-instructions",
                        file=f.rel,
                        line=line,
                        message="Supplementary variation selectors can hide arbitrary bytes after a visible character.",
                        snippet=_visible_line(text, i),
                        kind=kind,
                    )
                )
            elif cp in ZERO_WIDTH or (
                cp == ZWJ and 0 < i < n - 1 and _is_ascii_letter(text[i - 1]) and _is_ascii_letter(text[i + 1])
            ):
                if cp == 0xFEFF and i == 0:
                    i += 1
                    continue
                # count a run of zero-width chars: long runs carry binary payloads
                j = i
                while j < n and (ord(text[j]) in ZERO_WIDTH or ord(text[j]) == ZWJ):
                    j += 1
                run = j - i
                if line not in reported_lines["zw"] and per_file < MAX_PER_FILE:
                    reported_lines["zw"].add(line)
                    per_file += 1
                    sev = Severity.HIGH if (run >= 4 or f.kinds & {"skill", "mcp"}) else Severity.MEDIUM
                    if cp == 0x00AD and run == 1:
                        sev = Severity.LOW
                    findings.append(
                        Finding(
                            rule_id="UNI004",
                            title="Zero-width / invisible character",
                            severity=sev,
                            category="hidden-instructions",
                            file=f.rel,
                            line=line,
                            message=f"{run} invisible character(s) (U+{cp:04X}...). These can split keywords to evade "
                            "filters or encode hidden data.",
                            snippet=_visible_line(text, i),
                            kind=kind,
                        )
                    )
                i = j
                continue
            i += 1
    return findings


def _visible_line(text: str, offset: int) -> str:
    start = text.rfind("\n", 0, offset) + 1
    end = text.find("\n", offset)
    line = text[start : end if end != -1 else len(text)]
    out = []
    for ch in line[:300]:
        cp = ord(ch)
        if cp in BIDI or cp in ZERO_WIDTH or cp == ZWJ or cp in TAG_RANGE or cp in VS_SUPPLEMENT:
            out.append(f"<U+{cp:04X}>")
        else:
            out.append(ch)
    return "".join(out)
