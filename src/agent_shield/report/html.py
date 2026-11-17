"""Self-contained HTML report (no external assets, all content escaped)."""

from __future__ import annotations

import html
from datetime import datetime, timezone

from .. import __version__
from ..models import ScanResult

_CSS = """
:root{--bg:#f7f7f8;--card:#fff;--fg:#1b1d22;--muted:#5d6370;--line:#e3e5e8;
--crit:#b3261e;--high:#d9480f;--med:#b7791f;--low:#2f6fb3;--info:#6b7280;--ok:#1f7a4d}
@media (prefers-color-scheme:dark){:root{--bg:#121316;--card:#1b1d22;--fg:#e8e9ec;--muted:#9aa0aa;
--line:#2c2f36;--crit:#ff6b62;--high:#ff8a4c;--med:#f2c14e;--low:#6fa8ff;--info:#9aa0aa;--ok:#4ccf8f}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Inter,sans-serif}
main{max-width:1080px;margin:0 auto;padding:24px 16px 64px}
h1{font-size:22px;margin:0 0 4px}.sub{color:var(--muted);font-size:13px;word-break:break-all}
.top{display:flex;gap:16px;flex-wrap:wrap;margin:20px 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px}
.score{font-size:44px;font-weight:700;line-height:1}.verdict{font-weight:700;text-transform:uppercase;
letter-spacing:.05em;font-size:13px;margin-top:6px}
.v-block{color:var(--crit)}.v-warn{color:var(--med)}.v-pass{color:var(--ok)}
.counts{display:flex;gap:10px;flex-wrap:wrap}.pill{border-radius:999px;padding:2px 10px;font-size:12px;
font-weight:600;border:1px solid currentColor;white-space:nowrap}
.s-critical{color:var(--crit)}.s-high{color:var(--high)}.s-medium{color:var(--med)}
.s-low{color:var(--low)}.s-info{color:var(--info)}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);
border-radius:10px;overflow:hidden}th,td{text-align:left;padding:10px 12px;border-top:1px solid var(--line);
vertical-align:top;font-size:14px}th{background:transparent;color:var(--muted);font-size:12px;
text-transform:uppercase;letter-spacing:.04em;border-top:0}
code,pre{font:12.5px/1.45 ui-monospace,SFMono-Regular,Menlo,monospace}
pre{white-space:pre-wrap;word-break:break-word;background:var(--bg);border:1px solid var(--line);
border-radius:6px;padding:8px;margin:6px 0 0;max-height:220px;overflow:auto}
.msg{color:var(--muted);font-size:13px}.judge{font-size:12.5px;margin-top:6px}
.wrap{overflow-x:auto}.empty{padding:24px;text-align:center;color:var(--ok)}
"""


def _e(s) -> str:
    return html.escape(str(s), quote=True)


def to_html(result: ScanResult) -> str:
    counts = result.counts()
    pills = "".join(
        f'<span class="pill s-{_e(k)}">{v} {_e(k)}</span>' for k, v in counts.items() if v
    ) or '<span class="pill s-info">no findings</span>'
    rows = []
    for f in result.findings:
        judge = ""
        if f.judge:
            if "verdict" in f.judge:
                orig = f" (was {_e(f.original_severity.label)})" if f.original_severity is not None else ""
                judge = (f'<div class="judge">LLM judge: <b>{_e(f.judge["verdict"])}</b> '
                         f'{f.judge.get("confidence", 0):.2f}{orig} &mdash; {_e(f.judge.get("reason", ""))}</div>')
            else:
                judge = f'<div class="judge">LLM judge: {_e(f.judge.get("error", "n/a"))}</div>'
        rows.append(
            "<tr>"
            f'<td><span class="pill s-{_e(f.severity.label)}">{_e(f.severity.label)}</span></td>'
            f"<td><code>{_e(f.rule_id)}</code><br><span class=msg>{_e(f.category)}</span></td>"
            f"<td><b>{_e(f.title)}</b><div class=msg>{_e(f.message)}</div>"
            f"{'<pre>' + _e(f.snippet) + '</pre>' if f.snippet else ''}{judge}</td>"
            f"<td><code>{_e(f.file)}:{f.line}</code></td>"
            "</tr>"
        )
    table = (
        '<div class="wrap"><table><thead><tr><th>Severity</th><th>Rule</th><th>Finding</th><th>Location</th>'
        f'</tr></thead><tbody>{"".join(rows)}</tbody></table></div>'
        if rows else '<div class="card empty">No findings.</div>'
    )
    errors = "".join(f"<li>{_e(e)}</li>" for e in result.errors)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>Agent Shield report</title><style>{_CSS}</style></head><body><main>
<h1>Agent Shield report</h1>
<div class="sub">{_e(result.root)} &middot; {result.files_scanned} files &middot; kinds: {_e(", ".join(result.kinds) or "none")}
&middot; LLM judge: {"on" if result.judge_used else "off"} &middot; {now} &middot; v{__version__}</div>
<div class="top">
 <div class="card"><div class="score">{result.score}</div><div class="msg">score / 100</div>
 <div class="verdict v-{_e(result.verdict)}">{_e(result.verdict)}</div></div>
 <div class="card" style="flex:1;min-width:240px"><div class="msg" style="margin-bottom:8px">Findings by severity</div>
 <div class="counts">{pills}</div>
 {f'<ul class="msg">{errors}</ul>' if errors else ''}</div>
</div>
{table}
</main></body></html>
"""
