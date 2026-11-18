"""Regenerate the README screenshots in docs/screenshots/.

Runs real scans, wraps their output in small HTML pages (terminal view, eval
chart, SARIF view), and renders PNGs with headless Chrome using a throwaway
profile. Usage:

    uv run python scripts/make_screenshots.py [--no-judge]
"""

from __future__ import annotations

import html
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SHOTS = ROOT / "docs" / "screenshots"
WORK = ROOT / "out" / "shots"
CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
ANSI = re.compile(r"\x1b\[[0-9;]*m")

BASE_CSS = """
*{box-sizing:border-box}body{margin:0;background:#eef0f3;font:15px/1.5 -apple-system,BlinkMacSystemFont,
"Segoe UI",Inter,sans-serif;color:#1b1d22;padding:28px}
.term{background:#15171c;border-radius:12px;box-shadow:0 10px 30px rgba(0,0,0,.18);overflow:hidden}
.bar{background:#24272e;padding:10px 14px;display:flex;gap:8px;align-items:center}
.dot{width:12px;height:12px;border-radius:50%}.title{color:#9aa0aa;font-size:12px;margin-left:10px;
font-family:ui-monospace,Menlo,monospace}
pre{margin:0;padding:18px 20px;color:#d7dae0;font:13.5px/1.6 ui-monospace,SFMono-Regular,Menlo,monospace;
white-space:pre}
.p{color:#7ee787}.c{color:#ff6b62;font-weight:700}.h{color:#ff9e4a;font-weight:700}.m{color:#e6c34d}
.l{color:#6fa8ff}.blk{color:#ff6b62;font-weight:700}.pass{color:#4ccf8f;font-weight:700}.dim{color:#8b919c}
"""


def run(args: list[str]) -> str:
    out = subprocess.run([sys.executable, "-m", "agent_shield.cli", *args], cwd=ROOT,
                         capture_output=True, text=True)
    return ANSI.sub("", out.stdout)


def colorize(text: str) -> str:
    out = []
    for line in html.escape(text).splitlines():
        line = re.sub(r"^(  )(CRITICAL)", r'\1<span class="c">\2</span>', line)
        line = re.sub(r"^(  )(HIGH)", r'\1<span class="h">\2</span>', line)
        line = re.sub(r"^(  )(MEDIUM)", r'\1<span class="m">\2</span>', line)
        line = re.sub(r"^(  )(LOW)", r'\1<span class="l">\2</span>', line)
        line = line.replace("verdict: BLOCK", 'verdict: <span class="blk">BLOCK</span>')
        line = line.replace("verdict: PASS", 'verdict: <span class="pass">PASS</span>')
        line = re.sub(r"(\[judge: [^\]]+\])", r'<span class="dim">\1</span>', line)
        if line.startswith(("  (+", "  note:", "reports written")):
            line = f'<span class="dim">{line}</span>'
        out.append(line)
    return "\n".join(out)


def terminal_page(cmd: str, output: str) -> str:
    body = f'<span class="p">$</span> {html.escape(cmd)}\n{colorize(output)}'
    return f"""<!doctype html><meta charset="utf-8"><style>{BASE_CSS}</style>
<div class="term"><div class="bar"><span class="dot" style="background:#ff5f57"></span>
<span class="dot" style="background:#febc2e"></span><span class="dot" style="background:#28c840"></span>
<span class="title">agent-shield</span></div><pre>{body}</pre></div>"""


def eval_page(eval_md: str) -> str:
    rows = []
    for line in eval_md.splitlines():
        m = re.match(r"\| (Static[^|]*) \| (\d+) \| (\d+) \| (\d+) \| (\d+) \| ([\d.]+) \| ([\d.]+) \| ([\d.]+) \|", line)
        if m and len(rows) < 3:
            rows.append(m.groups())
    names = ["Static rules only", "+ local judge (hardening off)", "+ local judge (hardened)"]
    bars = []
    for name, r in zip(names, rows):
        p, rc = float(r[5]), float(r[6])
        bars.append(f"""<div class="row"><div class="name">{name}<div class="sub">TP {r[1]} · FP {r[2]} · FN {r[3]}
 · TN {r[4]}</div></div><div class="bars">
<div class="b"><span class="lab">precision</span><div class="track"><div class="fill pr" style="width:{p*100:.0f}%"></div>
</div><span class="v">{p:.2f}</span></div>
<div class="b"><span class="lab">recall</span><div class="track"><div class="fill rc" style="width:{rc*100:.0f}%"></div>
</div><span class="v">{rc:.2f}</span></div></div></div>""")
    judge = re.findall(r"\| (hardening off|hardened) \| (\d+) \| (\d+) \| (\d+) \| (\d+) \|", eval_md)
    jrows = "".join(f"<tr><td>{a}</td><td>{b}</td><td class='{'bad' if c != '0' else 'ok'}'>{c}</td>"
                    f"<td>{d}</td><td>{e}</td></tr>" for a, b, c, d, e in judge)
    css = BASE_CSS + """
.card{background:#fff;border-radius:12px;padding:24px 28px;box-shadow:0 6px 24px rgba(0,0,0,.08)}
h1{font-size:20px;margin:0 0 4px}.lead{color:#5d6370;font-size:13.5px;margin:0 0 20px}
.row{display:flex;gap:20px;align-items:center;padding:12px 0;border-top:1px solid #e8eaee}
.name{width:250px;font-weight:600}.sub{font-weight:400;color:#6b7280;font-size:12px}
.bars{flex:1}.b{display:flex;align-items:center;gap:10px;margin:3px 0}.lab{width:70px;font-size:12px;color:#5d6370}
.track{flex:1;background:#eef0f3;border-radius:4px;height:14px}.fill{height:14px;border-radius:4px}
.pr{background:#2f6fb3}.rc{background:#1f7a4d}.v{width:40px;font-variant-numeric:tabular-nums;font-weight:600}
table{border-collapse:collapse;width:100%;margin-top:6px;font-size:13.5px}th,td{text-align:left;padding:7px 10px;
border-top:1px solid #e8eaee}th{color:#5d6370;font-size:12px;font-weight:600}.bad{color:#b3261e;font-weight:700}
.ok{color:#1f7a4d;font-weight:700}h2{font-size:15px;margin:24px 0 2px}"""
    return f"""<!doctype html><meta charset="utf-8"><style>{css}</style><div class="card">
<h1>Corpus evaluation</h1><p class="lead">29 malicious (inert) and 13 clean samples · skills, MCP servers,
agent configs, model files · judge: qwen3.5:4b via Ollama</p>{''.join(bars)}
<h2>Judge mistakes, counted per finding</h2><table><tr><th>Judge</th><th>Findings reviewed on malicious samples</th>
<th>Wrongly downgraded</th><th>Findings on clean samples</th><th>Correctly downgraded</th></tr>{jrows}</table></div>"""


def sarif_page(sarif: dict) -> str:
    run_ = sarif["runs"][0]
    result = run_["results"][0]
    rule = next(r for r in run_["tool"]["driver"]["rules"] if r["id"] == result["ruleId"])
    excerpt = {"tool": {"driver": {"name": "agent-shield", "rules": [{k: rule[k] for k in
               ("id", "shortDescription", "properties")}]}},
               "results": [{k: result[k] for k in ("ruleId", "level", "message", "locations")}]}
    msg = excerpt["results"][0]["message"]["text"]
    excerpt["results"][0]["message"]["text"] = msg if len(msg) < 70 else msg[:67] + "..."
    text = html.escape(json.dumps(excerpt, indent=2))
    text = re.sub(r"(&quot;[\w$-]+&quot;)(:)", r'<span class="k">\1</span>\2', text)
    css = BASE_CSS + ".k{color:#79c0ff}pre{font-size:12.5px;white-space:pre-wrap}"
    n = len(run_["results"])
    return f"""<!doctype html><meta charset="utf-8"><style>{css}</style><div class="term"><div class="bar">
<span class="dot" style="background:#ff5f57"></span><span class="dot" style="background:#febc2e"></span>
<span class="dot" style="background:#28c840"></span><span class="title">agent-shield.sarif ({n} results,
first shown) - uploaded to GitHub code scanning</span></div><pre>{text}</pre></div>"""


def shoot(page: Path, png: Path, width: int, height: int) -> None:
    with tempfile.TemporaryDirectory() as profile:
        subprocess.run([CHROME, "--headless=new", "--disable-gpu", "--hide-scrollbars", "--no-first-run",
                        "--no-default-browser-check", f"--user-data-dir={profile}",
                        f"--window-size={width},{height}", "--force-device-scale-factor=2",
                        f"--screenshot={png}", page.as_uri()],
                       check=True, capture_output=True, timeout=120)
    print(f"wrote {png.relative_to(ROOT)}")


def main() -> None:
    judge = "--no-judge" not in sys.argv
    WORK.mkdir(parents=True, exist_ok=True)
    SHOTS.mkdir(parents=True, exist_ok=True)
    jflag = ["--judge"] if judge else []

    bad = "corpus/malicious/skill-ssh-stealer"
    out_bad = run(["scan", bad, "--out", str(WORK / "bad"), "--format", "text,html,sarif"])
    out_bad = out_bad.replace(str(WORK), "out")
    (WORK / "cli_bad.html").write_text(terminal_page(f"agent-shield scan {bad}", out_bad))

    report_target = "corpus/malicious/skill-prompt-injection"
    run(["scan", report_target, "--out", str(WORK / "report"), "--format", "html", *jflag])

    clean = "corpus/clean"
    out_clean = run(["scan", clean, "--format", "text", *jflag])
    (WORK / "cli_clean.html").write_text(terminal_page(f"agent-shield scan {clean} {' '.join(jflag)}".strip(),
                                                       out_clean))

    (WORK / "eval.html").write_text(eval_page((ROOT / "reports" / "eval.md").read_text()))
    sarif = json.loads((WORK / "bad" / "agent-shield.sarif").read_text())
    (WORK / "sarif.html").write_text(sarif_page(sarif))

    shoot(WORK / "cli_bad.html", SHOTS / "cli-scan-malicious.png", 1100, 330)
    shoot(WORK / "report" / "agent-shield.html", SHOTS / "html-report.png", 1180, 900)
    shoot(WORK / "cli_clean.html", SHOTS / "cli-scan-clean.png", 1100, 210)
    shoot(WORK / "eval.html", SHOTS / "eval-results.png", 1000, 580)
    shoot(WORK / "sarif.html", SHOTS / "sarif-output.png", 900, 1010)
    shutil.rmtree(WORK / "bad", ignore_errors=True)


if __name__ == "__main__":
    main()
