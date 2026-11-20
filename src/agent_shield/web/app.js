// Agent Shield GUI. All scanned text is untrusted: render with textContent only.
"use strict";

const $ = (id) => document.getElementById(id);
const state = { files: [], status: null, filter: null, current: null, busy: false };

function el(tag, attrs = {}, ...children) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") n.className = v;
    else if (k === "text") n.textContent = v;
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else n.setAttribute(k, v);
  }
  for (const c of children) if (c != null) n.append(c);
  return n;
}

function toast(msg) {
  const t = $("toast");
  t.textContent = msg;
  t.classList.add("show");
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => t.classList.remove("show"), 3200);
}

const fmtBytes = (n) => (n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`);

// ------------------------------------------------------------ file picking --

function addFiles(list) {
  for (const { file, path } of list) {
    if (!state.files.some((f) => f.path === path)) state.files.push({ file, path });
  }
  renderFiles();
}

function renderFiles() {
  const ul = $("files");
  ul.replaceChildren();
  for (const f of state.files) {
    ul.append(el("li", {},
      el("code", { title: f.path, text: f.path }),
      el("span", {}, el("span", { class: "hint", text: fmtBytes(f.file.size) + " " }),
        el("button", { class: "x", type: "button", "aria-label": `Remove ${f.path}`, text: "✕",
          onclick: () => { state.files = state.files.filter((x) => x !== f); renderFiles(); } }))));
  }
  const total = state.files.reduce((s, f) => s + f.file.size, 0);
  $("meta").textContent = state.files.length ? `${state.files.length} file${state.files.length > 1 ? "s" : ""} · ${fmtBytes(total)}` : "";
  $("clear").hidden = !state.files.length;
  $("scan").disabled = !state.files.length || state.busy;
}

// Walk dropped folders (FileSystemEntry API), keeping relative paths.
async function entryFiles(entry, prefix = "") {
  if (entry.isFile) {
    const file = await new Promise((res, rej) => entry.file(res, rej));
    return [{ file, path: prefix + entry.name }];
  }
  const reader = entry.createReader();
  const out = [];
  for (;;) {
    const batch = await new Promise((res, rej) => reader.readEntries(res, rej));
    if (!batch.length) break;
    for (const e of batch) out.push(...(await entryFiles(e, `${prefix}${entry.name}/`)));
  }
  return out;
}

function setupDrop() {
  const drop = $("drop");
  drop.addEventListener("click", () => $("in-files").click());
  drop.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); $("in-files").click(); } });
  ["dragenter", "dragover"].forEach((t) => drop.addEventListener(t, (e) => { e.preventDefault(); drop.classList.add("over"); }));
  ["dragleave", "drop"].forEach((t) => drop.addEventListener(t, () => drop.classList.remove("over")));
  drop.addEventListener("drop", async (e) => {
    e.preventDefault();
    const items = [...(e.dataTransfer.items || [])].map((i) => i.webkitGetAsEntry && i.webkitGetAsEntry()).filter(Boolean);
    if (items.length) {
      const all = [];
      for (const it of items) all.push(...(await entryFiles(it)));
      addFiles(all);
    } else {
      addFiles([...e.dataTransfer.files].map((f) => ({ file: f, path: f.name })));
    }
  });
  $("pick-files").addEventListener("click", () => $("in-files").click());
  $("pick-folder").addEventListener("click", () => $("in-folder").click());
  $("in-files").addEventListener("change", (e) => { addFiles([...e.target.files].map((f) => ({ file: f, path: f.name }))); e.target.value = ""; });
  $("in-folder").addEventListener("change", (e) => { addFiles([...e.target.files].map((f) => ({ file: f, path: f.webkitRelativePath || f.name }))); e.target.value = ""; });
  $("clear").addEventListener("click", () => { state.files = []; renderFiles(); });
}

// ------------------------------------------------------------------ status --

async function loadStatus() {
  const s = await (await fetch("/api/status")).json();
  state.status = s;
  $("foot").textContent = `agent-shield v${s.version} · runs locally on 127.0.0.1`;
  const sel = $("model");
  sel.replaceChildren(...s.models.map((m) => el("option", { value: m, text: m })));
  if (s.models.includes(s.default_model)) sel.value = s.default_model;
  const js = $("judge-status");
  js.replaceChildren(el("span", { class: "dot" + (s.ollama && s.models.length ? " on" : "") }));
  if (!s.ollama) {
    js.append("Ollama isn't running, so the judge is off. Static rules still work.");
    $("judge").disabled = true;
  } else if (!s.models.length) {
    js.append("Ollama is running but has no models pulled.");
    $("judge").disabled = true;
  } else {
    js.append(`Ollama ready · ${s.models.length} model${s.models.length > 1 ? "s" : ""}. Slower, but clears false positives.`);
  }
  $("judge").addEventListener("change", () => { sel.hidden = !$("judge").checked; });
  if (s.samples) loadSamples();
}

async function loadSamples() {
  const list = await (await fetch("/api/samples")).json();
  if (!list.length) return;
  $("samples-card").hidden = false;
  const box = $("samples");
  for (const group of ["malicious", "clean"]) {
    const items = list.filter((s) => s.group === group);
    if (!items.length) continue;
    box.append(el("div", { class: "group", text: group === "malicious" ? "Malicious (inert)" : "Clean" }));
    box.append(el("div", { class: "chips" }, ...items.map((s) =>
      el("button", { class: `chip ${group === "malicious" ? "mal" : "cln"}`, type: "button", text: s.name,
        onclick: () => scanSample(s.path) }))));
  }
}

// -------------------------------------------------------------------- scan --

function setBusy(on, label = "Scanning…") {
  state.busy = on;
  const b = $("scan");
  b.replaceChildren(on ? el("span", { class: "spinner" }) : "", on ? ` ${label}` : "Scan");
  b.disabled = on || !state.files.length;
  document.querySelectorAll(".chip").forEach((c) => { c.disabled = on; });
}

function judgeParams() {
  return { judge: $("judge").checked, model: $("model").value };
}

async function scanUpload() {
  if (!state.files.length || state.busy) return;
  const { judge, model } = judgeParams();
  const fd = new FormData();
  for (const f of state.files) fd.append("file", f.file, f.path);
  if (judge) { fd.append("judge", "on"); fd.append("judge_model", model); }
  await runScan(() => fetch("/api/scan", { method: "POST", body: fd }), judge);
}

async function scanSample(path) {
  if (state.busy) return;
  const { judge, model } = judgeParams();
  await runScan(() => fetch("/api/scan-sample", { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ path, judge, judge_model: model }) }), judge);
}

async function runScan(send, judge) {
  setBusy(true, judge ? "Scanning with AI judge…" : "Scanning…");
  try {
    const r = await send();
    const data = await r.json();
    if (!r.ok) throw new Error(data.error || `HTTP ${r.status}`);
    state.filter = null;
    showResult(data);
    loadHistory();
  } catch (e) {
    toast(`Scan failed: ${e.message}`);
  } finally {
    setBusy(false);
  }
}

// ----------------------------------------------------------------- results --

const SEVS = ["critical", "high", "medium", "low", "info"];

function showResult(r) {
  state.current = r;
  $("empty").hidden = true;
  $("out").hidden = false;
  $("r-score").textContent = r.score;
  const v = $("r-verdict");
  v.textContent = r.verdict;
  v.className = `verdict v-${r.verdict}`;
  $("r-label").textContent = r.label;
  $("r-sub").textContent = `${r.files_scanned} file${r.files_scanned === 1 ? "" : "s"} · kinds: ${r.kinds.join(", ") || "none detected"} · AI judge: ${r.judge_used ? "on" : "off"}`;
  const pills = $("r-pills");
  pills.replaceChildren();
  for (const s of SEVS) {
    const n = r.counts[s] || 0;
    if (!n) continue;
    const p = el("button", { class: `pill s-${s}${state.filter === s ? " active" : ""}`, type: "button",
      title: "Filter findings", onclick: () => { state.filter = state.filter === s ? null : s; showResult(r); } },
      el("span", { text: `${n} ${s}` }));
    pills.append(p);
  }
  if (!pills.children.length) pills.append(el("span", { class: "pill s-info", text: "no findings" }));
  $("r-errors").replaceChildren(...r.errors.map((e) => el("li", { text: e })));
  $("a-html").href = `/report/${r.id}.html`;
  $("a-sarif").href = `/report/${r.id}.sarif`;
  $("a-json").href = `/report/${r.id}.json`;

  const list = state.filter ? r.findings.filter((f) => f.severity === state.filter) : r.findings;
  $("r-count").textContent = r.findings.length
    ? `${list.length} finding${list.length === 1 ? "" : "s"}${state.filter ? ` · ${state.filter} only` : ""}`
    : "No findings";
  const box = $("r-findings");
  box.replaceChildren();
  for (const f of list) {
    const judge = f.judge
      ? el("div", { class: "jv", text: f.judge.verdict
          ? `AI judge: ${f.judge.verdict} (${Number(f.judge.confidence || 0).toFixed(2)})${f.original_severity ? ` · was ${f.original_severity}` : ""} — ${f.judge.reason || ""}`
          : `AI judge: ${f.judge.error || "n/a"}` })
      : null;
    box.append(el("div", { class: "finding" },
      el("div", { class: "top" },
        el("span", { class: `pill s-${f.severity}`, text: f.severity }),
        el("span", { class: "title", text: f.title }),
        el("span", { class: "loc", text: `${f.file}:${f.line}` })),
      el("div", { class: "rule", text: `${f.rule_id} · ${f.category}` }),
      f.message ? el("div", { class: "msg", text: f.message }) : null,
      f.snippet ? el("pre", { text: f.snippet }) : null,
      judge));
  }
  if (!r.findings.length) box.append(el("div", { class: "empty", text: "Nothing suspicious matched the rules. A pass is evidence, not a guarantee." }));
}

async function loadHistory() {
  const items = await (await fetch("/api/history")).json();
  $("history-empty").hidden = items.length > 0;
  $("history").replaceChildren(...items.map((h) => el("li", {
    tabindex: "0", onclick: () => openScan(h.id), onkeydown: (e) => { if (e.key === "Enter") openScan(h.id); } },
    el("span", { class: `verdict v-${h.verdict}`, text: h.verdict, style: "margin:0;font-size:11px;padding:1px 8px" }),
    el("span", { class: "h-label", text: h.label, title: h.label }),
    el("span", { class: "h-time", text: `${h.score} · ${h.time}` }))));
}

async function openScan(id) {
  const r = await fetch(`/api/scan/${id}`);
  if (r.ok) { state.filter = null; showResult(await r.json()); }
}

setupDrop();
$("scan").addEventListener("click", scanUpload);
loadStatus().catch(() => toast("Could not reach the agent-shield server"));
loadHistory();
