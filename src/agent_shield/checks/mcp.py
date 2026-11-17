"""Structural MCP checks: parse server configs and tool manifests.

  MCP-S001 unpinned package launched by npx/uvx/pipx/bunx       medium
  MCP-S002 container image without tag/digest (or :latest)       medium
  MCP-S003 filesystem server rooted at / or the home directory    high
  MCP-S004 remote server over plain HTTP                         medium
  MCP-S005 tool name shadowing (duplicate across servers)         high
  MCP-S006 tool name collides with a well-known agent tool        low
  MCP-S007 tool description hides content (padding / very long)   high/medium
  MCP-S008 shell wrapper as server command (sh -c "...")          medium
"""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

import yaml

from ..discovery import ScanFile
from ..models import Finding, Severity

LAUNCHERS = {"npx", "bunx", "uvx", "pipx", "pnpm", "yarn", "npm"}
PINNED_NPM = re.compile(r"^(@[\w.-]+/)?[\w.-]+@(\d+\.\d+\.\d+[\w.+-]*|sha\d+:[a-f0-9]+)$")
PINNED_PY = re.compile(r"^[\w.\[\],-]+(==|@)\d+[\w.]*$")
WELL_KNOWN_TOOLS = {
    "bash", "shell", "execute_command", "run_terminal_cmd", "terminal", "read_file", "write_file",
    "edit_file", "str_replace_editor", "send_email", "web_fetch", "fetch", "web_search", "computer",
    "Bash", "Read", "Write", "Edit", "Glob", "Grep", "WebFetch", "WebSearch", "Task",
}
BROAD_ROOTS = {"/", "~", "~/", "$HOME", "${HOME}", "/Users", "/home", "C:\\", "C:/"}


def _load_structured(f: ScanFile):
    text = f.text()
    suffix = f.path.suffix.lower()
    try:
        if suffix in {".json", ".jsonc"}:
            cleaned = re.sub(r"(?m)^\s*//.*$", "", text) if suffix == ".jsonc" else text
            return json.loads(cleaned)
        if suffix in {".yaml", ".yml"}:
            return yaml.safe_load(text)
        if suffix == ".toml":
            return tomllib.loads(text)
    except (ValueError, yaml.YAMLError, tomllib.TOMLDecodeError):
        return None
    return None


def _servers(data) -> dict:
    if not isinstance(data, dict):
        return {}
    for key in ("mcpServers", "mcp_servers", "servers"):
        val = data.get(key)
        if isinstance(val, dict):
            return {k: v for k, v in val.items() if isinstance(v, dict)}
    # VS Code style {"mcp": {"servers": {...}}}
    if isinstance(data.get("mcp"), dict):
        return _servers(data["mcp"])
    return {}


def _tools(data) -> list[dict]:
    if isinstance(data, dict) and isinstance(data.get("tools"), list):
        return [t for t in data["tools"] if isinstance(t, dict) and "name" in t]
    if isinstance(data, list):
        return [t for t in data if isinstance(t, dict) and "name" in t and "description" in t]
    return []


def _line_of(text: str, needle: str) -> int:
    idx = text.find(needle)
    return text.count("\n", 0, idx) + 1 if idx >= 0 else 1


def _package_arg(command: str, args: list[str]) -> str | None:
    cmd = Path(command).name
    rest = list(args)
    if cmd in {"pnpm", "yarn"} and rest[:1] == ["dlx"]:
        rest = rest[1:]
    elif cmd == "npm" and rest[:1] == ["exec"]:
        rest = rest[1:]
    elif cmd == "pipx" and rest[:1] == ["run"]:
        rest = rest[1:]
    elif cmd in {"pnpm", "yarn", "npm"}:
        return None
    skip_next = False
    for a in rest:
        if skip_next:
            skip_next = False
            continue
        if a in {"--from", "--package", "-p", "--with"}:
            skip_next = cmd in {"uvx", "pipx"} and a != "--from"
            if a == "--from":
                # uvx --from pkg==1.0 tool  -> the --from value is the package
                idx = rest.index(a)
                return rest[idx + 1] if idx + 1 < len(rest) else None
            continue
        if a.startswith("-"):
            continue
        return a
    return None


def _is_pinned(cmd: str, pkg: str) -> bool:
    if pkg.startswith((".", "/", "file:", "git+")):
        return "#" in pkg or "@" in pkg.split("/")[-1] or pkg.startswith((".", "/", "file:"))
    if Path(cmd).name in {"uvx", "pipx"}:
        return bool(PINNED_PY.match(pkg))
    return bool(PINNED_NPM.match(pkg)) and not pkg.endswith("@latest")


def check_mcp(files: list[ScanFile]) -> list[Finding]:
    findings: list[Finding] = []
    tool_owners: dict[str, list[tuple[str, int]]] = {}

    for f in files:
        if "mcp" not in f.kinds or f.path.suffix.lower() not in {".json", ".jsonc", ".yaml", ".yml", ".toml"}:
            continue
        data = _load_structured(f)
        if data is None:
            continue
        text = f.text()

        def add(rule_id, title, sev, msg, snippet, needle, category="mcp"):
            findings.append(Finding(rule_id=rule_id, title=title, severity=sev, category=category,
                                    file=f.rel, line=_line_of(text, needle), message=msg,
                                    snippet=snippet[:400], kind="mcp"))

        for name, srv in _servers(data).items():
            command = str(srv.get("command", ""))
            args = [str(a) for a in srv.get("args", []) if a is not None]
            cmd = Path(command).name
            if cmd in LAUNCHERS:
                pkg = _package_arg(command, args)
                if pkg and not _is_pinned(cmd, pkg):
                    add("MCP-S001", "Unpinned MCP server package", Severity.MEDIUM,
                        f"Server '{name}' runs '{pkg}' via {cmd} without an exact version, so every launch "
                        "may fetch new, unreviewed code. Pin an exact version (pkg@1.2.3 / pkg==1.2.3).",
                        f"{command} {' '.join(args)}", pkg, "supply-chain")
            if cmd in {"docker", "podman"} and "run" in args:
                image = _docker_image(args)
                if image and ("@sha256:" not in image) and (":" not in image.split("/")[-1] or image.endswith(":latest")):
                    add("MCP-S002", "Container image not pinned", Severity.MEDIUM,
                        f"Server '{name}' runs image '{image}' without a fixed tag or digest.",
                        f"{command} {' '.join(args)}", image, "supply-chain")
            if cmd in {"sh", "bash", "zsh", "cmd", "powershell", "pwsh"} and any(a in {"-c", "/c", "-Command"} for a in args):
                add("MCP-S008", "Server launched through a shell wrapper", Severity.MEDIUM,
                    f"Server '{name}' is started with an inline shell script, which hides what actually runs.",
                    f"{command} {' '.join(args)}", command, "risky-exec")
            for a in args:
                if a.rstrip("/\\") in {r.rstrip("/\\") for r in BROAD_ROOTS} or a in BROAD_ROOTS or re.fullmatch(r"/(Users|home)/[^/]+/?", a):
                    add("MCP-S003", "Over-broad filesystem root", Severity.HIGH,
                        f"Server '{name}' is given access to '{a}'. Grant only the project directory.",
                        f"{command} {' '.join(args)}", a, "over-broad-permissions")
                    break
            url = str(srv.get("url", "") or srv.get("serverUrl", ""))
            if url.startswith("http://") and not re.match(r"http://(localhost|127\.0\.0\.1|\[::1\])", url):
                add("MCP-S004", "Remote MCP server over plain HTTP", Severity.MEDIUM,
                    f"Server '{name}' uses unencrypted HTTP; tool calls and tokens can be intercepted.",
                    url, url, "network")

        for tool in _tools(data):
            tname = str(tool.get("name"))
            desc = str(tool.get("description", ""))
            tool_owners.setdefault(tname, []).append((f.rel, _line_of(text, f'"{tname}"')))
            if tname in WELL_KNOWN_TOOLS:
                add("MCP-S006", "Tool name collides with a well-known agent tool", Severity.LOW,
                    f"Tool '{tname}' has the same name as a common built-in tool; agents may call the wrong one.",
                    tname, f'"{tname}"', "tool-shadowing")
            if re.search(r"\n{6,}|[ \t]{80,}", desc):
                add("MCP-S007", "Tool description padded to hide content", Severity.HIGH,
                    f"Tool '{tname}' has long runs of blank space, typically used to push instructions out of view "
                    "in approval dialogs.", desc[:200], f'"{tname}"', "tool-poisoning")
            elif len(desc) > 1500:
                add("MCP-S007", "Very long tool description", Severity.MEDIUM,
                    f"Tool '{tname}' description is {len(desc)} characters; review it for embedded instructions.",
                    desc[:200], f'"{tname}"', "tool-poisoning")

    for tname, owners in tool_owners.items():
        distinct = sorted({o[0] for o in owners})
        if len(distinct) > 1:
            for rel, line in owners:
                findings.append(Finding(
                    rule_id="MCP-S005", title="Tool name shadowing across servers", severity=Severity.HIGH,
                    category="tool-shadowing", file=rel, line=line, kind="mcp",
                    message=f"Tool '{tname}' is defined by several servers ({', '.join(distinct)}); one can "
                    "hijack calls meant for the other.",
                    snippet=tname,
                ))
    return findings


def _docker_image(args: list[str]) -> str | None:
    try:
        i = args.index("run") + 1
    except ValueError:
        return None
    takes_value = {"-e", "--env", "-v", "--volume", "--name", "--network", "-p", "--publish", "--mount",
                   "-w", "--workdir", "--user", "-u", "--entrypoint", "--env-file", "--platform"}
    while i < len(args):
        a = args[i]
        if a in takes_value:
            i += 2
            continue
        if a.startswith("-"):
            i += 1
            continue
        return a
    return None
