"""Structural agent-config checks (Claude Code, Codex, generic YAML/JSON).

  AGT-S001 unrestricted shell in permission allow-list       high
  AGT-S002 no sandbox configured                             medium
  AGT-S003 all project MCP servers auto-enabled              medium
  AGT-S004 wildcard allow of every tool                      critical
"""

from __future__ import annotations

import re

from ..discovery import ScanFile
from ..models import Finding, Severity
from .mcp import _load_structured

SHELL_WILDCARDS = re.compile(r"^(Bash|Shell|shell|bash|run_terminal_cmd|execute_command)(\(\s*\*?\s*(:\s*\*)?\s*\))?$")


def _walk(obj, path=()):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield path + (str(k),), v
            yield from _walk(v, path + (str(k),))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _walk(v, path + (str(i),))


def check_agent_configs(files: list[ScanFile]) -> list[Finding]:
    findings: list[Finding] = []
    for f in files:
        if "agent_config" not in f.kinds:
            continue
        data = _load_structured(f)
        text = f.text()

        def add(rule_id, title, sev, msg, snippet, needle):
            idx = text.find(needle) if needle else -1
            findings.append(Finding(rule_id=rule_id, title=title, severity=sev, category="agent-config",
                                    file=f.rel, line=text.count("\n", 0, idx) + 1 if idx >= 0 else 1,
                                    message=msg, snippet=snippet[:300], kind="agent_config"))

        if isinstance(data, dict):
            perms = data.get("permissions")
            allow = perms.get("allow", []) if isinstance(perms, dict) else []
            for entry in allow if isinstance(allow, list) else []:
                e = str(entry).strip()
                if e == "*":
                    add("AGT-S004", "Every tool allowed without prompting", Severity.CRITICAL,
                        "permissions.allow contains '*', so every tool runs without approval.", e, '"*"')
                elif SHELL_WILDCARDS.match(e):
                    add("AGT-S001", "Unrestricted shell allowed", Severity.HIGH,
                        f"permissions.allow contains '{e}', letting the agent run any shell command without "
                        "asking. Allow specific commands, e.g. Bash(npm test:*).", e, e)
            if data.get("enableAllProjectMcpServers") is True:
                add("AGT-S003", "All project MCP servers auto-enabled", Severity.MEDIUM,
                    "Any MCP server added to the repo's .mcp.json starts without review.",
                    "enableAllProjectMcpServers: true", "enableAllProjectMcpServers")

        if not re.search(r"(?i)\bsandbox", text):
            add("AGT-S002", "No sandbox configured", Severity.MEDIUM,
                "This agent config does not enable a sandbox. Configure one (e.g. Codex sandbox_mode = "
                "\"workspace-write\", Claude Code \"sandbox\": {\"enabled\": true}, or run in a container).",
                "", "")
    return findings
