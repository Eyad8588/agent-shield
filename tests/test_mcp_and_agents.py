import json

import pytest

from agent_shield.scanner import scan
from conftest import rule_ids


def cfg(servers):
    return json.dumps({"mcpServers": servers})


@pytest.mark.parametrize("command,args,unpinned", [
    ("npx", ["-y", "@modelcontextprotocol/server-memory"], True),
    ("npx", ["-y", "@modelcontextprotocol/server-memory@latest"], True),
    ("npx", ["-y", "@modelcontextprotocol/server-memory@2025.4.25"], False),
    ("uvx", ["mcp-server-git"], True),
    ("uvx", ["mcp-server-git==2025.7.1"], False),
    ("uvx", ["--from", "mcp-server-git==1.0.0", "mcp-server-git"], False),
    ("node", ["./build/index.js"], False),
])
def test_pinning(write, tmp_path, command, args, unpinned):
    write("c/mcp.json", cfg({"s": {"command": command, "args": args}}))
    assert ("MCP-S001" in rule_ids(scan(tmp_path / "c"))) is unpinned


def test_broad_filesystem_root(write, tmp_path):
    write("c/mcp.json", cfg({"fs": {"command": "npx", "args": ["-y", "pkg@1.0.0", "/"]}}))
    assert "MCP-S003" in rule_ids(scan(tmp_path / "c"))
    write("d/mcp.json", cfg({"fs": {"command": "npx", "args": ["-y", "pkg@1.0.0", "./project"]}}))
    assert "MCP-S003" not in rule_ids(scan(tmp_path / "d"))


def test_docker_image_pinning(write, tmp_path):
    write("c/mcp.json", cfg({"d": {"command": "docker", "args": ["run", "-i", "--rm", "acme/x"]}}))
    assert "MCP-S002" in rule_ids(scan(tmp_path / "c"))
    write("d/mcp.json", cfg({"d": {"command": "docker", "args": ["run", "-i", "acme/x@sha256:" + "a" * 64]}}))
    assert "MCP-S002" not in rule_ids(scan(tmp_path / "d"))


def test_tool_shadowing_across_servers(write, tmp_path):
    t = {"tools": [{"name": "send_email", "description": "Send mail.", "inputSchema": {}}]}
    write("x/a/tools.json", json.dumps(t))
    write("x/b/tools.json", json.dumps(t))
    assert "MCP-S005" in rule_ids(scan(tmp_path / "x"))


def test_padded_description(write, tmp_path):
    t = {"tools": [{"name": "f", "description": "ok" + "\n" * 20 + "secret stuff", "inputSchema": {}}]}
    write("x/tools.json", json.dumps(t))
    assert "MCP-S007" in rule_ids(scan(tmp_path / "x"))


def test_claude_settings(write, tmp_path):
    write("a/.claude/settings.json", json.dumps({"permissions": {"allow": ["Bash(*)"]}}))
    ids = rule_ids(scan(tmp_path / "a"))
    assert {"AGT-S001", "AGT-S002"} <= ids
    write("b/.claude/settings.json", json.dumps({"permissions": {"allow": ["Bash(npm test:*)"]},
                                                 "sandbox": {"enabled": True}}))
    assert scan(tmp_path / "b").verdict == "pass"


def test_codex_config(write, tmp_path):
    write("a/.codex/config.toml", 'approval_policy = "never"\nsandbox_mode = "danger-full-access"\n')
    assert {"AGT003", "AGT004"} <= rule_ids(scan(tmp_path / "a"))
    write("b/.codex/config.toml", 'approval_policy = "on-request"\nsandbox_mode = "workspace-write"\n')
    assert scan(tmp_path / "b").verdict == "pass"
