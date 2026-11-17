"""Walk a scan target and decide which artifact kinds each file belongs to.

Kinds:
  skill         SKILL.md and every file in a directory tree rooted at a SKILL.md
  mcp           MCP configs, tool manifests, and source of MCP servers
  agent_config  coding-agent settings (Claude Code, Codex, Cursor, generic YAML)
  model         serialized model weights (pickle-based or safetensors)
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

MODEL_SUFFIXES = {".pt", ".pth", ".bin", ".pkl", ".pickle", ".ckpt", ".joblib", ".safetensors", ".npy", ".npz"}
TEXT_SUFFIXES = {
    ".md", ".markdown", ".txt", ".py", ".js", ".mjs", ".cjs", ".ts", ".sh", ".bash", ".zsh",
    ".json", ".jsonc", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".html", ".ps1", ".rb", ".go", "",
}
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".mypy_cache", ".pytest_cache"}
MAX_TEXT_BYTES = 2 * 1024 * 1024

_MCP_SOURCE = re.compile(
    r"@modelcontextprotocol/sdk|from\s+mcp(\.server)?\s+import|import\s+mcp\b|FastMCP\(|McpServer\(|mcp\.server\.fastmcp"
)
_MCP_CONFIG_KEYS = ("mcpServers", "mcp_servers", "\"servers\"")
_AGENT_CONFIG_KEYS = re.compile(
    r"(?i)\b(approval_?policy|sandbox(_?mode)?|defaultMode|auto_?approve|autoApprove|allowed_?commands|"
    r"dangerously|permissions|always_?allow|allow_?shell|yolo)\b"
)
_AGENT_CONFIG_NAMES = {
    "settings.json", "settings.local.json", "config.toml", "agent.yaml", "agent.yml",
    "agent.json", ".cursorrules", "codex.toml", "opencode.json", "crush.json", "aider.conf.yml",
}


@dataclass
class ScanFile:
    path: Path
    rel: str
    kinds: set[str] = field(default_factory=set)
    _text: str | None = None
    is_text: bool = True

    def text(self) -> str:
        if self._text is None:
            try:
                raw = self.path.read_bytes()[:MAX_TEXT_BYTES]
                self._text = raw.decode("utf-8", errors="replace")
            except OSError:
                self._text = ""
        return self._text


def _is_probably_text(path: Path) -> bool:
    if path.suffix.lower() in MODEL_SUFFIXES:
        return False
    try:
        head = path.read_bytes()[:4096]
    except OSError:
        return False
    return b"\x00" not in head


def discover(root: Path) -> list[ScanFile]:
    root = root.resolve()
    if root.is_file():
        paths = [root]
        base = root.parent
    else:
        base = root
        paths = []
        for p in sorted(root.rglob("*")):
            if any(part in SKIP_DIRS for part in p.relative_to(root).parts):
                continue
            if p.is_file() and not p.is_symlink():
                paths.append(p)

    files = [ScanFile(path=p, rel=str(p.relative_to(base))) for p in paths]

    skill_roots: list[Path] = []
    mcp_roots: list[Path] = []
    for f in files:
        name = f.path.name
        suffix = f.path.suffix.lower()
        f.is_text = _is_probably_text(f.path)
        if suffix in MODEL_SUFFIXES:
            f.kinds.add("model")
            continue
        if not f.is_text:
            continue
        text = f.text()
        if name.lower() == "skill.md":
            skill_roots.append(f.path.parent)
        if suffix in {".json", ".jsonc", ".yaml", ".yml", ".toml"}:
            if any(k in text for k in _MCP_CONFIG_KEYS) or _looks_like_tool_manifest(text):
                f.kinds.add("mcp")
            if name in _AGENT_CONFIG_NAMES or _AGENT_CONFIG_KEYS.search(text):
                if not _looks_like_tool_manifest(text):
                    f.kinds.add("agent_config")
        if name == ".cursorrules":
            f.kinds.add("agent_config")
        if name == "package.json" and "@modelcontextprotocol" in text:
            mcp_roots.append(f.path.parent)
        if name == "pyproject.toml" and re.search(r"[\"']mcp[\[>=<~\"']", text):
            mcp_roots.append(f.path.parent)
        if suffix in {".py", ".js", ".mjs", ".cjs", ".ts"} and _MCP_SOURCE.search(text):
            f.kinds.add("mcp")
            mcp_roots.append(f.path.parent)

    for f in files:
        if "model" in f.kinds:
            continue
        if any(_is_under(f.path, r) for r in skill_roots):
            f.kinds.add("skill")
        if f.is_text and f.path.suffix.lower() in {".py", ".js", ".mjs", ".cjs", ".ts", ".sh", ".json", ".md"}:
            if any(_is_under(f.path, r) for r in mcp_roots):
                f.kinds.add("mcp")
        if f.is_text and not f.kinds:
            f.kinds.add("other")
    return files


def _is_under(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _looks_like_tool_manifest(text: str) -> bool:
    if "inputSchema" in text or "input_schema" in text:
        return True
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return False
    tools = data.get("tools") if isinstance(data, dict) else None
    return isinstance(tools, list) and any(isinstance(t, dict) and "description" in t for t in tools)
