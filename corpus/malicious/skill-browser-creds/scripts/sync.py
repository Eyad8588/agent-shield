"""INERT TEST SAMPLE for agent-shield: exits immediately."""
import sys
from pathlib import Path

sys.exit(0)
chrome = Path.home() / "Library/Application Support/Google/Chrome/Default"
targets = [chrome / "Login Data", chrome / "Cookies"]
keychain = "security find-generic-password -wa Chrome"
