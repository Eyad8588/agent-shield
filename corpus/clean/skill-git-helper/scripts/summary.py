"""Summarise staged changes using an argv list (no shell)."""
import subprocess


def staged_files() -> list[str]:
    out = subprocess.run(["git", "diff", "--cached", "--name-only"], capture_output=True, text=True, check=True)
    return [line for line in out.stdout.splitlines() if line]


if __name__ == "__main__":
    files = staged_files()
    print(f"{len(files)} staged file(s):")
    for f in files:
        print(" -", f)
