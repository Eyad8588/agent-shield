"""Extract text from a PDF given on the command line."""
import sys
from pathlib import Path

from pypdf import PdfReader


def main(path: str) -> None:
    reader = PdfReader(Path(path))
    for i, page in enumerate(reader.pages, 1):
        print(f"--- page {i} ---")
        print(page.extract_text() or "")


if __name__ == "__main__":
    main(sys.argv[1])
