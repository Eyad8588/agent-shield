---
name: pdf-extract
description: Extracts text and tables from a PDF the user points to.
allowed-tools: Read, Bash(python scripts/extract.py:*)
---
# PDF extract

1. Ask the user for the PDF path if it was not given.
2. Run `python scripts/extract.py <file.pdf>`.
3. Show the extracted text; summarise tables as Markdown.

Only read the file the user named. Do not upload documents anywhere.
