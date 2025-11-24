# Changelog

All notable changes to this project will be documented in this file.

## [4.0.0] - 2025-11-24
- Refactored codebase for modularity and improved file identification logic.
- Added guarded imports for optional dependencies to satisfy static analyzers.
- Replaced banner with large ASCII-art `FileXray` header.
- Added non-interactive CLI support via `argparse` (`--file`, `--directory`, `--list-formats`, `--show-modules`).
- Hardened `extract_strings()` decoding and improved ExifTool detection using `shutil.which`.
- Cleaned and split `requirements.txt` into core and `requirements-optional.txt`.
- Added `.gitignore` and improved `setup.py` metadata and console entry point.

## [3.0.0] - previous
- Original project baseline (older commit history summarized here).

<!--
Keep entries brief. Use conventional commits or a structured format if desired.
-->
