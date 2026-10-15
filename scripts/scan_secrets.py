"""Scan a directory for exposed credentials using the YARA rules in rules/yara/.

CI runs this against the repository itself: the project's own credential-exposure
rules check that no key file, Terraform state or credential file was committed.

Usage:
    uv run python scripts/scan_secrets.py [PATH]      # default: the repository root

Exits 1 if anything matches.
"""

import argparse
import sys
from pathlib import Path

import yara
from tabulate import tabulate

REPO_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = REPO_ROOT / "rules" / "yara"

# Never scanned: tool caches, dependencies, VCS internals, and the rule source itself
# (the PEM rule's own header/footer strings would match it).
SKIP_DIRS = {".git", ".venv", ".cache", "__pycache__", ".pytest_cache", ".ruff_cache", ".terraform"}
SKIP_FILES = {(RULES_DIR / p.name).resolve() for p in RULES_DIR.glob("*.yar")}
MAX_SIZE = 5 * 1024 * 1024  # credential files are small; skip large binaries


def iter_files(root: Path):
    for path in root.rglob("*"):
        if any(part in SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        if path.is_file() and path.resolve() not in SKIP_FILES and path.stat().st_size <= MAX_SIZE:
            yield path


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan files for exposed credentials.")
    parser.add_argument("path", nargs="?", default=str(REPO_ROOT), type=Path)
    args = parser.parse_args()

    rules = yara.compile(filepaths={p.stem: str(p) for p in sorted(RULES_DIR.glob("*.yar"))})
    root = args.path.resolve()
    findings, scanned = [], 0
    for path in iter_files(root):
        scanned += 1
        for match in rules.match(str(path)):
            findings.append(
                [match.meta.get("severity", ""), match.rule, path.relative_to(root).as_posix()]
            )

    if findings:
        print(tabulate(findings, headers=["Severity", "Rule", "File"], tablefmt="github"))
    print(f"\nScanned {scanned} files: {len(findings)} credential exposure finding(s).")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
