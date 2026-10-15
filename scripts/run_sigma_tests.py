"""Run the Sigma test harness and print a pass/fail table.

Writes reports/sigma_test_results.md and .json, and appends the table to the
GitHub Actions job summary when running in CI. Exits 1 if any rule fails.

Usage:
    uv run python scripts/run_sigma_tests.py           # table only
    uv run python scripts/run_sigma_tests.py --verbose # also show misses, FPs and SQL
"""

import argparse
import json
import os
import sys
from dataclasses import asdict
from pathlib import Path

from sigma_harness import REPO_ROOT, run_all
from tabulate import tabulate

REPORT_DIR = REPO_ROOT / "reports"


def build_table(results) -> list[list]:
    return [
        [
            "PASS" if r.passed else "FAIL",
            r.name,
            ", ".join(r.techniques),
            r.level,
            f"{r.malicious_detected}/{r.malicious_total}",
            len(r.false_positives),
            r.benign_in_scope,
        ]
        for r in results
    ]


HEADERS = ["Result", "Rule", "ATT&CK", "Level", "Detected", "Benign FPs", "Benign tested"]


def main() -> int:
    parser = argparse.ArgumentParser(description="Test Sigma rules against labeled samples.")
    parser.add_argument("--verbose", action="store_true", help="show failure details and SQL")
    args = parser.parse_args()

    results = run_all()
    table = build_table(results)
    print(tabulate(table, headers=HEADERS, tablefmt="github"))

    failed = [r for r in results if not r.passed]
    for r in results:
        if args.verbose or not r.passed:
            print(f"\n--- {r.name} ---")
            if r.missed:
                print("  missed malicious events:", *r.missed, sep="\n    ")
            if r.false_positives:
                print("  fired on benign events:", *r.false_positives, sep="\n    ")
            if r.benign_in_scope == 0:
                print("  no benign events of this log type: false-positive test is empty")
            if args.verbose:
                print("  SQL:", r.sql)

    total_events = sum(r.malicious_total for r in results)
    summary = (
        f"\n{len(results) - len(failed)}/{len(results)} rules passed, "
        f"{sum(r.malicious_detected for r in results)}/{total_events} malicious events detected, "
        f"{sum(len(r.false_positives) for r in results)} false positives."
    )
    print(summary)

    # Reports for humans (markdown) and for other scripts / CI artifacts (JSON).
    REPORT_DIR.mkdir(exist_ok=True)
    markdown = "## Sigma rule tests\n\n" + tabulate(table, headers=HEADERS, tablefmt="github")
    markdown += "\n" + summary + "\n"
    (REPORT_DIR / "sigma_test_results.md").write_text(markdown, encoding="utf-8")
    (REPORT_DIR / "sigma_test_results.json").write_text(
        json.dumps([asdict(r) | {"passed": r.passed} for r in results], indent=2), encoding="utf-8"
    )
    if summary_file := os.environ.get("GITHUB_STEP_SUMMARY"):
        with Path(summary_file).open("a", encoding="utf-8") as f:
            f.write(markdown)

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
