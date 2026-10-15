"""Compile the Logica hunts to SQL and run them locally on DuckDB.

Each hunts/logica/<name>.l file defines a predicate called `Hunt`. This script:
  1. loads every JSONL sample in tests/data into a DuckDB table called `logs`
     (DuckDB merges the different event shapes into one wide table),
  2. compiles each hunt with Logica's compiler and writes <name>.sql next to it,
     so readers can see exactly what query Logica produced,
  3. runs the SQL and prints the results.

The same .l files can target BigQuery by switching @Engine (Phase 3).

Usage:
    uv run python scripts/run_hunts.py            # compile, write .sql, run, print
    uv run python scripts/run_hunts.py --check    # fail if a committed .sql is stale

Logica is called through its Python API rather than its CLI, because the CLI imports
`readline`, which does not exist on Windows.
"""

import argparse
import sys
from pathlib import Path

import duckdb
from logica.compiler import universe
from logica.parser_py import parse
from tabulate import tabulate

REPO_ROOT = Path(__file__).resolve().parent.parent
HUNTS_DIR = REPO_ROOT / "hunts" / "logica"
DATA_GLOB = (REPO_ROOT / "tests" / "data").as_posix() + "/**/*.jsonl"


def compile_hunt(path: Path) -> str:
    """Compile a Logica file and return the SQL for its `Hunt` predicate."""
    rules = parse.ParseFile(path.read_text("utf-8"))["rule"]
    program = universe.LogicaProgram(rules)
    return program.FormattedPredicateSql("Hunt")


def load_logs() -> duckdb.DuckDBPyConnection:
    db = duckdb.connect(":memory:")
    # union_by_name: events have different fields; missing ones become NULL.
    db.execute(
        "CREATE TABLE logs AS SELECT * FROM read_json(?, format='newline_delimited', "
        "union_by_name=true, filename=true)",
        [DATA_GLOB],
    )
    return db


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Logica hunts on DuckDB.")
    parser.add_argument("--check", action="store_true", help="fail if committed SQL is stale")
    args = parser.parse_args()

    db = load_logs()
    stale = 0
    for path in sorted(HUNTS_DIR.glob("*.l")):
        sql = compile_hunt(path)
        sql_path = path.with_suffix(".sql")
        header = f"-- Generated from {path.name} by scripts/run_hunts.py. Do not edit by hand.\n"
        # Strip trailing spaces Logica leaves on some lines, so formatting hooks don't
        # rewrite the file and make the --check comparison fail.
        content = header + "\n".join(line.rstrip() for line in sql.strip().splitlines()) + "\n"
        if args.check:
            current = sql_path.read_text("utf-8") if sql_path.exists() else None
            if current != content:
                print(f"[STALE] {sql_path.relative_to(REPO_ROOT)}")
                stale += 1
        else:
            sql_path.write_text(content, encoding="utf-8", newline="\n")

        # Logica's DuckDB preamble (schema/type setup) plus the query: run as one script,
        # then fetch the result of the final SELECT.
        cursor = db.execute(sql)
        columns = [c[0] for c in cursor.description]
        rows = cursor.fetchall()
        print(f"\n=== {path.stem} ({len(rows)} rows) ===")
        print(tabulate(rows, headers=columns, maxcolwidths=60) if rows else "(no rows)")

    return 1 if stale else 0


if __name__ == "__main__":
    sys.exit(main())
