"""Compile the Logica hunts to SQL and run them locally on DuckDB (and on BigQuery).

Each hunts/logica/<name>.l file defines a predicate called `Hunt`. This script:
  1. loads the JSONL samples in tests/data into DuckDB:
       logs          every Windows event (DuckDB merges their shapes into one table)
       audit_events  every Google Cloud Audit Log entry, with the same simple columns
                     as the BigQuery view of the same name (infra/terraform/logging.tf)
  2. compiles each hunt with Logica's compiler and writes the SQL next to it,
     so readers can see exactly what query Logica produced,
  3. runs the SQL and prints the results.

Windows hunts declare @Engine("duckdb") themselves. GCP hunts (gcp_*.l) are
engine-neutral: they read an `AuditEvent` predicate, and this script prepends a
two-line preamble that binds it to the DuckDB table or to the BigQuery view. Each
GCP hunt therefore compiles twice: <name>.sql (DuckDB, run in CI on tests/data)
and <name>.bigquery.sql (run on the lab's real audit logs with --bigquery).

Usage:
    uv run python scripts/run_hunts.py            # compile, write .sql, run on DuckDB
    uv run python scripts/run_hunts.py --check    # fail if a committed .sql is stale
    uv run --group lab python scripts/run_hunts.py --bigquery my-lab-project
                                                  # also run the GCP hunts on BigQuery

Logica is called through its Python API rather than its CLI, because the CLI imports
`readline`, which does not exist on Windows.
"""

import argparse
import json
import sys
from pathlib import Path

import duckdb
from logica.compiler import universe
from logica.parser_py import parse
from tabulate import tabulate

REPO_ROOT = Path(__file__).resolve().parent.parent
HUNTS_DIR = REPO_ROOT / "hunts" / "logica"
DATA_DIR = REPO_ROOT / "tests" / "data"

# Columns of the audit_events view, and the flattened sample field each one comes from.
AUDIT_COLUMNS = {
    "event_time": "timestamp",
    "log_type": "logName",
    "service_name": "protoPayload.serviceName",
    "method_name": "protoPayload.methodName",
    "principal_email": "protoPayload.authenticationInfo.principalEmail",
    "resource_name": "protoPayload.resourceName",
    "caller_ip": "protoPayload.requestMetadata.callerIp",
}

_ARGS = ", ".join(f"{column}:" for column in AUDIT_COLUMNS)
GCP_PREAMBLES = {
    "duckdb": f'@Engine("duckdb");\nAuditEvent({_ARGS}) :- audit_events({_ARGS});\n',
    "bigquery": (
        f'@Engine("bigquery");\n'
        f"AuditEvent({_ARGS}) :- `purple_loop_lab_logs.audit_events`({_ARGS});\n"
    ),
}


def is_gcp_hunt(path: Path) -> bool:
    return path.stem.startswith("gcp_")


def compile_hunt(path: Path, engine: str = "duckdb") -> str:
    """Compile a Logica file and return the SQL for its `Hunt` predicate."""
    source = path.read_text("utf-8")
    if is_gcp_hunt(path):
        source = GCP_PREAMBLES[engine] + source
    rules = parse.ParseFile(source)["rule"]
    return universe.LogicaProgram(rules).FormattedPredicateSql("Hunt")


def _sample_files() -> tuple[list[str], list[dict]]:
    """Split tests/data into Windows JSONL files and flattened audit events."""
    windows, audit = [], []
    for path in sorted(DATA_DIR.rglob("*.jsonl")):
        events = [json.loads(line) for line in path.read_text("utf-8").splitlines()]
        if events and "logName" in events[0]:
            audit.extend(events)
        else:
            windows.append(path.as_posix())
    return windows, audit


def load_logs() -> duckdb.DuckDBPyConnection:
    db = duckdb.connect(":memory:")
    windows, audit = _sample_files()
    # union_by_name: events have different fields; missing ones become NULL.
    db.execute(
        "CREATE TABLE logs AS SELECT * FROM read_json(?, format='newline_delimited', "
        "union_by_name=true, filename=true)",
        [windows],
    )
    columns = ", ".join(f"{c} TEXT" for c in AUDIT_COLUMNS)
    db.execute(f"CREATE TABLE audit_events ({columns})")
    rows = []
    for event in audit:
        row = {c: event.get(field) for c, field in AUDIT_COLUMNS.items()}
        # Same value as the BigQuery view's _TABLE_SUFFIX: "activity", "data_access".
        row["log_type"] = row["log_type"].rsplit("%2F", 1)[-1]
        rows.append(list(row.values()))
    db.executemany(f"INSERT INTO audit_events VALUES ({', '.join('?' * len(AUDIT_COLUMNS))})", rows)
    return db


def write_or_check(sql_path: Path, source_name: str, sql: str, check: bool) -> bool:
    """Write the generated SQL, or with check=True report whether it is stale."""
    header = f"-- Generated from {source_name} by scripts/run_hunts.py. Do not edit by hand.\n"
    # Strip trailing spaces Logica leaves on some lines, so formatting hooks don't
    # rewrite the file and make the --check comparison fail.
    content = header + "\n".join(line.rstrip() for line in sql.strip().splitlines()) + "\n"
    if check:
        current = sql_path.read_text("utf-8") if sql_path.exists() else None
        if current != content:
            print(f"[STALE] {sql_path.relative_to(REPO_ROOT)}")
            return True
        return False
    sql_path.write_text(content, encoding="utf-8", newline="\n")
    return False


def print_rows(title: str, columns: list[str], rows: list) -> None:
    print(f"\n=== {title} ({len(rows)} rows) ===")
    print(tabulate(rows, headers=columns, maxcolwidths=60) if rows else "(no rows)")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Logica hunts on DuckDB (and BigQuery).")
    parser.add_argument("--check", action="store_true", help="fail if committed SQL is stale")
    parser.add_argument("--bigquery", metavar="PROJECT", help="also run GCP hunts on BigQuery")
    args = parser.parse_args()

    db = load_logs()
    stale = 0
    for path in sorted(HUNTS_DIR.glob("*.l")):
        sql = compile_hunt(path)
        stale += write_or_check(path.with_suffix(".sql"), path.name, sql, args.check)
        if is_gcp_hunt(path):
            bq_sql = compile_hunt(path, "bigquery")
            bq_path = path.with_suffix(".bigquery.sql")
            stale += write_or_check(bq_path, path.name, bq_sql, args.check)

        # Logica's DuckDB preamble (schema/type setup) plus the query: run as one script,
        # then fetch the result of the final SELECT.
        cursor = db.execute(sql)
        print_rows(path.stem, [c[0] for c in cursor.description], cursor.fetchall())

        if args.bigquery and is_gcp_hunt(path):
            from google.cloud import bigquery  # lab dependency group only

            result = bigquery.Client(project=args.bigquery).query(bq_sql).result()
            rows = [list(row.values()) for row in result]
            print_rows(f"{path.stem} on BigQuery", [f.name for f in result.schema], rows)

    return 1 if stale else 0


if __name__ == "__main__":
    sys.exit(main())
