"""Export Windows events from the Purple Loop GCP lab into tests/data.

The lab's Ops Agents send event logs to Cloud Logging, and a log sink copies
them into BigQuery (infra/terraform/logging.tf). This script queries one time
window from the `winevt` table, turns each event's raw XML into the repo's flat
event schema (normalize.parse_windows_event_xml), and writes a JSONL sample file.

The lab runs no attack tooling, so its exports are BENIGN baseline: real
background activity from a domain controller and member server that every Sigma
rule must stay quiet on. After exporting, run the detection tests; any hit is a
false positive to investigate (tune the rule, or explain why the event belongs
elsewhere).

Setup (once):
    gcloud auth application-default login
    uv sync --group lab

Usage:
    uv run --group lab python scripts/export_lab_logs.py \\
        --project my-lab-project --since 2026-10-15T09:00:00Z --until 2026-10-15T10:00:00Z \\
        --why "One hour of DC and member-server baseline after a fresh build."

    # Only some events, e.g. process creation on the member server:
    uv run --group lab python scripts/export_lab_logs.py ... \\
        --event-id 1 --event-id 4688 --host ws01

Every export must be recorded in tests/data/manifest.yaml. If the output file has
no manifest entry yet, the script appends one (origin: self-generated) using --why.
"""

import argparse
import sys
from datetime import datetime
from pathlib import Path
from xml.etree.ElementTree import ParseError

import yaml
from extract_samples import DATA_DIR, MANIFEST_FILE, to_jsonl
from normalize import parse_windows_event_xml

DEFAULT_DATASET = "purple_loop_lab_logs"
DEFAULT_OUTPUT = "benign/lab_baseline.jsonl"

# Cloud Logging's BigQuery export keeps the jsonPayload column name and lowercases
# nested fields (raw_xml already is). The time filter uses the partition column,
# so only the requested days are scanned. Values are query parameters, never
# string-formatted into the SQL. Host and event ID filters are applied after
# parsing, on the event's own fields.
QUERY = """
SELECT jsonPayload.raw_xml AS raw_xml
FROM `{table}`
WHERE timestamp >= @since AND timestamp < @until
ORDER BY timestamp
LIMIT @limit
"""


def parse_time(value: str) -> datetime:
    # fromisoformat accepts a trailing "Z" on Python 3.11+.
    stamp = datetime.fromisoformat(value)
    if stamp.tzinfo is None:
        raise argparse.ArgumentTypeError(f"{value}: give a timezone, e.g. 2026-10-15T09:00:00Z")
    return stamp


def fetch_raw_events(args: argparse.Namespace) -> list[str]:
    """Run the BigQuery query and return each row's raw event XML."""
    # Imported here so the rest of the repo (and its tests) never needs the
    # Google Cloud client libraries.
    from google.cloud import bigquery

    client = bigquery.Client(project=args.project)
    table = f"{args.project}.{args.dataset}.winevt"
    job_config = bigquery.QueryJobConfig(
        query_parameters=[
            bigquery.ScalarQueryParameter("since", "TIMESTAMP", args.since),
            bigquery.ScalarQueryParameter("until", "TIMESTAMP", args.until),
            bigquery.ScalarQueryParameter("limit", "INT64", args.limit),
        ],
        # Refuse to run a query that would scan more than 1 GB (cost guard).
        maximum_bytes_billed=10**9,
    )
    rows = client.query(QUERY.format(table=table), job_config=job_config).result()
    return [row.raw_xml for row in rows if row.raw_xml]


def normalize_events(
    raw_events: list[str], event_ids: list[int], host: str | None = None
) -> tuple[list[dict], int]:
    """Parse raw XML into flat events, keep the wanted IDs/host, drop exact duplicates."""
    events: list[dict] = []
    seen: set[str] = set()
    failed = 0
    for raw in raw_events:
        try:
            event = parse_windows_event_xml(raw)
        except (ParseError, ValueError, KeyError, TypeError) as error:  # malformed/non-event XML
            failed += 1
            print(f"[skip] unparseable event: {error}")
            continue
        if event_ids and event["EventID"] not in event_ids:
            continue
        # Computer is "ws01" before the domain join and "ws01.<domain>" after it.
        if host and event.get("Hostname", "").split(".")[0].lower() != host.lower():
            continue
        # The agent can resend an event after a restart; keep one copy.
        key = to_jsonl([event])
        if key not in seen:
            seen.add(key)
            events.append(event)
    return events, failed


# Fields that describe "the same activity" for each event type. A fresh Windows
# host repeats some benign activity hundreds of times (the first lab export had
# 550 near-identical .NET compiler launches in 20 minutes), which bloats the
# corpus without testing anything new. Events sharing a pattern are capped.
PATTERN_FIELDS = {
    1: ("Image", "ParentImage"),  # Sysmon process create
    10: ("SourceImage", "TargetImage", "GrantedAccess"),  # Sysmon process access
    13: ("Image", "TargetObject"),  # Sysmon registry value set
    4688: ("NewProcessName", "ParentProcessName"),  # Security process create
    4698: ("TaskName",),  # scheduled task created
    4769: ("ServiceName", "TicketEncryptionType"),  # Kerberos service ticket
    7045: ("ServiceName", "ImagePath"),  # service installed
}


def pattern_key(event: dict) -> tuple:
    """(EventID, short host name, identifying fields) for repeat capping."""
    host = str(event.get("Hostname", "")).split(".")[0].lower()
    fields = PATTERN_FIELDS.get(event["EventID"], ())
    return (event["EventID"], host, *(str(event.get(f, "")).lower() for f in fields))


def cap_repeats(events: list[dict], max_per_pattern: int) -> list[dict]:
    """Keep at most max_per_pattern events per pattern (the earliest ones). 0 = no cap."""
    if max_per_pattern <= 0:
        return events
    counts: dict[tuple, int] = {}
    kept = []
    for event in events:
        key = pattern_key(event)
        counts[key] = counts.get(key, 0) + 1
        if counts[key] <= max_per_pattern:
            kept.append(event)
    return kept


def manifest_entry(
    output: str, why: str, since: str, until: str, count: int, technique: str | None = None
) -> str:
    """YAML text for a new manifest entry, appended so the file's comments survive."""
    entry = {
        "output": output,
        "label": output.split("/")[0],
        "origin": "self-generated",
        **({"technique": technique} if technique else {}),
        "why": why,
        "exported": {"window": f"{since} / {until}", "events": count},
    }
    body = yaml.safe_dump([entry], sort_keys=False, allow_unicode=True, width=100)
    return "\n" + "\n".join(f"  {line}" if line else line for line in body.splitlines()) + "\n"


def ensure_manifest_entry(manifest_file: Path, entry_text: str, output: str) -> bool:
    """Append entry_text unless output already has an entry. Returns True if appended."""
    samples = yaml.safe_load(manifest_file.read_text("utf-8"))["samples"]
    if any(s["output"] == output for s in samples):
        return False
    with manifest_file.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(entry_text)
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description="Export lab Windows events from BigQuery.")
    parser.add_argument("--project", required=True, help="GCP project ID of the lab")
    parser.add_argument("--dataset", default=DEFAULT_DATASET)
    parser.add_argument(
        "--since", required=True, type=parse_time, help="start (inclusive), ISO 8601"
    )
    parser.add_argument("--until", required=True, type=parse_time, help="end (exclusive), ISO 8601")
    parser.add_argument("--host", help="only events from this VM, e.g. ws01")
    parser.add_argument("--event-id", type=int, action="append", default=[], dest="event_ids")
    parser.add_argument(
        "--limit", type=int, default=100000, help="max rows read from BigQuery (before filters)"
    )
    parser.add_argument(
        "--max-per-pattern",
        type=int,
        default=5,
        help="max events of the same activity per host (0 = keep all; default %(default)s)",
    )
    parser.add_argument(
        "--output", default=DEFAULT_OUTPUT, help="path under tests/data (default: %(default)s)"
    )
    parser.add_argument("--why", required=True, help="one line for the manifest entry")
    args = parser.parse_args()

    # The lab has no attack tooling, so exports are benign baseline. Malicious
    # samples need an ATT&CK technique and a rule folder; add those by hand.
    if not args.output.startswith("benign/") or not args.output.endswith(".jsonl"):
        sys.exit("--output must be a .jsonl path under benign/ (the lab produces benign baseline).")

    raw = fetch_raw_events(args)
    events, failed = normalize_events(raw, args.event_ids, args.host)
    if not events:
        sys.exit(f"No events matched ({len(raw)} rows read, {failed} unparseable).")
    matched = len(events)
    events = cap_repeats(events, args.max_per_pattern)
    print(f"[filter] {len(raw)} rows read, {matched} matched, {len(events)} kept after repeat cap")

    path = DATA_DIR / args.output
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(to_jsonl(events), encoding="utf-8", newline="\n")
    print(f"[wrote] tests/data/{args.output}: {len(events)} events ({failed} unparseable skipped)")

    entry = manifest_entry(
        args.output, args.why, args.since.isoformat(), args.until.isoformat(), len(events)
    )
    if ensure_manifest_entry(MANIFEST_FILE, entry, args.output):
        print(f"[manifest] added an entry for {args.output}; review it before committing")
    else:
        print(f"[manifest] {args.output} already listed; update its 'exported' details if needed")

    print("Next: uv run python scripts/run_sigma_tests.py   (any benign hit is a false positive)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
