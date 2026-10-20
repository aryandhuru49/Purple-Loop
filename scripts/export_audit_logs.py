"""Export Google Cloud Audit Log entries from the lab project into tests/data.

Reads entries straight from the Cloud Logging API (entries.list), not BigQuery, so
audit history from before the BigQuery sink existed (e.g. the lab's first
Terraform apply) is available too. Each entry is:
  1. redacted: human account emails and public caller IPs are replaced with
     reserved example values, because these samples are committed to a public repo
  2. flattened to dotted native field names (normalize.flatten_log_entry)
  3. written as JSONL, with a manifest entry appended if the file has none

Positive samples for the GCP rules come from scripts/simulate_gcp_audit_events.py,
which performs each risky-looking admin action once and immediately undoes it.

Setup (once):
    gcloud auth application-default login
    uv sync --group lab

Usage:
    # Positive sample for one rule (the folder name must match the rule file name):
    uv run --group lab python scripts/export_audit_logs.py --project my-lab \\
        --since 2026-10-20T19:00:00Z --until 2026-10-20T19:30:00Z \\
        --filter 'protoPayload.methodName="google.iam.admin.v1.CreateServiceAccountKey"' \\
        --output malicious/gcp_iam_service_account_key_created/lab_simulation.jsonl \\
        --technique T1098.001 --why "Key created by the simulation script."

    # Benign baseline: everything else in the window. --exclude-malicious skips
    # entries already committed as positives, so no event is labeled twice.
    uv run --group lab python scripts/export_audit_logs.py ... \\
        --output benign/gcp_audit_baseline.jsonl --exclude-malicious --why "..."
"""

import argparse
import ipaddress
import json
import re
import sys
from collections.abc import Iterator

from export_lab_logs import ensure_manifest_entry, manifest_entry, parse_time
from extract_samples import DATA_DIR, MANIFEST_FILE, to_jsonl
from normalize import flatten_log_entry

LOGGING_API = "https://logging.googleapis.com/v2/entries:list"

# Reserved values for redaction: example.com (RFC 2606) and TEST-NET-3 (RFC 5737).
REDACTED_EMAIL = "lab-admin@example.com"
REDACTED_IP = "203.0.113.10"

# Google-managed and workload identities are not personal data and are kept,
# because rules and hunts depend on telling them apart from people.
NON_PERSONAL = re.compile(r"(\.gserviceaccount\.com|@system\.gserviceaccount\.com)$", re.I)

AUDIT_LOGS = ("activity", "data_access")

# Caller IPs inside these ranges are lab-internal and kept. Every other address is
# redacted: deciding by "is this public?" would miss edge cases, so the default
# is to remove.
INTERNAL_NETWORKS = [
    ipaddress.ip_network(n)
    for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
              "127.0.0.0/8", "::1/128", "fc00::/7")
]  # fmt: skip


def is_internal(ip: str) -> bool:
    address = ipaddress.ip_address(ip)
    return any(address in network for network in INTERNAL_NETWORKS)


def fetch_entries(project: str, log_filter: str) -> Iterator[dict]:
    """Yield LogEntry dicts matching the filter, oldest first (all pages)."""
    # Imported here so tests and the rest of the repo never need google-auth.
    import google.auth
    from google.auth.transport.requests import AuthorizedSession

    credentials, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/logging.read"])
    session = AuthorizedSession(credentials)
    body = {
        "resourceNames": [f"projects/{project}"],
        "filter": log_filter,
        "orderBy": "timestamp asc",
        "pageSize": 1000,
    }
    while True:
        response = session.post(LOGGING_API, json=body, timeout=60)
        response.raise_for_status()
        page = response.json()
        yield from page.get("entries", [])
        if not page.get("nextPageToken"):
            return
        body["pageToken"] = page["nextPageToken"]


def build_filter(project: str, since: str, until: str, extra: str | None) -> str:
    """Cloud Logging filter: audit logs of this project, inside the time window."""
    logs = " OR ".join(
        f'logName="projects/{project}/logs/cloudaudit.googleapis.com%2F{name}"'
        for name in AUDIT_LOGS
    )
    parts = [f"({logs})", f'timestamp>="{since}"', f'timestamp<"{until}"']
    if extra:
        parts.append(f"({extra})")
    return " AND ".join(parts)


def redact(entry: dict) -> dict:
    """Replace human emails and public caller IPs everywhere in the entry.

    Values are collected from the fields that hold them, then replaced throughout
    the whole entry (they also appear in IAM members like "user:<email>").
    """
    text = json.dumps(entry)
    payload = entry.get("protoPayload", {})
    email = payload.get("authenticationInfo", {}).get("principalEmail", "")
    emails = set(re.findall(r'user:([^"\s]+@[^"\s]+)', text))
    if email and not NON_PERSONAL.search(email):
        emails.add(email)
    for value in sorted(emails, key=len, reverse=True):
        text = text.replace(value, REDACTED_EMAIL)

    ip = payload.get("requestMetadata", {}).get("callerIp", "")
    try:
        if ip and not is_internal(ip):
            text = text.replace(ip, REDACTED_IP)
    except ValueError:  # "private", "gce-internal-ip" and similar markers
        pass
    return json.loads(text)


def malicious_insert_ids() -> set[str]:
    """insertIds of every audit entry already committed as a positive sample."""
    ids = set()
    for path in (DATA_DIR / "malicious").rglob("*.jsonl"):
        for line in path.read_text("utf-8").splitlines():
            event = json.loads(line)
            if "insertId" in event:
                ids.add(event["insertId"])
    return ids


def main() -> int:
    parser = argparse.ArgumentParser(description="Export lab Cloud Audit Log entries.")
    parser.add_argument("--project", required=True, help="GCP project ID of the lab")
    parser.add_argument("--since", required=True, type=parse_time, help="start (inclusive)")
    parser.add_argument("--until", required=True, type=parse_time, help="end (exclusive)")
    parser.add_argument("--filter", help="extra Cloud Logging filter, ANDed with the window")
    parser.add_argument("--output", required=True, help="path under tests/data")
    parser.add_argument("--technique", help="ATT&CK technique (required for malicious/)")
    parser.add_argument(
        "--exclude-malicious",
        action="store_true",
        help="skip entries already committed under malicious/ (for benign baselines)",
    )
    parser.add_argument("--why", required=True, help="one line for the manifest entry")
    args = parser.parse_args()

    label = args.output.split("/")[0]
    if label not in ("malicious", "benign") or not args.output.endswith(".jsonl"):
        sys.exit("--output must be a .jsonl path under malicious/<rule>/ or benign/.")
    if label == "malicious" and not args.technique:
        sys.exit("--technique is required for malicious samples.")

    since = args.since.isoformat().replace("+00:00", "Z")
    until = args.until.isoformat().replace("+00:00", "Z")
    log_filter = build_filter(args.project, since, until, args.filter)
    skip = malicious_insert_ids() if args.exclude_malicious else set()

    events, seen = [], set()
    for entry in fetch_entries(args.project, log_filter):
        if entry.get("insertId") in skip or entry.get("insertId") in seen:
            continue
        seen.add(entry.get("insertId"))
        events.append(flatten_log_entry(redact(entry)))
    if not events:
        sys.exit(f"No audit entries matched: {log_filter}")

    path = DATA_DIR / args.output
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(to_jsonl(events), encoding="utf-8", newline="\n")
    print(
        f"[wrote] tests/data/{args.output}: {len(events)} entries ({len(skip)} positives skipped)"
    )

    entry = manifest_entry(args.output, args.why, since, until, len(events), args.technique)
    if ensure_manifest_entry(MANIFEST_FILE, entry, args.output):
        print(f"[manifest] added an entry for {args.output}; review it before committing")
    else:
        print(f"[manifest] {args.output} already listed; update its 'exported' details if needed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
