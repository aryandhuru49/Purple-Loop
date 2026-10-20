"""Generate real Cloud Audit Log samples for the GCP detection rules.

Performs each risky-looking admin action ONCE in the lab project and immediately
undoes it, so the audit log holds both the action (positive sample) and its
reversal (a benign near-miss). These are ordinary gcloud admin commands, not
attack tooling, and nothing is left behind:

  action (rule should fire)                      undo (rule must stay quiet)
  ---------------------------------------------  ------------------------------------
  create a key for a throwaway service account   delete the key, then the account
  grant roles/editor to that account             remove the grant
  open a firewall rule to 0.0.0.0/0              delete it (it targets a tag no VM has)
  disable, then delete, a throwaway log sink     (the sink is created first: benign)
  read a lab secret as a person                  (value is discarded, never printed)

Safety:
  * refuses to run unless the project contains the lab VPC (purple-loop-vpc)
  * requires --yes
  * cleanup runs in a finally block, in reverse order, even if a step fails
  * the key file is written to a temp dir and deleted immediately

Usage:
    uv run python scripts/simulate_gcp_audit_events.py --project my-lab --yes
Then export the printed time window with scripts/export_audit_logs.py.
"""

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

PREFIX = "purple-loop-sim"


class Gcloud:
    def __init__(self, project: str) -> None:
        exe = shutil.which("gcloud")
        if not exe:
            sys.exit("gcloud not found on PATH.")
        self.exe, self.project = exe, project

    def run(self, *args: str, check: bool = True) -> str:
        """Run one gcloud command quietly; output is returned, never printed."""
        cmd = [self.exe, *args, f"--project={self.project}", "--quiet"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if check and result.returncode != 0:
            raise RuntimeError(f"gcloud {' '.join(args[:3])} failed: {result.stderr.strip()}")
        return result.stdout


def step(name: str) -> None:
    print(f"[{datetime.now(UTC):%H:%M:%S}Z] {name}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate GCP audit log samples in the lab.")
    parser.add_argument("--project", required=True, help="the lab project ID")
    parser.add_argument("--yes", action="store_true", help="confirm: make changes in the lab")
    args = parser.parse_args()
    if not args.yes:
        sys.exit("This changes IAM, firewall and logging in the project. Re-run with --yes.")

    gcloud = Gcloud(args.project)
    # Guard: only ever run inside the Purple Loop lab project.
    gcloud.run("compute", "networks", "describe", "purple-loop-vpc", "--format=value(name)")

    sa_email = f"{PREFIX}@{args.project}.iam.gserviceaccount.com"
    member = f"serviceAccount:{sa_email}"
    sink = f"{PREFIX}-sink"
    firewall = f"{PREFIX}-open"
    undo: list[tuple[str, tuple[str, ...]]] = []  # (description, gcloud args), run in reverse

    start = datetime.now(UTC)
    try:
        step("create throwaway service account (benign)")
        gcloud.run(
            "iam",
            "service-accounts",
            "create",
            PREFIX,
            "--display-name=Purple Loop audit simulation (temporary)",
        )
        undo.append(("delete service account", ("iam", "service-accounts", "delete", sa_email)))
        time.sleep(10)  # IAM is eventually consistent; new accounts can't be used at once

        step("create a service account key (rule: key created)")
        with tempfile.TemporaryDirectory() as tmp:
            key_file = Path(tmp) / "key.json"
            gcloud.run(
                "iam",
                "service-accounts",
                "keys",
                "create",
                str(key_file),
                f"--iam-account={sa_email}",
            )
            key_id = json.loads(key_file.read_text())["private_key_id"]
            key_file.unlink()  # never keep the credential
        step("delete the key (benign)")
        gcloud.run("iam", "service-accounts", "keys", "delete", key_id, f"--iam-account={sa_email}")

        step("grant roles/editor (rule: privileged role granted)")
        binding = (f"--member={member}", "--role=roles/editor", "--condition=None")
        gcloud.run("projects", "add-iam-policy-binding", args.project, *binding)
        undo.append(
            (
                "remove editor grant",
                ("projects", "remove-iam-policy-binding", args.project, *binding),
            )
        )
        step("remove the grant (benign)")
        gcloud.run(*undo.pop()[1])

        step("open a firewall rule to 0.0.0.0/0 on an unused tag (rule: firewall open)")
        gcloud.run(
            "compute",
            "firewall-rules",
            "create",
            firewall,
            "--network=purple-loop-vpc",
            "--direction=INGRESS",
            "--allow=tcp:8080",
            "--source-ranges=0.0.0.0/0",
            f"--target-tags={PREFIX}-no-such-vm",
            "--priority=65000",
        )
        undo.append(("delete firewall rule", ("compute", "firewall-rules", "delete", firewall)))
        step("delete the firewall rule (benign)")
        gcloud.run(*undo.pop()[1])

        step("create a throwaway log sink that matches nothing (benign)")
        gcloud.run(
            "logging",
            "sinks",
            "create",
            sink,
            f"bigquery.googleapis.com/projects/{args.project}/datasets/purple_loop_lab_logs",
            f'--log-filter=logName="projects/{args.project}/logs/{PREFIX}-none"',
        )
        undo.append(("delete log sink", ("logging", "sinks", "delete", sink)))
        step("disable the sink (rule: sink disabled)")
        gcloud.run("logging", "sinks", "update", sink, "--disabled")
        step("delete the sink (rule: sink deleted)")
        gcloud.run(*undo.pop()[1])

        step("read a lab secret as a person (rule: unexpected secret access)")
        gcloud.run("secrets", "versions", "access", "latest", "--secret=purple-loop-domain-admin")
    finally:
        for description, cmd in reversed(undo):
            step(f"cleanup: {description}")
            gcloud.run(*cmd, check=False)

    end = datetime.now(UTC)
    print("\nDone. Audit entries take a minute to appear. Export this window:")
    print(f"  --since {start:%Y-%m-%dT%H:%M:%SZ} --until {end:%Y-%m-%dT%H:%M:%SZ}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
