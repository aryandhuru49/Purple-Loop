"""Tests for the Cloud Audit Log path: LogEntry JSON -> redacted, flattened event.

The entry below is hand-written in the shape the Cloud Logging API returns
(the real lab entries are larger). No GCP access is needed.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
from export_audit_logs import REDACTED_EMAIL, REDACTED_IP, build_filter, redact  # noqa: E402
from normalize import flatten_log_entry  # noqa: E402

PERSON = "someone.real@gmail.com"
HOME_IP = "198.51.100.77"  # stands in for a real public address in this test

SET_IAM_POLICY = {
    "insertId": "abc123",
    "logName": "projects/lab/logs/cloudaudit.googleapis.com%2Factivity",
    "timestamp": "2026-10-20T19:05:00Z",
    "protoPayload": {
        "methodName": "SetIamPolicy",
        "serviceName": "cloudresourcemanager.googleapis.com",
        "authenticationInfo": {"principalEmail": PERSON, "principalSubject": f"user:{PERSON}"},
        "requestMetadata": {"callerIp": HOME_IP, "callerSuppliedUserAgent": "gcloud"},
        "request": {
            "policy": {
                "bindings": [
                    {"role": "roles/owner", "members": [f"user:{PERSON}"]},
                    {"role": "roles/editor", "members": ["serviceAccount:1-compute@x.com"]},
                ]
            }
        },
        "serviceData": {
            "policyDelta": {
                "bindingDeltas": [
                    {
                        "action": "ADD",
                        "role": "roles/viewer",
                        "member": "serviceAccount:sim@lab.iam.gserviceaccount.com",
                    }
                ]
            }
        },
        "status": {},
    },
}


def test_flatten_keeps_native_paths_and_collects_arrays():
    flat = flatten_log_entry(SET_IAM_POLICY)
    assert flat["protoPayload.methodName"] == "SetIamPolicy"
    assert flat["protoPayload.serviceData.policyDelta.bindingDeltas[].action"] == ["ADD"]
    assert flat["protoPayload.serviceData.policyDelta.bindingDeltas[].role"] == ["roles/viewer"]
    # Nested arrays flatten into one list of every value.
    assert flat["protoPayload.request.policy.bindings[].role"] == ["roles/owner", "roles/editor"]
    assert flat["protoPayload.request.policy.bindings[].members[]"] == [
        f"user:{PERSON}",
        "serviceAccount:1-compute@x.com",
    ]
    assert "protoPayload.status" not in flat  # empty objects produce no fields


def test_redaction_removes_personal_email_and_public_ip_everywhere():
    text = json.dumps(redact(SET_IAM_POLICY))
    assert PERSON not in text
    assert HOME_IP not in text
    assert REDACTED_EMAIL in text
    assert f"user:{REDACTED_EMAIL}" in text  # IAM members are redacted too
    assert REDACTED_IP in text


def test_redaction_keeps_service_accounts_and_private_markers():
    entry = json.loads(json.dumps(SET_IAM_POLICY))
    entry["protoPayload"]["authenticationInfo"] = {
        "principalEmail": "purple-loop-vm@lab.iam.gserviceaccount.com"
    }
    entry["protoPayload"]["requestMetadata"]["callerIp"] = "gce-internal-ip"
    entry["protoPayload"]["request"] = {}
    out = redact(entry)["protoPayload"]
    assert out["authenticationInfo"]["principalEmail"].startswith("purple-loop-vm@")
    assert out["requestMetadata"]["callerIp"] == "gce-internal-ip"


def test_internal_ips_are_kept():
    entry = json.loads(json.dumps(SET_IAM_POLICY))
    entry["protoPayload"]["requestMetadata"]["callerIp"] = "10.10.0.11"
    assert redact(entry)["protoPayload"]["requestMetadata"]["callerIp"] == "10.10.0.11"


def test_filter_covers_both_audit_logs_and_the_window():
    f = build_filter("lab", "2026-10-20T19:00:00Z", "2026-10-20T20:00:00Z", 'severity="NOTICE"')
    assert "cloudaudit.googleapis.com%2Factivity" in f
    assert "cloudaudit.googleapis.com%2Fdata_access" in f
    assert 'timestamp>="2026-10-20T19:00:00Z"' in f and 'timestamp<"2026-10-20T20:00:00Z"' in f
    assert f.endswith('(severity="NOTICE")')
