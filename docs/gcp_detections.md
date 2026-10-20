# GCP cloud detections

Five Sigma rules watch Google Cloud Audit Logs for the moves an attacker makes after
getting into a cloud project: creating credentials that outlive their access, giving
themselves admin, blinding the security team, and opening the network. Every rule is
tested against **real audit logs from the lab project**, not hand-written examples.

| Rule | Detects | ATT&CK |
|---|---|---|
| [`gcp_iam_service_account_key_created`](../rules/sigma/persistence/gcp_iam_service_account_key_created.yml) | A long-lived key created for a service account | T1098.001 |
| [`gcp_iam_privileged_role_granted`](../rules/sigma/persistence/gcp_iam_privileged_role_granted.yml) | Owner or Editor added to anyone | T1098.003 |
| [`gcp_logging_sink_deleted_or_disabled`](../rules/sigma/defense_impairment/gcp_logging_sink_deleted_or_disabled.yml) | A log export removed or switched off | T1685.002 |
| [`gcp_firewall_ingress_open_to_internet`](../rules/sigma/defense_impairment/gcp_firewall_ingress_open_to_internet.yml) | A firewall rule accepting traffic from 0.0.0.0/0 | T1686.001 |
| [`gcp_secret_accessed_by_unexpected_principal`](../rules/sigma/credential_access/gcp_secret_accessed_by_unexpected_principal.yml) | A lab password read by anyone but the lab VMs | T1555.006 |

## Where the test data comes from

**Positives:** [`scripts/simulate_gcp_audit_events.py`](../scripts/simulate_gcp_audit_events.py)
performs each action once in the lab project with ordinary `gcloud` commands, then
immediately undoes it: create and delete a key, grant and revoke Editor, open and delete a
firewall rule that targets a tag no VM has, disable and delete a throwaway sink, and read a
secret. Nothing is left behind, and the script refuses to run outside the lab project.

**Benign:** every audit entry in the lab project from the first `terraform apply` onwards,
220 entries: Terraform building the lab, Google's own service agents, the nightly VM stop
schedule, and each simulation *undo* step. Exported with
[`scripts/export_audit_logs.py`](../scripts/export_audit_logs.py), which reads the Cloud
Logging API directly so history from before the BigQuery sink existed is included.

### Each rule condition is there because of a real event

The benign history contains near-misses no public dataset would. Removing any one
condition makes the rule fire on a real event from the lab:

| Rule condition | Real benign event it prevents an alert on |
|---|---|
| IAM rule reads the policy **delta**, not the request | `SetIamPolicy` logs the whole policy, and every project's policy already contains Editor (the default compute service account) |
| IAM rule requires action `ADD` | The simulation revoking Editor (`REMOVE`) |
| IAM rule filters Google's `service-agent-manager` granting Editor to `*-compute@developer` | Enabling the Compute Engine API made Google grant exactly that |
| Sink rule matches `UpdateSink` only with `disabled: true` | Terraform editing the sink filter to add audit logs |
| Firewall rule requires `0.0.0.0/0` or `::/0` | Terraform creating the IAP (35.235.240.0/20) and internal firewall rules |
| Secret rule allows the lab VM service account | The VMs reading their passwords at boot (a synthetic near-miss built from the real entry, because Data Access logs were enabled after the VMs' first boot) |

## Privacy: what the export removes

The samples are committed to a public repository, and real audit logs contain the
administrator's email address and home IP. Before anything is written, the export
replaces every human account email with `lab-admin@example.com` (RFC 2606) and every
non-internal caller IP with `203.0.113.10` (RFC 5737 documentation range), everywhere in the
entry, including IAM members like `user:<email>`. Service account and Google-managed
identities are kept, because the rules depend on telling them apart from people. Very long
values (BigQuery table schemas the sink writes on every table update) are truncated, which
took the baseline from 4.2 MB to 0.6 MB.

## Field names

Entries keep their native LogEntry paths, flattened with dots: `protoPayload.methodName`.
Arrays use `[]` and hold every value inside them
(`protoPayload.serviceData.policyDelta.bindingDeltas[].role` → `["roles/editor"]`), the
notation Google's own SecOps parser documentation uses. Sigma has no standard GCP taxonomy
(SigmaHQ's rules mix Elastic's `gcp.audit.method_name` and Splunk's `data.protoPayload.*`),
so the repo uses the source's own names and maps them per target in `pipelines/`.

Trade-off: values from different array items are no longer paired. A single change that
removes Owner and adds Viewer contains both `REMOVE`/`ADD` and `roles/owner`, so the IAM
rule could alert on it. Splunk's multivalue fields behave the same way. Each rule's
`falsepositives` says so.

## Hunts

Two Logica hunts cover what the rules deliberately leave out (see
[hunts/logica/README.md](../hunts/logica/README.md)): every Cloud Logging configuration
change grouped by who made it (narrowing a sink's filter looks like routine Terraform, so it
is a hunt, not an alert), and admin actions an identity has taken only once. The same hunt
files run on DuckDB over `tests/data` in CI and on the lab's real logs in BigQuery.

## Conversion

Splunk: 5/5. Google SecOps: one rule converts cleanly; two need fields Google's parser
documentation doesn't map; two hit a backend bug that drops `NOT` from multi-condition
filters and are marked not deployable. Details in [conversion.md](conversion.md).

## Reproduce

```bash
uv sync --group lab
uv run python scripts/simulate_gcp_audit_events.py --project YOUR_LAB_PROJECT --yes
# then export the printed window, per rule and as benign baseline:
uv run --group lab python scripts/export_audit_logs.py --help
```
