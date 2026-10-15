# Purple Loop GCP lab (Terraform)

Infrastructure and logging for the detection lab. The step-by-step guide to deploy, connect,
export and tear down is in [docs/lab_runbook.md](../../docs/lab_runbook.md), and the reasons
behind the design are in [docs/design_decisions.md](../../docs/design_decisions.md#gcp-lab-infrastructure-and-logging-only).

| File | What it defines |
|---|---|
| `versions.tf`, `providers.tf` | Terraform ≥ 1.15, google ~> 8.7, random ~> 3.9 |
| `variables.tf` | Inputs, plus the pinned Sysmon/config hashes |
| `apis.tf` | Google APIs the lab uses |
| `network.tf` | VPC, subnet with flow logs, Cloud Router + NAT, IAP and internal firewall rules |
| `iam.tf` | Least-privilege VM service account, and the scheduler's permission to stop VMs |
| `secrets.tf` | Lab passwords: ephemeral → Secret Manager via write-only args (never in state) |
| `compute.tf` | dc01, ws01 (Windows Server 2025) and lnx01 (Debian 13), with no public IPs and Shielded VM |
| `scripts/` | Idempotent startup scripts: Sysmon, audit policy, Ops Agent, AD promotion/join, auditd |
| `logging.tf` | Log sink → partitioned BigQuery dataset (30-day expiry) |
| `budget.tf` | Budget email alerts at 50/90/100% actual and 100% forecast |
| `schedule.tf` | Nightly stop of every lab VM |
| `outputs.tf` | Ready-to-paste IAP, SSH and secret commands |

```bash
cp terraform.tfvars.example terraform.tfvars   # then edit; it is gitignored
terraform init && terraform plan -out lab.tfplan && terraform apply lab.tfplan
```
