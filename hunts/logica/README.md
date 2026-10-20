# Logica threat hunts

Hunts are written in [Logica](https://github.com/evgskv/logica), a logic programming
language that compiles to SQL. Each `.l` file defines a `Hunt` predicate; the matching
`.sql` file is the query Logica generated for DuckDB, and GCP hunts also have a
`.bigquery.sql` (all committed so you can read them, and checked in CI so they can't drift).

```bash
uv run python scripts/run_hunts.py                                   # DuckDB, tests/data
uv run --group lab python scripts/run_hunts.py --bigquery LAB_PROJECT  # + GCP hunts on BigQuery
```

Hunts differ from detection rules: they return **leads for an analyst**, ranked or
grouped, not alerts. Some rows will be benign. That is expected.

| Hunt | Question it answers | What it finds in the Phase 1 data |
|---|---|---|
| `rare_parent_child_pairs` | Which process chains are rare in this environment? | `wscript.exe -> powershell.exe`, `regsvr32.exe -> powershell.exe` and `cmd.exe -> mshta.exe` (plus benign one-offs, because the dataset is small) |
| `kerberos_ticket_spread` | Which accounts request tickets for unusually many services, and with RC4? | `Administrator` requested RC4 tickets for 30 distinct services; the normal account requested 3 |
| `lsass_access_inventory` | Which processes open LSASS, and with what rights? | `powershell.exe` with `0x1010` and `rundll32.exe` with `0x1fffff` next to routine `svchost.exe` `0x1000` |
| `gcp_logging_config_changes` | Who changed Cloud Logging configuration (sinks, exclusions, buckets)? | Terraform's sink filter edit, which the sink rule deliberately ignores, next to the simulation's create/disable/delete of a throwaway sink |
| `gcp_rare_principal_methods` | Which admin actions has an identity taken only once? | The one-off service account key creation and sink deletion, among first-time Terraform setup calls |

The GCP hunts are engine-neutral: they read an `AuditEvent` predicate, and `run_hunts.py`
binds it either to a DuckDB table built from `tests/data` or to the BigQuery view
`purple_loop_lab_logs.audit_events` (defined in `infra/terraform/logging.tf`). Both have the
same columns, so one hunt file is tested in CI and runs unchanged on the lab's real logs.

## Why Logica

- Hunts read like statements of intent (`PairCount(parent:, child:) += 1 :- ProcessStart(...)`)
  and compose: `ProcessStart` unifies Sysmon 1 and Security 4688 once, and every later
  predicate reuses it.
- The same program compiles to different engines: the GCP hunts compile to DuckDB SQL for CI
  and to BigQuery SQL for the lab, from one source file.

## Limitations

- The Phase 1 dataset is small, so "rare" is relative to a few hundred events. In a real
  environment the threshold would be tuned and computed over weeks of data.
- "Accounts authenticating from unusual hosts" needs logon events (4624). The public samples
  don't include them, and the lab baseline export keeps only the event IDs the rules read;
  exporting 4624 from the lab is the next step for this hunt.
- Logica is called through its Python API because its CLI imports `readline`, which is not
  available on Windows.
