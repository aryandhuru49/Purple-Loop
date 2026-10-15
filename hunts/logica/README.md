# Logica threat hunts

Hunts are written in [Logica](https://github.com/evgskv/logica), a logic programming
language that compiles to SQL. Each `.l` file defines a `Hunt` predicate; the matching
`.sql` file is the query Logica generated for DuckDB (committed so you can read it, and
checked in CI so it can't drift).

```bash
uv run python scripts/run_hunts.py
```

Hunts differ from detection rules: they return **leads for an analyst**, ranked or
grouped, not alerts. Some rows will be benign. That is expected.

| Hunt | Question it answers | What it finds in the Phase 1 data |
|---|---|---|
| `rare_parent_child_pairs` | Which process chains are rare in this environment? | `wscript.exe -> powershell.exe`, `regsvr32.exe -> powershell.exe` and `cmd.exe -> mshta.exe` (plus benign one-offs, because the dataset is small) |
| `kerberos_ticket_spread` | Which accounts request tickets for unusually many services, and with RC4? | `Administrator` requested RC4 tickets for 30 distinct services; the normal account requested 3 |
| `lsass_access_inventory` | Which processes open LSASS, and with what rights? | `powershell.exe` with `0x1010` and `rundll32.exe` with `0x1fffff` next to routine `svchost.exe` `0x1000` |

## Why Logica

- Hunts read like statements of intent (`PairCount(parent:, child:) += 1 :- ProcessStart(...)`)
  and compose: `ProcessStart` unifies Sysmon 1 and Security 4688 once, and every later
  predicate reuses it.
- The same program compiles to different engines. Locally it targets DuckDB; Phase 3 runs
  the same hunts on BigQuery by changing `@Engine`.

## Limitations

- The Phase 1 dataset is small, so "rare" is relative to a few hundred events. In a real
  environment the threshold would be tuned and computed over weeks of data.
- "Accounts authenticating from unusual hosts" needs logon events (4624), which the public
  samples don't include. It is planned for the Phase 2 lab data.
- Logica is called through its Python API because its CLI imports `readline`, which is not
  available on Windows.
