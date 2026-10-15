# Rule conversion

Sigma rules in `rules/sigma/` are the single source of truth. `scripts/convert_rules.py`
turns them into platform queries under `converted/`. Those files are generated: CI runs
`convert_rules.py --check` and fails if anyone edits them by hand or forgets to regenerate.

```bash
uv run python scripts/convert_rules.py          # regenerate converted/
uv run python scripts/convert_rules.py --check  # verify converted/ is current
```

Current per-rule status: [converted/CONVERSION_REPORT.md](../converted/CONVERSION_REPORT.md).

## Targets

| Target | Backend | Pipelines | Required to pass |
|---|---|---|---|
| Splunk SPL + `savedsearches.conf` | pySigma-backend-splunk | `sysmon`, `splunk_windows` | Yes |
| Google SecOps UDM search | pySigma-backend-secops | `secops_udm` | No |
| Google SecOps YARA-L 2.0 | pySigma-backend-secops (`yara_l` format, beta upstream) | `secops_udm` | No |

Versions are pinned in `pyproject.toml`. pySigma stays below 2.0 because sigma-cli and the
Splunk and SecOps backends still require pySigma 1.x.

## Splunk assumptions

The `splunk_windows` pipeline writes `source="WinEventLog:<channel>"` and Windows field names
(`EventCode`, `Image`, `CommandLine`, ...). That matches the Splunk Add-on for Microsoft
Windows with classic (non-XML) rendering. If your inputs use `renderXml = true`, events arrive
as `source="XmlWinEventLog:<channel>"` and the source conditions must be adapted (for example
with a custom pipeline). The searches have not been run against a live Splunk instance in
this project; the detection logic itself is tested locally with SQLite
(`scripts/sigma_harness.py`).

## Google SecOps: what works and what doesn't

Google SecOps is a paid platform, so none of the SecOps output is executed. It is generated,
checked automatically for the problems below, and reviewed by hand.

**Unmapped fields.** The backend maps Windows fields onto Google's Unified Data Model (UDM).
It has no mapping for `GrantedAccess`, `TicketEncryptionType`, `ImagePath` or `TaskContent`,
so the LSASS-access, Kerberoasting, service-install and 4698 rules are reported as unsupported.
We deliberately do not invent UDM mappings: a wrong mapping produces a query that looks valid
and silently never matches. Kerberoasting is covered instead by a hand-written native YARA-L
rule in `rules/yara_l/`.

**Backend bugs found while reviewing the output (pySigma-backend-secops 1.0.0):**

1. *Operator precedence in YARA-L output.* When a Sigma rule uses the `windash` modifier on
   a single value, the YARA-L formatter joins the dash variants with `OR` but does not wrap them
   in parentheses, e.g. `img AND -i: OR /i: OR -i: AND payload`. `AND` binds tighter than `OR`,
   so the rule would fire on any command line containing `/i:`. The UDM search output of the
   same rule is parenthesized correctly. `convert_rules.py` detects mixed top-level `AND`/`OR`
   and marks the file `DO NOT DEPLOY` (⚠️ in the report) rather than rewriting the logic.
2. *Invalid rule names.* The rule name is derived from the title without sanitizing, so
   `Scrobj.dll (Squiblydoo)` yields an invalid identifier. `convert_rules.py` replaces
   characters other than letters, digits and `_`. Only the name is changed.
3. *Meta strings.* Multi-line descriptions and double quotes are copied into YARA-L `meta:`
   verbatim, which breaks string syntax. `convert_rules.py` collapses whitespace and replaces
   double quotes with single quotes in title, description and false positives before conversion.

These are good candidates to report upstream at
https://github.com/AttackIQ/pySigma-backend-secops/issues.

**Field semantics to verify in a real tenant.** Sysmon's `TargetObject` contains the registry
key *and* value name (`HKLM\...\CurrentVersion\Run\Updater`). In UDM, the key and value name
are usually separate fields (`target.registry.registry_key` / `registry_value_name`). The Run-key
rule matches `\CurrentVersion\Run\` with a trailing backslash (to avoid look-alike keys such as
`...\RunTime\`); if the SecOps parser stores only the key, that pattern needs adjusting for
SecOps. This cannot be confirmed without a tenant and is listed as a known limitation.

## ATT&CK version note

Tags follow ATT&CK v20, in which tactic TA0005 is named **Stealth** (formerly Defense Evasion)
and **Defense Impairment** (TA0112) was added. `sigma check` validates tags against the current
ATT&CK release, which is how the rename was caught.
