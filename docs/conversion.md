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
| Splunk SPL + `savedsearches.conf` | pySigma-backend-splunk | [`gcp_audit_splunk.yml`](../pipelines/gcp_audit_splunk.yml), `sysmon`, `splunk_windows` | Yes |
| Google SecOps UDM search | pySigma-backend-secops | [`gcp_audit_secops.yml`](../pipelines/gcp_audit_secops.yml), `secops_udm` | No |
| Google SecOps YARA-L 2.0 | pySigma-backend-secops (`yara_l` format, beta upstream) | [`gcp_audit_secops.yml`](../pipelines/gcp_audit_secops.yml), `secops_udm` | No |

The installed pipelines cover Windows only. The two `pipelines/gcp_audit_*.yml` files are
this repo's own field mappings for the GCP Cloud Audit Log rules (see below); they apply
only to rules with `logsource: {product: gcp, service: gcp.audit}`.

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
4. *Dropped NOT on multi-condition filters (found with the GCP rules).* `sel and not filter`
   where `filter` has two or more conditions is emitted as `sel AND filter`: the NOT simply
   disappears. A single negated condition converts correctly (to `!=`). The output compiles,
   so nothing warns you, and the rule alerts *only* on the activity it was meant to exclude:
   the secret rule would fire on the lab VMs and never on a person. Reproduced with a
   two-line Windows rule, so it is the backend, not this repo's pipeline.
   `convert_rules.py` detects a negated detection with more than one condition and marks
   the output `DO NOT DEPLOY` (tested in `tests/test_convert.py`).
   Upstream issue draft: [docs/upstream/secops_dropped_not_issue.md](upstream/secops_dropped_not_issue.md).

These are good candidates to report upstream at
https://github.com/AttackIQ/pySigma-backend-secops/issues.

**Field semantics to verify in a real tenant.** Sysmon's `TargetObject` contains the registry
key *and* value name (`HKLM\...\CurrentVersion\Run\Updater`). In UDM, the key and value name
are usually separate fields (`target.registry.registry_key` / `registry_value_name`). The Run-key
rule matches `\CurrentVersion\Run\` with a trailing backslash (to avoid look-alike keys such as
`...\RunTime\`); if the SecOps parser stores only the key, that pattern needs adjusting for
SecOps. This cannot be confirmed without a tenant and is listed as a known limitation.

## GCP Cloud Audit Log rules

The rules use the native Cloud Logging field paths (`protoPayload.methodName`), with `[]`
for arrays, as Google's own SecOps parser documentation writes them. Each target maps them
explicitly; there is no fallback that could produce a plausible but wrong field.

**Splunk.** Assumes the [Splunk Add-on for Google Cloud Platform](https://splunkbase.splunk.com/app/3088)
reading a Pub/Sub log sink: `sourcetype="google:gcp:pubsub:message"`, the LogEntry under
`data`, arrays as Splunk multivalue fields with `{}`
(`data.protoPayload.request.sourceRanges{}`). The pipeline's first step fails the conversion
for any GCP field it has no mapping for. Not run against a live Splunk.

**SecOps.** Every UDM field comes from Google's mapping table for the default
`GCP_CLOUDAUDIT` parser ([docs](https://docs.cloud.google.com/chronicle/docs/ingestion/default-parsers/gcp-cloudaudit)),
for example `methodName` → `metadata.product_event_type`, `principalEmail` →
`principal.user.email_addresses`, `bindingDeltas[].role` → `principal.user.attribute.roles.name`.
Two rules are unsupported because the documentation has no mapping for a field they need
(`request.sink.disabled`; `request.sourceRanges[]` is only mapped to a label). Two more
convert but hit backend bug 4 above and are marked not deployable. That leaves one GCP rule
(service account key created) with trustworthy SecOps output, which is the honest result.

## ATT&CK version note

Tags follow ATT&CK v20, in which tactic TA0005 is named **Stealth** (formerly Defense Evasion)
and **Defense Impairment** (TA0112) was added. `sigma check` validates tags against the current
ATT&CK release, which is how the rename was caught. The same release renumbered the cloud
techniques the GCP rules use: *Disable or Modify Cloud Log* is now **T1685.002** and *Cloud
Firewall* is **T1686.001** (formerly T1562.008 and T1562.007, which no longer exist).
