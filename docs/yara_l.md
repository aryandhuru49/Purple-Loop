# Native YARA-L 2.0 rules

`rules/yara_l/` holds three hand-written Google SecOps rules that use features Sigma
cannot express well. They complement the Sigma rules rather than duplicating them.

> **Not executed.** Google SecOps is a paid platform, so these rules are written,
> linted offline (`tests/test_yaral_lint.py`), and reviewed, but never compiled or
> run against real data in this project. Treat them as reviewed drafts until they are
> validated in a tenant (steps below).

## The rules

| Rule | YARA-L feature it shows | Why Sigma falls short |
|---|---|---|
| `kerberoasting_burst.yaral` | Hop window grouped by account, `count_distinct` outcome, outcome condition (`$distinct_services >= 5`) | Sigma rules match single events; the Sigma Kerberoasting rule alerts on every RC4 ticket. The real signal is *volume per account*. |
| `lsass_access_followed_by_dump_file.yaral` | Two event types joined on host + process GUID, ordered by timestamp, **sliding window** (`over 2m after $open`) | Sigma cannot join a process-access event to a later file-creation event from the same process. |
| `same_service_installed_on_many_hosts.yaral` | Aggregation across the fleet: distinct hosts per service name in a 30-minute window | A per-event rule sees one host at a time; spread across hosts is invisible to it. |

The LSASS rule is grounded in the Phase 1 data: in the OTRF comsvcs dataset, `rundll32.exe`
opens `lsass.exe` with `0x1fffff` and then writes `lsass-comsvcs.dmp`, which is exactly the
sequence the rule joins.

Sigma does have a correlation extension (`event_count`, `value_count`, `temporal`), but the
pySigma SecOps backend does not convert correlations, and joining on a field shared by two
*different* log sources (process GUID) is more natural in YARA-L.

## UDM field mappings

A YARA-L rule is only as good as its assumptions about how Google's parser maps raw Windows
fields into UDM. Each mapping is marked as confirmed or assumed.

| Raw field | UDM field used | Status | Evidence |
|---|---|---|---|
| Sysmon 10 event | `metadata.event_type = "PROCESS_OPEN"` | Confirmed | Google community rule `potential_credential_dumping_activity_via_lsass.yaral` |
| Sysmon 10 `GrantedAccess` | `target.resource.name` | Confirmed | Same rule matches access masks on this field |
| Sysmon 10/11 process GUID | `principal.process.product_specific_process_id` | Confirmed | Used in outcomes of Google's LSASS and dump-file rules |
| Sysmon 11 event | `metadata.event_type = "FILE_CREATION"`, `target.file.full_path` | Confirmed | Google community rule `lsass_process_memory_dump_file_creation.yaral` |
| 7045 service install | `SERVICE_CREATION`, `product_name = "Service Control Manager"`, `target.application` = service name | Confirmed | Google community rule `win_susp_or_malicious_service_created.yaral` |
| 4769 `TicketEncryptionType`, `Status` | `additional.fields["..."]` | **Assumed** | No current Google rule references these fields |
| 4769 requesting account / `ServiceName` | `principal.user.userid` / `target.user.userid` | **Assumed** | Same as above |

Source of the confirmed mappings: https://github.com/chronicle/detection-rules
(rules under `rules/community/microsoft/windows/`).

## Validating in a tenant

1. Ingest Windows Security and Sysmon logs (Phase 2's lab produces both).
2. Confirm the assumed 4769 mappings with a UDM search, then adjust the rule:
   `metadata.product_event_type = "4769"` and inspect where `TicketEncryptionType`,
   `ServiceName` and the account name land in the parsed event.
3. Paste each rule into the Rules Editor; it compiles on save and reports syntax errors.
4. Run a **retrohunt** over the time window of a lab attack (Phase 2 runbook) and confirm
   the rule fires, then over a quiet window and confirm it doesn't.
5. Enable as a live rule with alerting only after both checks pass.

## Writing style choices

- Functions and aggregations operate on event fields (e.g. `count_distinct($tgs.target.user.userid)`),
  matching Google's published rules, rather than on placeholder variables.
- `risk_score` is a constant per rule. Computing it from another outcome variable may be
  supported, but it is not used in Google's examples, so it was avoided until it can be tested.
- Every rule records the ATT&CK version (`v20`) and its false positives in `meta`.
