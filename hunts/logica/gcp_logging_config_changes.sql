-- Generated from gcp_logging_config_changes.l by scripts/run_hunts.py. Do not edit by hand.
-- Initializing DuckDB environment.
create schema if not exists logica_home;
-- Empty record, has to have a field by DuckDB syntax.
drop type if exists logicarecord893574736 cascade; create type logicarecord893574736 as struct(nirvana numeric);
create sequence if not exists eternal_logical_sequence;


-- Logica type: logicarecord481217614
drop type if exists logicarecord481217614 cascade; create type logicarecord481217614 as struct(r logicarecord893574736);

-- Logica type: logicarecord383307722
drop type if exists logicarecord383307722 cascade; create type logicarecord383307722 as struct(a timestamp);

-- Logica type: logicarecord519939597
drop type if exists logicarecord519939597 cascade; create type logicarecord519939597 as struct(args text[], predicate text);
SELECT
  audit_events.principal_email AS principal,
  audit_events.method_name AS method,
  audit_events.resource_name AS resource,
  SUM(1) AS changes,
  MIN(audit_events.event_time) AS first_seen,
  MAX(audit_events.event_time) AS last_seen
FROM
  audit_events
WHERE
  (audit_events.method_name LIKE 'google.logging.v2.ConfigServiceV2.%') AND
  ((SELECT
    MIN((CASE WHEN x_31.unnested_pod = 0 THEN 1 ELSE NULL END)) AS logica_value
  FROM
    (select unnest([0]::numeric[]) as unnested_pod) as x_31
  WHERE
    (audit_events.method_name LIKE '%.Get%')) IS NULL) AND
  ((SELECT
    MIN((CASE WHEN x_33.unnested_pod = 0 THEN 1 ELSE NULL END)) AS logica_value
  FROM
    (select unnest([0]::numeric[]) as unnested_pod) as x_33
  WHERE
    (audit_events.method_name LIKE '%.List%')) IS NULL) AND
  ('logging.googleapis.com' = audit_events.service_name)
GROUP BY audit_events.principal_email, audit_events.method_name, audit_events.resource_name;
