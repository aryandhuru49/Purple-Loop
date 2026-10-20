-- Generated from gcp_rare_principal_methods.l by scripts/run_hunts.py. Do not edit by hand.
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
WITH t_1_Calls AS (SELECT
  audit_events.principal_email AS principal,
  audit_events.method_name AS method,
  SUM(1) AS logica_value
FROM
  audit_events
WHERE
  ((SELECT
    MIN((CASE WHEN x_36.unnested_pod = 0 THEN 1 ELSE NULL END)) AS logica_value
  FROM
    (select unnest([0]::numeric[]) as unnested_pod) as x_36
  WHERE
    (audit_events.principal_email LIKE '%@system.gserviceaccount.com')) IS NULL) AND
  ((SELECT
    MIN((CASE WHEN x_38.unnested_pod = 0 THEN 1 ELSE NULL END)) AS logica_value
  FROM
    (select unnest([0]::numeric[]) as unnested_pod) as x_38
  WHERE
    (audit_events.principal_email LIKE '%@gcp-sa-%')) IS NULL) AND
  ((SELECT
    MIN((CASE WHEN x_40.unnested_pod = 0 THEN 1 ELSE NULL END)) AS logica_value
  FROM
    (select unnest([0]::numeric[]) as unnested_pod) as x_40
  WHERE
    (audit_events.principal_email LIKE '%@compute-system.iam.gserviceaccount.com')) IS NULL) AND
  ('activity' = audit_events.log_type)
GROUP BY audit_events.principal_email, audit_events.method_name)
SELECT
  Calls.principal AS principal,
  Calls.method AS method,
  1 AS calls
FROM
  t_1_Calls AS Calls
WHERE
  (Calls.logica_value = 1);
