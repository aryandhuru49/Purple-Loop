-- Generated from rare_parent_child_pairs.l by scripts/run_hunts.py. Do not edit by hand.
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
WITH t_2_ProcessStart AS (SELECT * FROM (

    SELECT
      LOWER(logs.ParentImage) AS parent,
      LOWER(logs.Image) AS child
    FROM
      logs
    WHERE
      (logs.EventID = 1)
   UNION ALL

    SELECT
      LOWER(t_3_logs.ParentProcessName) AS parent,
      LOWER(t_3_logs.NewProcessName) AS child
    FROM
      logs AS t_3_logs
    WHERE
      (t_3_logs.EventID = 4688)

) AS UNUSED_TABLE_NAME  ),
t_1_PairCount AS (SELECT
  ProcessStart.parent AS parent,
  ProcessStart.child AS child,
  SUM(1) AS logica_value
FROM
  t_2_ProcessStart AS ProcessStart
GROUP BY ProcessStart.parent, ProcessStart.child)
SELECT
  PairCount.parent AS parent,
  PairCount.child AS child,
  PairCount.logica_value AS seen
FROM
  t_1_PairCount AS PairCount
WHERE
  (PairCount.logica_value <= 2);
