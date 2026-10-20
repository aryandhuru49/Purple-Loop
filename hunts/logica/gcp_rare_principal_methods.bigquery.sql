-- Generated from gcp_rare_principal_methods.l by scripts/run_hunts.py. Do not edit by hand.
WITH t_1_Calls AS (SELECT
  purple_loop_lab_logs_audit_events.principal_email AS principal,
  purple_loop_lab_logs_audit_events.method_name AS method,
  SUM(1) AS logica_value
FROM
  `purple_loop_lab_logs.audit_events` AS purple_loop_lab_logs_audit_events
WHERE
  ((SELECT
    MIN(1) AS logica_value
  FROM
    (SELECT 'singleton' as s) as unused_singleton
  WHERE
    (purple_loop_lab_logs_audit_events.principal_email LIKE "%@system.gserviceaccount.com")) IS NULL) AND
  ((SELECT
    MIN(1) AS logica_value
  FROM
    (SELECT 'singleton' as s) as unused_singleton
  WHERE
    (purple_loop_lab_logs_audit_events.principal_email LIKE "%@gcp-sa-%")) IS NULL) AND
  ((SELECT
    MIN(1) AS logica_value
  FROM
    (SELECT 'singleton' as s) as unused_singleton
  WHERE
    (purple_loop_lab_logs_audit_events.principal_email LIKE "%@compute-system.iam.gserviceaccount.com")) IS NULL) AND
  ("activity" = purple_loop_lab_logs_audit_events.log_type)
GROUP BY principal, method)
SELECT
  Calls.principal AS principal,
  Calls.method AS method,
  1 AS calls
FROM
  t_1_Calls AS Calls
WHERE
  (Calls.logica_value = 1);
