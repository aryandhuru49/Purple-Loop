-- Generated from gcp_logging_config_changes.l by scripts/run_hunts.py. Do not edit by hand.
SELECT
  purple_loop_lab_logs_audit_events.principal_email AS principal,
  purple_loop_lab_logs_audit_events.method_name AS method,
  purple_loop_lab_logs_audit_events.resource_name AS resource,
  SUM(1) AS changes,
  MIN(purple_loop_lab_logs_audit_events.event_time) AS first_seen,
  MAX(purple_loop_lab_logs_audit_events.event_time) AS last_seen
FROM
  `purple_loop_lab_logs.audit_events` AS purple_loop_lab_logs_audit_events
WHERE
  (purple_loop_lab_logs_audit_events.method_name LIKE "google.logging.v2.ConfigServiceV2.%") AND
  ((SELECT
    MIN(1) AS logica_value
  FROM
    (SELECT 'singleton' as s) as unused_singleton
  WHERE
    (purple_loop_lab_logs_audit_events.method_name LIKE "%.Get%")) IS NULL) AND
  ((SELECT
    MIN(1) AS logica_value
  FROM
    (SELECT 'singleton' as s) as unused_singleton
  WHERE
    (purple_loop_lab_logs_audit_events.method_name LIKE "%.List%")) IS NULL) AND
  ("logging.googleapis.com" = purple_loop_lab_logs_audit_events.service_name)
GROUP BY principal, method, resource;
