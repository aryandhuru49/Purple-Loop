# Hunt: who changed Cloud Logging configuration, and how often?
#
# The sink rule alerts only when a sink is deleted or disabled. Quieter ways to blind
# a SIEM, such as narrowing a sink's filter or adding an exclusion, look exactly like
# routine Terraform changes, so they are left to this hunt: every create, update or
# delete of sinks, exclusions, buckets and views, grouped by who made it. An analyst
# compares the list with the people and pipelines that are supposed to own logging.
#
# Engine-neutral: scripts/run_hunts.py binds AuditEvent to DuckDB (tests/data) or to
# the BigQuery view purple_loop_lab_logs.audit_events.

LoggingChange(principal:, method:, resource:, time:) :-
  AuditEvent(service_name: "logging.googleapis.com", method_name: method,
             principal_email: principal, resource_name: resource, event_time: time),
  Like(method, "google.logging.v2.ConfigServiceV2.%"),
  ~Like(method, "%.Get%"),
  ~Like(method, "%.List%");

Hunt(principal:, method:, resource:,
     changes? += 1,
     first_seen? Min= time,
     last_seen? Max= time) distinct :-
  LoggingChange(principal:, method:, resource:, time:);
