# Hunt: admin actions a person or workload performed only once.
#
# In a stable project, each identity repeats the same few admin actions (Terraform
# applies, deploys, scheduled jobs). An action an identity has taken only once, such
# as a first-ever service account key or a one-off sink deletion, is a lead worth a
# look even when no rule covers it. Read-only calls (Data Access logs) are left out,
# and so are Google-managed service agents, which act on Google's behalf.
#
# Engine-neutral: scripts/run_hunts.py binds AuditEvent to DuckDB (tests/data) or to
# the BigQuery view purple_loop_lab_logs.audit_events.

AdminCall(principal:, method:) :-
  AuditEvent(log_type: "activity", principal_email: principal, method_name: method),
  ~Like(principal, "%@system.gserviceaccount.com"),
  ~Like(principal, "%@gcp-sa-%"),
  ~Like(principal, "%@compute-system.iam.gserviceaccount.com");

Calls(principal:, method:) += 1 :- AdminCall(principal:, method:);

Hunt(principal:, method:, calls:) :-
  Calls(principal:, method:) = calls,
  calls == 1;
