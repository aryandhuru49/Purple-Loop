# Route lab telemetry from Cloud Logging into BigQuery, where it can be queried
# with SQL and exported into tests/data (scripts/export_lab_logs.py).
#
# Log names come from the Ops Agent receiver IDs in infra/terraform/scripts/:
#   winevt   Windows Security, System, Sysmon and PowerShell event logs (raw XML)
#   auditd   Linux audit log (process execution)
#   journald Linux systemd journal
# plus the project's Cloud Audit Logs (who changed what in GCP), for the cloud
# detections and the BigQuery hunts:
#   cloudaudit.googleapis.com/activity     admin changes (always on, free)
#   cloudaudit.googleapis.com/data_access  reads, where enabled (see audit.tf)
# With partitioned tables, each log name becomes one table partitioned by day
# (e.g. cloudaudit_googleapis_com_activity).

locals {
  lab_log_names   = ["winevt", "auditd", "journald"]
  audit_log_names = ["cloudaudit.googleapis.com%2Factivity", "cloudaudit.googleapis.com%2Fdata_access"]
}

resource "google_bigquery_dataset" "lab_logs" {
  dataset_id  = "purple_loop_lab_logs"
  location    = var.region
  description = "Purple Loop lab telemetry exported from Cloud Logging."

  # Old partitions are deleted automatically: the lab keeps a rolling window,
  # and anything worth keeping is exported into tests/data as JSONL.
  default_partition_expiration_ms = var.log_retention_days * 24 * 60 * 60 * 1000

  # Lets `terraform destroy` remove the dataset even when it still holds logs.
  delete_contents_on_destroy = true

  depends_on = [google_project_service.apis]
}

resource "google_logging_project_sink" "lab_to_bigquery" {
  name        = "purple-loop-lab-to-bigquery"
  destination = "bigquery.googleapis.com/projects/${var.project_id}/datasets/${google_bigquery_dataset.lab_logs.dataset_id}"
  filter = join(" OR ", [
    for name in concat(local.lab_log_names, local.audit_log_names) :
    "logName=\"projects/${var.project_id}/logs/${name}\""
  ])

  # The sink gets its own service account (writer_identity) that we grant
  # write access on just this dataset below.
  unique_writer_identity = true

  bigquery_options {
    use_partitioned_tables = true
  }
}

# One flat view over both audit log tables, with simple column names. The Logica
# hunts in hunts/logica/gcp_*.l read this view on BigQuery, and scripts/run_hunts.py
# builds a DuckDB table with the same columns from tests/data, so one hunt file runs
# on both engines. The wildcard (cloudaudit_googleapis_com_*) picks up the
# data_access table too; its suffix becomes log_type.
#
# The sink creates the tables when the first matching entry arrives (usually within
# a minute of the first apply). If the view fails with "no matching table", run
# terraform apply again.
resource "google_bigquery_table" "audit_events" {
  dataset_id          = google_bigquery_dataset.lab_logs.dataset_id
  table_id            = "audit_events"
  description         = "Flattened Cloud Audit Log entries for the Logica hunts."
  deletion_protection = false

  view {
    use_legacy_sql = false
    query          = <<-SQL
      SELECT
        timestamp                                                     AS event_time,
        _TABLE_SUFFIX                                                 AS log_type,
        protopayload_auditlog.serviceName                             AS service_name,
        protopayload_auditlog.methodName                              AS method_name,
        protopayload_auditlog.authenticationInfo.principalEmail       AS principal_email,
        protopayload_auditlog.resourceName                            AS resource_name,
        protopayload_auditlog.requestMetadata.callerIp                AS caller_ip
      FROM `${var.project_id}.${google_bigquery_dataset.lab_logs.dataset_id}.cloudaudit_googleapis_com_*`
    SQL
  }
}

resource "google_bigquery_dataset_iam_member" "sink_writer" {
  dataset_id = google_bigquery_dataset.lab_logs.dataset_id
  role       = "roles/bigquery.dataEditor"
  member     = google_logging_project_sink.lab_to_bigquery.writer_identity
}
