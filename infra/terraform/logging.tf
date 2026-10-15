# Route lab telemetry from Cloud Logging into BigQuery, where it can be queried
# with SQL and exported into tests/data (scripts/export_lab_logs.py).
#
# Log names come from the Ops Agent receiver IDs in infra/terraform/scripts/:
#   winevt   Windows Security, System, Sysmon and PowerShell event logs (raw XML)
#   auditd   Linux audit log (process execution)
#   journald Linux systemd journal
# With partitioned tables, each log name becomes one table partitioned by day.

locals {
  lab_log_names = ["winevt", "auditd", "journald"]
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
    for name in local.lab_log_names : "logName=\"projects/${var.project_id}/logs/${name}\""
  ])

  # The sink gets its own service account (writer_identity) that we grant
  # write access on just this dataset below.
  unique_writer_identity = true

  bigquery_options {
    use_partitioned_tables = true
  }
}

resource "google_bigquery_dataset_iam_member" "sink_writer" {
  dataset_id = google_bigquery_dataset.lab_logs.dataset_id
  role       = "roles/bigquery.dataEditor"
  member     = google_logging_project_sink.lab_to_bigquery.writer_identity
}
