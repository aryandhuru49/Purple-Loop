# Data Access audit logs for Secret Manager.
#
# Admin Activity audit logs (who created, changed or deleted something) are always
# on. Data Access logs (who READ something) are off by default for most services,
# because they can be high volume. Reading a lab secret is exactly what the
# "secret accessed by an unexpected principal" rule watches, so turn them on for
# Secret Manager only. Two secrets read a few times a day is a negligible volume.
resource "google_project_iam_audit_config" "secret_manager_reads" {
  project = var.project_id
  service = "secretmanager.googleapis.com"

  # DATA_READ: secret values read (AccessSecretVersion) - what the rule needs.
  # ADMIN_READ / DATA_WRITE: metadata and IAM reads, version writes. Cheap here,
  # and full coverage is what Trivy (GCP-0079) checks for.
  audit_log_config {
    log_type = "DATA_READ"
  }
  audit_log_config {
    log_type = "ADMIN_READ"
  }
  audit_log_config {
    log_type = "DATA_WRITE"
  }

  depends_on = [google_project_service.apis]
}
