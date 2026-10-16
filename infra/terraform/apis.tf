# Every Google API the lab uses. disable_on_destroy = false so `terraform destroy`
# never switches off an API that something outside this lab might rely on.
locals {
  apis = [
    "compute.googleapis.com",
    "iap.googleapis.com",
    "iam.googleapis.com", # service account for the VMs
    "logging.googleapis.com",
    "monitoring.googleapis.com",
    "bigquery.googleapis.com",
    "secretmanager.googleapis.com",
    "billingbudgets.googleapis.com",
    "cloudresourcemanager.googleapis.com",
  ]
}

resource "google_project_service" "apis" {
  for_each = toset(local.apis)

  service            = each.value
  disable_on_destroy = false
}
