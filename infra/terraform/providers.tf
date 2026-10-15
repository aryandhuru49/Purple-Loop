provider "google" {
  project = var.project_id
  region  = var.region
  zone    = var.zone

  # The Billing Budgets API needs a quota project when called with user
  # credentials (gcloud auth application-default login). Bill those calls to
  # the lab project instead of failing with "API requires a quota project".
  user_project_override = true
  billing_project       = var.project_id

  default_labels = {
    project    = "purple-loop"
    managed_by = "terraform"
  }
}

data "google_project" "lab" {
  project_id = var.project_id
}
