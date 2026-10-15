# One dedicated service account for the lab VMs, instead of the Compute Engine
# default account (which has the broad Editor role). It can only write logs and
# metrics and read the two lab secrets.
resource "google_service_account" "lab_vm" {
  account_id   = "purple-loop-vm"
  display_name = "Purple Loop lab VMs"

  depends_on = [google_project_service.apis]
}

resource "google_project_iam_member" "vm_log_writer" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = google_service_account.lab_vm.member
}

resource "google_project_iam_member" "vm_metric_writer" {
  project = var.project_id
  role    = "roles/monitoring.metricWriter"
  member  = google_service_account.lab_vm.member
}

# The nightly stop schedule (schedule.tf) runs as the Compute Engine service agent,
# which needs permission to stop instances.
resource "google_project_iam_member" "compute_agent_scheduler" {
  project = var.project_id
  role    = "roles/compute.instanceAdmin.v1"
  member  = "serviceAccount:service-${data.google_project.lab.number}@compute-system.iam.gserviceaccount.com"

  depends_on = [google_project_service.apis]
}

# Optional extra people who may open IAP tunnels (owners can already).
resource "google_project_iam_member" "iap_tunnel_users" {
  for_each = toset(var.iap_members)

  project = var.project_id
  role    = "roles/iap.tunnelResourceAccessor"
  member  = each.value
}
