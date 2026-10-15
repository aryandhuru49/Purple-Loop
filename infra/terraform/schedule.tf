# Nightly auto-shutdown: stops every lab VM at var.shutdown_cron in var.time_zone,
# so a forgotten lab costs only disk storage overnight. There is deliberately no
# start schedule; start the lab when you need it (docs/lab_runbook.md).
#
# Stopping is done by the Compute Engine service agent, which iam.tf grants
# roles/compute.instanceAdmin.v1. Without that grant the schedule silently does nothing.
resource "google_compute_resource_policy" "nightly_stop" {
  name   = "purple-loop-nightly-stop"
  region = var.region

  instance_schedule_policy {
    time_zone = var.time_zone

    vm_stop_schedule {
      schedule = var.shutdown_cron
    }
  }

  depends_on = [google_project_iam_member.compute_agent_scheduler]
}
