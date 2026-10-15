# Ready-to-paste commands for using the lab. None of these outputs is secret:
# the passwords live only in Secret Manager (see secrets.tf).

output "rdp_tunnels" {
  description = "Open an IAP tunnel to a Windows host, then RDP to localhost:<port>."
  value = {
    dc01 = "gcloud compute start-iap-tunnel dc01 3389 --local-host-port=localhost:33891 --zone=${var.zone} --project=${var.project_id}"
    ws01 = "gcloud compute start-iap-tunnel ws01 3389 --local-host-port=localhost:33892 --zone=${var.zone} --project=${var.project_id}"
  }
}

output "ssh_linux" {
  description = "SSH to the Linux host through IAP (OS Login)."
  value       = "gcloud compute ssh lnx01 --tunnel-through-iap --zone=${var.zone} --project=${var.project_id}"
}

output "domain_admin_login" {
  description = "RDP user name, and the command that prints its password."
  value = {
    user            = "${var.domain_netbios_name}\\Administrator"
    password_access = "gcloud secrets versions access latest --secret=${google_secret_manager_secret.lab["domain_admin"].secret_id} --project=${var.project_id}"
  }
}

output "bigquery_dataset" {
  description = "Dataset receiving lab logs (tables: winevt, auditd, journald)."
  value       = "${var.project_id}.${google_bigquery_dataset.lab_logs.dataset_id}"
}

output "lab_hosts" {
  description = "Lab VM names and internal IPs."
  value       = { for name, vm in google_compute_instance.lab : name => vm.network_interface[0].network_ip }
}
