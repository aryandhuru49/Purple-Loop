# The three lab hosts. None has a public IP; reach them with IAP (see outputs).
#
#   dc01   Windows Server 2025, promotes itself to the first DC of a new forest
#   ws01   Windows Server 2025, joins the domain as a member server
#   lnx01  Debian 13, auditd + journald
#
# Each VM bootstraps itself with a startup script that runs at every boot and is
# safe to re-run: it installs Sysmon / Ops Agent / auditd only if missing, and
# re-applies audit and logging configuration each time.

locals {
  windows_image = "projects/windows-cloud/global/images/family/windows-2025"
  linux_image   = "projects/debian-cloud/global/images/family/debian-13"

  # Values shared by both Windows startup scripts.
  windows_script_vars = {
    project_id           = var.project_id
    domain_name          = var.domain_name
    domain_netbios_name  = var.domain_netbios_name
    dc_ip                = local.dc_ip
    admin_secret         = google_secret_manager_secret.lab["domain_admin"].secret_id
    dsrm_secret          = google_secret_manager_secret.lab["dsrm"].secret_id
    sysmon_zip_sha256    = var.sysmon_zip_sha256
    sysmon_config_url    = var.sysmon_config_url
    sysmon_config_sha256 = var.sysmon_config_sha256
  }

  hosts = {
    dc01 = {
      machine_type = var.windows_machine_type
      image        = local.windows_image
      disk_gb      = 50
      ip           = local.dc_ip
      metadata = {
        windows-startup-script-ps1 = templatefile("${path.module}/scripts/windows-bootstrap.ps1.tftpl",
        merge(local.windows_script_vars, { role = "dc" }))
      }
    }
    ws01 = {
      machine_type = var.windows_machine_type
      image        = local.windows_image
      disk_gb      = 50
      ip           = local.member_ip
      metadata = {
        windows-startup-script-ps1 = templatefile("${path.module}/scripts/windows-bootstrap.ps1.tftpl",
        merge(local.windows_script_vars, { role = "member" }))
      }
    }
    lnx01 = {
      machine_type = var.linux_machine_type
      image        = local.linux_image
      disk_gb      = 20
      ip           = local.linux_ip
      metadata = {
        startup-script = file("${path.module}/scripts/linux-bootstrap.sh")
      }
    }
  }
}

resource "google_compute_instance" "lab" {
  for_each = local.hosts

  name         = each.key
  machine_type = each.value.machine_type
  zone         = var.zone
  tags         = [local.lab_tag]
  labels       = { role = each.key }

  # Disks use Google-managed encryption. Customer-supplied keys (Trivy GCP-0033)
  # would make the lab unbootable whenever the key isn't supplied: wrong trade-off
  # for a throwaway lab holding no sensitive data.
  # trivy:ignore:GCP-0033
  boot_disk {
    initialize_params {
      image = each.value.image
      size  = each.value.disk_gb
      type  = "pd-balanced"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.lab.id
    network_ip = each.value.ip
    # No access_config block = no external IP address.
  }

  metadata = merge(each.value.metadata, {
    # Serial console access stays off; use IAP for interactive access.
    serial-port-enable = "FALSE"
    # SSH access is granted through IAM (OS Login), not keys pasted into
    # metadata. Windows ignores both keys; they are set everywhere for consistency.
    enable-oslogin         = "TRUE"
    block-project-ssh-keys = "TRUE"
  })

  service_account {
    email = google_service_account.lab_vm.email
    # Access is limited by the service account's IAM roles (iam.tf), which is
    # Google's recommended pattern over legacy access scopes.
    scopes = ["cloud-platform"]
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  # Nightly stop (schedule.tf).
  resource_policies = [google_compute_resource_policy.nightly_stop.id]

  # Lets Terraform stop a VM to change its machine type instead of failing.
  allow_stopping_for_update = true

  depends_on = [
    google_compute_router_nat.lab, # startup scripts download agents through NAT
    google_project_iam_member.vm_log_writer,
    google_secret_manager_secret_version.lab,
    google_secret_manager_secret_iam_member.vm_reads_secret,
  ]
}
