# Network: one private subnet, no public IPs on any VM.
#   * Inbound admin access only through Identity-Aware Proxy (IAP) TCP forwarding.
#   * Outbound internet (agent and Sysmon downloads, Windows Update) through Cloud NAT.
#   * Private Google Access lets VMs reach Google APIs (Logging, Secret Manager) privately.

locals {
  # Fixed internal addresses, so member hosts can point DNS at the DC.
  dc_ip     = cidrhost(var.subnet_cidr, 10)
  member_ip = cidrhost(var.subnet_cidr, 11)
  linux_ip  = cidrhost(var.subnet_cidr, 12)

  # Network tag applied to every lab VM; firewall rules target it.
  lab_tag = "purple-loop-lab"

  # Google's published source range for IAP TCP forwarding.
  iap_range = "35.235.240.0/20"
}

resource "google_compute_network" "lab" {
  name                    = "purple-loop-vpc"
  auto_create_subnetworks = false

  depends_on = [google_project_service.apis]
}

resource "google_compute_subnetwork" "lab" {
  name                     = "purple-loop-subnet"
  network                  = google_compute_network.lab.id
  region                   = var.region
  ip_cidr_range            = var.subnet_cidr
  private_ip_google_access = true

  # VPC flow logs are network telemetry for later hunts. Sampling and a 10 minute
  # aggregation keep the volume (and cost) small.
  log_config {
    aggregation_interval = "INTERVAL_10_MIN"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

# ---------------------------------------------------------------------------
# Outbound internet through Cloud NAT
# ---------------------------------------------------------------------------

resource "google_compute_router" "lab" {
  name    = "purple-loop-router"
  network = google_compute_network.lab.id
  region  = var.region
}

resource "google_compute_router_nat" "lab" {
  name                               = "purple-loop-nat"
  router                             = google_compute_router.lab.name
  region                             = var.region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "LIST_OF_SUBNETWORKS"

  subnetwork {
    name                    = google_compute_subnetwork.lab.id
    source_ip_ranges_to_nat = ["ALL_IP_RANGES"]
  }

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}

# ---------------------------------------------------------------------------
# Firewall. A custom VPC denies all ingress by default; these rules open only
# what the lab needs.
# ---------------------------------------------------------------------------

# RDP and SSH only from IAP's range: nothing is reachable from the internet.
resource "google_compute_firewall" "allow_iap" {
  name          = "purple-loop-allow-iap"
  network       = google_compute_network.lab.id
  direction     = "INGRESS"
  source_ranges = [local.iap_range]
  target_tags   = [local.lab_tag]

  allow {
    protocol = "tcp"
    ports    = ["22", "3389"]
  }

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

# Lab hosts talk to each other freely. Active Directory needs DNS, Kerberos,
# LDAP, SMB, RPC and a dynamic RPC port range, and lateral-movement telemetry
# is part of what the lab is for. Traffic never leaves the subnet.
# Accepted Trivy findings: all ports (GCP-0072) and large port range (GCP-0074),
# limited to sources inside the lab subnet.
# trivy:ignore:GCP-0072
# trivy:ignore:GCP-0074
resource "google_compute_firewall" "allow_internal" {
  name          = "purple-loop-allow-internal"
  network       = google_compute_network.lab.id
  direction     = "INGRESS"
  source_ranges = [var.subnet_cidr]
  target_tags   = [local.lab_tag]

  allow {
    protocol = "all"
  }
}
