# ---------------------------------------------------------------------------
# Required: set these in terraform.tfvars (copy terraform.tfvars.example).
# ---------------------------------------------------------------------------

variable "project_id" {
  description = "GCP project that hosts the lab. Use a dedicated project you can delete."
  type        = string
}

variable "billing_account_id" {
  description = "Billing account linked to the project, e.g. 012345-6789AB-CDEF01. Used for the budget alert."
  type        = string
}

variable "budget_alert_email" {
  description = "Email address that receives budget alerts."
  type        = string
}

# ---------------------------------------------------------------------------
# Optional
# ---------------------------------------------------------------------------

variable "region" {
  description = "Region for the subnet, NAT and VMs."
  type        = string
  default     = "us-central1"
}

variable "zone" {
  description = "Zone for the VMs."
  type        = string
  default     = "us-central1-a"
}

variable "time_zone" {
  description = "IANA time zone for the nightly shutdown schedule."
  type        = string
  default     = "America/New_York"
}

variable "shutdown_cron" {
  description = "Cron expression (in time_zone) for stopping all lab VMs. Default: every night at 22:00."
  type        = string
  default     = "0 22 * * *"
}

variable "monthly_budget" {
  description = "Monthly budget amount. Alerts fire at 50%, 90% and 100% of actual spend, and at 100% of forecast."
  type        = number
  default     = 50
}

variable "budget_currency" {
  description = "Currency of the billing account (must match it, or budget creation fails)."
  type        = string
  default     = "USD"
}

variable "domain_name" {
  description = "DNS name of the lab Active Directory forest."
  type        = string
  default     = "lab.purpleloop.local"
}

variable "domain_netbios_name" {
  description = "NetBIOS name of the lab domain (15 characters max)."
  type        = string
  default     = "PLLAB"
}

variable "subnet_cidr" {
  description = "CIDR range of the lab subnet. The VMs get fixed addresses .10, .11 and .12 inside it."
  type        = string
  default     = "10.10.0.0/24"
}

variable "windows_machine_type" {
  description = "Machine type for the two Windows Server hosts."
  type        = string
  default     = "e2-standard-2"
}

variable "linux_machine_type" {
  description = "Machine type for the Linux host."
  type        = string
  default     = "e2-small"
}

variable "iap_members" {
  description = "Extra principals allowed to open IAP tunnels, e.g. [\"user:you@example.com\"]. Project owners already can."
  type        = list(string)
  default     = []
}

variable "log_retention_days" {
  description = "Days BigQuery keeps exported lab logs before partitions expire."
  type        = number
  default     = 30
}

# ---------------------------------------------------------------------------
# Pinned downloads. Startup scripts refuse to install a file whose SHA-256
# differs, so an upstream change fails loudly instead of silently changing
# what the lab collects. Update both values together when upgrading.
# ---------------------------------------------------------------------------

variable "sysmon_zip_sha256" {
  description = "SHA-256 of https://download.sysinternals.com/files/Sysmon.zip (Sysmon 15.22, 2026-09-10)."
  type        = string
  default     = "00ecf1b46aec99299d3ae0bca79dc621458bd014b20b509d7c5c8e8c8611aa54"
}

variable "sysmon_config_url" {
  description = "Sysmon configuration: sysmon-modular 'balanced' profile, pinned to one release."
  type        = string
  default     = "https://github.com/olafhartong/sysmon-modular/releases/download/configs-a45dedb13a43/sysmonconfig-15.21.xml"
}

variable "sysmon_config_sha256" {
  description = "SHA-256 of sysmon_config_url (matches the release's SHA256SUMS file)."
  type        = string
  default     = "64bec37ba849c5f2934a55d2a29e7ddfae46a30d56f7f2908d1f8a454898797e"
}
