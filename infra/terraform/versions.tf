# Tool and provider versions.
# Terraform 1.11+ is required for write-only arguments and ephemeral resources,
# which keep the lab passwords out of the plan and state files (see secrets.tf).
terraform {
  required_version = ">= 1.15"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 8.7"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.9"
    }
  }

  # State stays local (and gitignored). For a single-person throwaway lab a
  # remote backend adds setup without much benefit; see docs/lab_runbook.md.
}
