# Budget alert for the lab project.
#
# A GCP budget only SENDS ALERTS; it does not stop spending. The real cost
# controls are the nightly shutdown (schedule.tf), small machine types, and
# `terraform destroy` when you're done (docs/lab_runbook.md).

resource "google_monitoring_notification_channel" "budget_email" {
  display_name = "Purple Loop budget alerts"
  type         = "email"

  labels = {
    email_address = var.budget_alert_email
  }

  depends_on = [google_project_service.apis]
}

resource "google_billing_budget" "lab" {
  billing_account = var.billing_account_id
  display_name    = "Purple Loop lab"

  budget_filter {
    projects = ["projects/${data.google_project.lab.number}"]
  }

  amount {
    specified_amount {
      currency_code = var.budget_currency
      units         = tostring(var.monthly_budget)
    }
  }

  threshold_rules {
    threshold_percent = 0.5
  }
  threshold_rules {
    threshold_percent = 0.9
  }
  threshold_rules {
    threshold_percent = 1.0
  }
  # Warns before the money is spent, based on Google's month-end forecast.
  threshold_rules {
    threshold_percent = 1.0
    spend_basis       = "FORECASTED_SPEND"
  }

  all_updates_rule {
    monitoring_notification_channels = [google_monitoring_notification_channel.budget_email.id]
    # Billing account admins also get the default emails.
    disable_default_iam_recipients = false
  }

  depends_on = [google_project_service.apis]
}
