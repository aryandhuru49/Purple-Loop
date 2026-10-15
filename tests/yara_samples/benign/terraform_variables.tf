# A variable named like a secret is not a secret: no value is stored here.
variable "admin_password" {
  description = "Set in terraform.tfvars (gitignored), never committed."
  type        = string
  sensitive   = true
}
