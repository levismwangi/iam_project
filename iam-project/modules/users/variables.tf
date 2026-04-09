variable "users" {
  description = "Map of users to create"
  type = map(object({
    display_name  = string
    first_name    = string
    last_name     = string
    department    = string
    job_title     = string
  }))
}

variable "temp_password" {
  description = "Temporary password for all new users"
  type        = string
  sensitive   = true # Marking as sensitive to avoid accidental exposure in logs or terraform apply
}

variable "tenant_domain" {
  description = "Primary tenant domain e.g. contoso.onmicrosoft.com"
  type        = string
}
