variable "users" {
  description = "Map of users to create"
  type = map(object({
    display_name  = string
    first_name    = string
    last_name     = string
    department    = string
    job_title     = string
    temp_password = string
  }))
}

variable "tenant_domain" {
  description = "Primary tenant domain e.g. contoso.onmicrosoft.com"
  type        = string
}
