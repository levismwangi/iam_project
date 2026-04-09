variable "tenant_id" {
  description = "Azure AD Tenant ID"
  type        = string
}

variable "subscription_id" {
  description = "Azure Subscription ID"
  type        = string
}

variable "location" {
  description = "Azure region for resources"
  type        = string
  default     = "southafricanorth"
}

variable "environment" {
  description = "Deployment environment (dev or prod)"
  type        = string
  default     = "dev"
}

variable "company_name" {
  description = "Company name used in resource naming"
  type        = string
  default     = "contoso"
}

variable "tenant_domain" {
  description = "Primary domain of the tenant e.g. contoso.onmicrosoft.com"
  type        = string
}

# Users
variable "users" {
  description = "Map of users to create"
  type = map(object({
    display_name = string
    first_name   = string
    last_name    = string
    department   = string
    job_title    = string
  }))
  default = {
    alice_kamau = {
      display_name = "Alice Kamau"
      first_name   = "Alice"
      last_name    = "Kamau"
      department   = "Finance"
      job_title    = "Financial Analyst"
    }
    bob_otieno = {
      display_name = "Bob Otieno"
      first_name   = "Bob"
      last_name    = "Otieno"
      department   = "IT"
      job_title    = "Systems Engineer"
    }
    carol_mwangi = {
      display_name = "Carol Mwangi"
      first_name   = "Carol"
      last_name    = "Mwangi"
      department   = "HR"
      job_title    = "HR Manager"
    }
    david_njoroge = {
      display_name = "David Njoroge"
      first_name   = "David"
      last_name    = "Njoroge"
      department   = "Sales"
      job_title    = "Sales Executive"
    }
    eve_wanjiku = {
      display_name = "Eve Wanjiku"
      first_name   = "Eve"
      last_name    = "Wanjiku"
      department   = "IT"
      job_title    = "Security Engineer"
    }
  }
}

# Departments / Groups
variable "departments" {
  description = "List of departments to create groups for"
  type        = list(string)
  default     = ["IT", "HR", "Finance", "Sales"]
}

# Applications
variable "applications" {
  description = "Map of applications to register"
  type = map(object({
    name          = string
    redirect_uris = list(string)
    logout_url    = string
  }))
  default = {
    hr_portal = {
      name          = "HR Portal"
      redirect_uris = ["https://hrportal.contoso.com/auth/callback"]
      logout_url    = "https://hrportal.contoso.com/logout"
    }
    finance_app = {
      name          = "Finance App"
      redirect_uris = ["https://financeapp.contoso.com/auth/callback"]
      logout_url    = "https://financeapp.contoso.com/logout"
    }
    sales_crm = {
      name          = "Sales CRM"
      redirect_uris = ["https://salescrm.contoso.com/auth/callback"]
      logout_url    = "https://salescrm.contoso.com/logout"
    }
  }
}

# PIM
variable "pim_eligible_assignments" {
  description = "Map of PIM eligible role assignments"
  type = map(object({
    user_key          = string
    role_display_name = string
    justification     = string
    duration_months   = number
  }))
  default = {
    bob_global_reader = {
      user_key          = "bob_otieno"
      role_display_name = "Global Reader"
      justification     = "IT engineer requires read access for troubleshooting"
      duration_months   = 3
    }
    eve_security_admin = {
      user_key          = "eve_wanjiku"
      role_display_name = "Security Administrator"
      justification     = "Security engineer requires admin role for incident response"
      duration_months   = 3
    }
  }
}


# Monitoring
variable "alert_email" {
  description = "Email address for security alert notifications"
  type        = string
  default     = "security@contoso.com"
}

variable "log_retention_days" {
  description = "Number of days to retain logs in Log Analytics"
  type        = number
  default     = 30
}
