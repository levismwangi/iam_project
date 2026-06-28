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
# Directory roles (Azure AD roles)
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


# Group eligibility (membership/ownership of Azure AD groups)
variable "pim_group_eligible_assigments" {
  description = "Map of PIM eligible group membership/ownership assigments"
  type = map(object({
    group_key       = string # key into module.groups.group_object_ids, e.g. "IT"
    principal_key   = string # key into module.users.user_objects, e.g. "bob_otieno"
    assignment_type = string # "member" or "owner"
    justification   = string
  }))
  default = {
    bob_it_member = {
      group_key       = "IT"
      principal_key   = "bob_otieno"
      assignment_type = "member"
      justification   = "Systems engineer requires JIT membership in IT group for elevated troubleshooting tasks"
    }
    eve_it_owner = {
      group_key       = "IT"
      principal_key   = "eve_wanjiku"
      assignment_type = "owner"
      justification   = "Security engineer requires JIT ownership to manage IT group membership during incident response"
    }
  }
}

# Group activation policy (controls how eligibility above gets activated)
variable "pim_group_activation_policies" {
  description = "Map of group_key => activation policy for that group's PIM-eligible roles"
  type = map(object({
    role_id                            = string # "member" or "owner"
    maximum_duration                   = string # ISO8601, e.g. "PT8H"
    require_approval                   = bool
    require_justification              = optional(bool, true)
    require_multifactor_authentication = optional(bool, true)
    approver_group_key                 = optional(string) # key into module.groups outputs; required if require_approval = true
  }))
  default = {
    IT = {
      role_id                            = "member"
      maximum_duration                   = "PT8H"
      require_approval                   = false # TODO: revisit once an approver group is decided on
      require_justification              = true
      require_multifactor_authentication = true
    }
  }
}


# Azure RBAC role eligibility (subscription/resource-group scoped roles)
# role_definition_id below is built in root main.tf via a local, since it 
# depends on var.subscription_id (a variable default cannot reference another variable).
variable "pim_rbac_eligible_assignments" {
  description = "Map of PIM eligible Azure RBAC role assignments"
  type = map(object({
    scope              = string
    role_definition_id = string
    principal_key      = string # key into module.users.user_objects
    duration_hours     = optional(number)
    justification      = string
    ticket_number      = optional(string)
    ticket_system      = optional(string)
  }))
  default = {} # populated via root main.tf using locals 
}

# PIM - Azure RBAC activation policy (controls how eligibility above gets activated)
variable "pim_rbac_activation_policies" {
  description = "Map of policy_key => activation policy for an Azure RBAC role at a given scope"
  type = map(object({
    scope                              = string
    role_definition_id                 = string
    maximum_duration                   = string # ISO8601, e.g. "PT8H"
    require_approval                   = bool
    require_justification              = optional(bool, true)
    require_multifactor_authentication = optional(bool, true)
    approver_group_key                 = optional(string)
    active_assignment_expire_after     = optional(string, "P365D") # ISO8601, e.g. "P365D" for 1 year
  }))
  default = {} # populated via root main.tf using locals
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

# Bootstrap / Key Vault
variable "key_vault_name" {
  description = "Name of the Key Vault used to store the temporary user password"
  type        = string
}

variable "bootstrap_resource_group_name" {
  description = "Name of the resource group containing the Key Vault and Terraform state storage"
  type        = string
  default     = "rg-terraform-state"
}
