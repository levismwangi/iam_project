
# modules/groups/main.tf

# One security group per department
resource "azuread_group" "dept" {
  for_each = toset(var.departments)

  display_name       = "grp-${lower(var.company_name)}-${lower(each.key)}"
  description        = "Security group for ${each.key} department"
  security_enabled   = true
  mail_enabled       = false
  assignable_to_role = false

  # Dynamically assign users whose department matches this group
  members = [
    for user_key, user in var.users :
    user.object_id
    if user.department == each.key
  ]
}

# Privileged users group — excluded from some CA policies
resource "azuread_group" "privileged_users" {
  display_name     = "grp-${lower(var.company_name)}-privileged-users"
  description      = "Users with privileged roles — managed via PIM"
  security_enabled = true
  mail_enabled     = false
}

# Break-glass / emergency access group — excluded from MFA CA
resource "azuread_group" "break_glass" {
  display_name     = "grp-${lower(var.company_name)}-break-glass"
  description      = "Emergency break-glass accounts — excluded from Conditional Access"
  security_enabled = true
  mail_enabled     = false
}

terraform {
  required_version = ">= 1.6.0"
  required_providers {
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 2.47"
    }
  }
}
