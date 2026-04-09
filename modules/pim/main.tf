/// PIM requires M365 E5 or E3 with PIM add-on licenses for users to be eligible for role assignments.

# modules/pim/main.tf
# Privileged Identity Management — Just-In-Time eligible role assignments


# Look up available directory role definitions
data "azuread_directory_role_templates" "all" {}

locals {
  # Build a lookup: role display name -> template ID
  role_template_map = {
    for t in data.azuread_directory_role_templates.all.role_templates :
    t.display_name => t.object_id
  }
}

# Activate the directory roles so we can assign them
resource "azuread_directory_role" "pim_roles" {
  for_each     = toset([for v in var.pim_eligible_assignments : v.role_display_name])
  display_name = each.key
}


/*
# PIM Eligible Role Assignments
# Users get the role assigned as ELIGIBLE — they must activate it on-demand
# via the Azure Portal or Graph API with justification
resource "azuread_directory_role_eligibility_schedule_request" "this" {
  for_each = var.pim_eligible_assignments

  role_definition_id = azuread_directory_role.pim_roles[each.value.role_display_name].template_id
  principal_id       = var.user_objects[each.value.user_key].object_id
  directory_scope_id = "/"
  justification      = each.value.justification
}

# NOTE: PIM role management policies (activation rules, approval workflows,
# notification settings) are not yet fully exposed by the azuread Terraform
# provider. These settings must be configured manually in the Azure Portal
# under Entra ID → Roles and administrators → <Role> → Settings, or via
# the Microsoft Graph API directly.
#
# Settings to configure manually per role:
#   - Maximum activation duration: 8 hours
#   - Require MFA on activation: Yes
#   - Require justification on activation: Yes
#   - Require approval: Yes (set bob.otieno as approver)
#   - Send notifications on activation: Yes


*/
