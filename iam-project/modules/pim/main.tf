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


# PIM Role Management Policy — enforce approval + justification on activation
# NOTE: azuread provider supports policy updates via azuread_directory_role_management_policy
resource "azuread_directory_role_management_policy" "this" {
  for_each = toset([for v in var.pim_eligible_assignments : v.role_display_name])

  role_id    = azuread_directory_role.pim_roles[each.key].object_id
  scope_id   = "/"
  scope_type = "DirectoryRole"

  active_assignment_rules {
    require_multifactor_authentication = true
    require_justification              = true
    expiration_required                = true
    expire_after                       = "P3M" # 3 months max active assignment
  }

  eligible_assignment_rules {
    expiration_required = true
    expire_after        = "P3M"
  }

  activation_rules {
    maximum_duration                   = "PT8H" # Max 8 hours per activation
    require_multifactor_authentication = true
    require_justification              = true

    # Require approval for Global Admin activations
    approval_stage {
      primary_approver {
        object_id = var.user_objects["bob_otieno"].object_id # IT approver
        type      = "singleUser"
      }
    }
  }

  notification_rules {
    eligible_assignments {
      admin_notifications {
        notification_level    = "All"
        default_recipients    = true
        additional_recipients = []
      }
    }

    active_assignments {
      admin_notifications {
        notification_level    = "All"
        default_recipients    = true
        additional_recipients = []
      }
    }

    eligible_activations {
      admin_notifications {
        notification_level    = "All"
        default_recipients    = true
        additional_recipients = []
      }
    }
  }
}
