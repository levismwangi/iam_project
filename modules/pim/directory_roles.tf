# modules/pim/directory_roles.tf
#
# PIM for Entra ID Directory Roles — eligibility only.
#
# NOTE: Activation policy (maximum activation duration, require_approval,
# require_multifactor_authentication, notifications) is NOT exposed by the
# azuread provider for directory roles — there is no
# azuread_directory_role_management_policy resource as of v3.8.0.
#
# Configure activation policy manually per role:
#   Entra ID portal → Roles and administrators → <Role> → Settings
# or via direct Microsoft Graph API calls (roleManagementPolicies).

# Activate each distinct directory role referenced below (de-duplicated —
# activating a role is a one-time, tenant-wide action, not per-assignment).


/*
resource "azuread_directory_role" "this" {
    for_each = toset([
        for v in var.directory_role_eligible_assignments : v.role_display_name
    ])
    display_name = each.key
}

# Grant eligibility-one request per entry in the input map.
resource "azuread_directory_role_eligibility_schedule_request" "this" {
    for_each = var.directory_role_eligible_assignments

    role_definition_id = azuread_directory_role.this[each.value.role_display_name].template_id
    principal_id        = var.user_objects[each.value.user_key].object_id
    directory_scope_id  = "/" # tenant-wide; directory roles do not support sub-scoping
    justification       = each.value.justification
}

*/