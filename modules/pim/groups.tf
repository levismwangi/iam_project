# modules/pim/groups.tf
#
# PIM for Azure AD Groups — eligibility (membership/ownership) AND
# activation policy. Unlike directory roles, the azuread provider DOES
# expose activation policy here via azuread_group_role_management_policy.
#
# CAUTION: azuread_privileged_access_group_eligibility_schedule has several
# open upstream issues (RoleAssignmentExists on update, drift on
# expiration_date) as of provider v3.x. Prefer creating new assignments over
# editing existing ones; test changes in a non-prod tenant first.
# See: github.com/hashicorp/terraform-provider-azuread issues #1306, #1412,
# #1431, #1613.


resource "azuread_privileged_access_group_eligibility_schedule" "this" {
    for_each = var.group_eligible_assignments

    group_id        = var.group_objects[each.value.group_key].object_id
    principal_id    = var.user_objects[each.value.principal_key].object_id
    assignment_type = each.value.assignment_type # "member" or "owner"
    justification   = each.value.justification

    #Eligibility itself does not expire unless you add  expiration_date / permanent_assignment handling here -
    # left out for now since none of your current entries need it.connection {
    # Add when/if required:
    # permanent_assignment - true
    # expiration_date = "2027-01-01T00:00:00Z"
}

# Activation policy - controls what happens when an eligible user actually activates membership/ownership of the group.
# These policy objects are created automatically by Entra ID per group/role_id
# combination, so this resource updates an existing policy rather than
# creating a new one from scratch - auto-imports on first apply per provider docs.

resource "azuread_group_role_management_policy" "this" {
    for_each = var.group_activation_policies

    group_id = var.group_objects[each.key].object_id
    role_id  = each.value.role_id # "member" or "owner"

    active_assignment_rules {
        expire_after = "P365D"
    }

    eligible_assignment_rules {
        expiration_required = false
    }

    activation_rules {
        maximum_duration                    = each.value.maximum_duration
        require_approval                    = each.value.require_approval
        require_justification               = each.value.require_justification
        require_multifactor_authentication  = each.value.require_multifactor_authentication

        dynamic "approval_stage" {
            for_each = each.value.require_approval ? [1] : []
            content {
                primary_approver {
                    object_id = var.group_objects[each.value.approver_group_key].object_id
                    type      = "Group"
                }
            }
        }
    }
}
