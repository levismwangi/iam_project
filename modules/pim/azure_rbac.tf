# modules/pim/azure_rbac.tf
#
# PIM for Azure Resource (RBAC) roles - eligibility AND activation policy.
# Uses the azurerm provider, not azuread, since RBAC roles are an Azure
# Resource Manager concept, separate from Entra ID directory roles/groups.
# 
# `scope` is supplied per-assignment (not hardcoded to subscription or RG),
# so this works whether you target subscriptions, resource groups, or a mix.

/*

resource "azurerm_pim_eligible_role_assignment" "this" {
    for_each = var.rbac_eligible_assignments

    scope = each.value.scope
    role_definition_id = each.value.role_definition_id
    principal_id = var.user_objects[each.value.principal_key].object_id

    justification = each.value.justification

    dynamic "schedule" {
        for_each = each.value.duration_hours != null ? [1] : []
        content {
            expiration {
                duration_hours = each.value.duration_hours
            }
        }
    }

    dynamic "ticket" {
        for_each = each.value.ticket_number != null ? [1] : []
        content {
            number = each.value.ticket_number
            system = each.value.ticket_system
        }
    }
}

resource azurerm_role_management_policy "this" {
    for_each = var.rbac_activation_policies

    scope = each.value.scope
    role_definition_id = each.value.role_definition_id

    active_assignment_rules {
        expire_after = each.value.active_assignment_expire_after
    } 

    eligible_assignment_rules {
        expiration_required = false
    }

    activation_rules {
        maximum_duration = each.value.maximum_duration
        require_approval = each.value.require_approval
        require_justification = each.value.require_justification
        require_multifactor_authentication = each.value.require_multifactor_authentication

        dynamic "approval_stage" {
            for_each = each.value.require_approval ? [1] : []
            content {
                primary_approver {
                    object_id = var.group_objects[each.value.approver_group_key].object_id
                    type = "Group"
                }
            }
    
        }
    }
}


*/