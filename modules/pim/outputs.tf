# modules/pim/outputs.tf

output "directory_role_eligibility_ids" {
  description = "Map of assigment_key => directory role eligibility request ID"
  value       = { for k, r in azuread_directory_role_eligibility_schedule_request.this : k => r.id }
}

output "group_eligibility_ids" {
  description = "Map of assignment_key => group eligibility schedule ID"
  value       = { for k, r in azuread_privileged_access_group_eligibility_schedule.this : k => r.id }
}

output "rbac_eligibility_ids" {
  description = "Map of assignment_key => Azure RBAC eligible role assignment ID"
  value       = { for k, r in azurerm_pim_eligible_role_assignment.this : k => r.id }
}
