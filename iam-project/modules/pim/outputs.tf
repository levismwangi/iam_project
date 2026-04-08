output "eligible_assignment_ids" {
  description = "Map of assignment key to schedule request ID"
  value = {
    for k, v in azuread_directory_role_eligibility_schedule_request.this :
    k => v.id
  }
}

output "activated_role_ids" {
  description = "Directory role object IDs activated for PIM"
  value = {
    for k, r in azuread_directory_role.pim_roles :
    k => r.object_id
  }
}
