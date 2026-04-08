output "group_object_ids" {
  description = "Map of department name to group object ID"
  value       = { for k, g in azuread_group.dept : k => g.object_id }
}

output "privileged_users_group_id" {
  value = azuread_group.privileged_users.object_id
}

output "break_glass_group_id" {
  value = azuread_group.break_glass.object_id
}
