output "user_object_ids" {
  description = "Map of user key to object ID"
  value       = { for k, u in azuread_user.this : k => u.object_id }
}

output "user_principal_names" {
  description = "Map of user key to UPN"
  value       = { for k, u in azuread_user.this : k => u.user_principal_name }
}

# Full user objects — used by groups and PIM modules
output "user_objects" {
  description = "Full azuread_user objects"
  value       = azuread_user.this
}
