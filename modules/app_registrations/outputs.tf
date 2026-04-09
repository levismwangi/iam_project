output "app_client_ids" {
  description = "Map of app key to client ID"
  value       = { for k, a in azuread_application.this : k => a.client_id }
}

output "app_object_ids" {
  description = "Map of app key to object ID"
  value       = { for k, a in azuread_application.this : k => a.object_id }
}

output "service_principal_ids" {
  description = "Map of app key to service principal object ID"
  value       = { for k, sp in azuread_service_principal.this : k => sp.object_id }
}

output "app_secrets" {
  description = "Map of app key to client secret value — treat as sensitive"
  value       = { for k, s in azuread_application_password.this : k => s.value }
  sensitive   = true
}
