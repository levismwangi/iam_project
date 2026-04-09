# ROOT outputs.tf — Defines outputs for the entire project

output "user_object_ids" {
  description = "Object IDs of all created users"
  value       = module.users.user_object_ids
  sensitive   = false
}

output "user_principal_names" {
  description = "UPNs of all created users"
  value       = module.users.user_principal_names
}

output "group_object_ids" {
  description = "Object IDs of all department groups"
  value       = module.groups.group_object_ids
}

output "app_client_ids" {
  description = "Client IDs of all registered applications"
  value       = module.app_registrations.app_client_ids
}

output "app_object_ids" {
  description = "Object IDs of all registered applications"
  value       = module.app_registrations.app_object_ids
}

/*
output "conditional_access_policy_ids" {
  description = "IDs of all Conditional Access policies"
  value       = module.conditional_access.policy_ids
}
*/
output "log_analytics_workspace_id" {
  description = "Resource ID of the Log Analytics workspace"
  value       = module.monitoring.log_analytics_workspace_id
}

output "resource_group_name" {
  description = "Name of the IAM resource group"
  value       = azurerm_resource_group.iam.name
}
