# foundation/outputs.tf

output "iam_resource_group_name" {
  description = "Name of the IAM resource group"
  value       = azurerm_resource_group.iam.name
}

output "iam_resource_group_id" {
  description = "Resource ID of the IAM resource group"
  value       = azurerm_resource_group.iam.id
}

output "iam_resource_group_location" {
  description = "Location of the IAM resource group"
  value       = azurerm_resource_group.iam.location
}
