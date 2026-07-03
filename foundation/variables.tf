# foundation/variables.tf

variable "subscription_id" {
  description = "Azure Subscription ID"
  type        = string
}

variable "tenant_id" {
  description = "Azure AD Tenant ID"
  type        = string
}

variable "company_name" {
  description = "Company name used in resource naming"
  type        = string
  default     = "contoso"
}

variable "environment" {
  description = "Deployment environment (dev or prod)"
  type        = string
  default     = "dev"
}

variable "location" {
  description = "Azure region for resources"
  type        = string
  default     = "southafricanorth"
}

variable "terraform_sp_object_id" {
  description = "Object ID of the Terraform Service Principal (not the client/app ID — the SP object ID)"
  type        = string
}
