variable "resource_group_name" {
  description = "Name of the resource group"
  type        = string
}

variable "location" {
  description = "Azure region"
  type        = string
}

variable "resource_prefix" {
  description = "Prefix used in resource naming"
  type        = string
}

variable "alert_email" {
  description = "Email address for security alert notifications"
  type        = string
}

variable "log_retention_days" {
  description = "Log retention in days"
  type        = number
  default     = 30
}

variable "prt_high_risk_client_ids" {
  description = "Well-known first-party Entra client IDs treated as higher-risk when used non-interactively from an unbaselined device — see the PRT replay detection rule's threat model comment."
  type        = list(string)
  default = [
    "04b07795-8ddb-461a-bbee-02f9e1bf7b46", # Microsoft Azure CLI
    "1950a258-227b-4e31-a9cf-717495945fc2", # Microsoft Azure PowerShell
    "1b730954-1685-4b74-9bfd-dac224a7b894", # Azure Active Directory PowerShell (legacy)
  ]
}

variable "prt_composite_score_threshold" {
  description = "Minimum composite risk score required to trigger the PRT replay detection rule (see rule comment for scoring breakdown)."
  type        = number
  default     = 5
}
