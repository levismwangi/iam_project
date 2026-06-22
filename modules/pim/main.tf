# modules/pim/main.tf

terraform {
  required_version = ">= 1.6.0"
  required_providers {
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 2.47" # matches root providers.tf — do not diverge across modules
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.90" # matches root providers.tf — do not diverge across modules
    }
  }
}
