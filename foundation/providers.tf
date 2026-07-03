# foundation/providers.tf

terraform {
  required_version = ">= 1.6.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.90"
    }
  }

  # Separate state file from the main root module —
  # foundation state must never be mixed with main state
  # since they have different lifecycles.
  backend "azurerm" {
    resource_group_name  = "rg-terraform-state"
    storage_account_name = "tfstateiam"
    container_name       = "tfstate"
    key                  = "foundation.terraform.tfstate"
  }
}

provider "azurerm" {
  features {}
  subscription_id = var.subscription_id
  use_oidc        = true
}
