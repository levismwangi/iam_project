# foundation/main.tf
# ============================================================
# FOUNDATION — Prerequisites for the IAM project
#
# This root module runs ONCE before the main Terraform root.
# It creates resources that must exist before the main pipeline
# can deploy, specifically:
#
#   1. The IAM resource group
#   2. Microsoft Sentinel Contributor
#      — allows the Terraform SP to create Sentinel analytics rules
#
# Triggered by: .github/workflows/bootstrap.yml (manual only)
# State file  : foundation.terraform.tfstate (separate from main)
# ============================================================

locals {
  resource_prefix = "${var.company_name}-${var.environment}"
  iam_rg_name     = "rg-${local.resource_prefix}-iam"
}

# ── IAM Resource Group ────────────────────────────────────────────────────────
resource "azurerm_resource_group" "iam" {
  name     = local.iam_rg_name
  location = var.location

  tags = {
    environment = var.environment
    managed_by  = "terraform"
    project     = "iam-project"
    module      = "foundation"
  }
}


# ── Microsoft Sentinel Contributor ────────────────────────────────────────────
# Allows the Terraform SP to create and manage Sentinel analytics rules,
# alert rules, and other Sentinel resources in the IAM resource group.
resource "azurerm_role_assignment" "terraform_sp_sentinel_contributor" {
  scope                = azurerm_resource_group.iam.id
  role_definition_name = "Microsoft Sentinel Contributor"
  principal_id         = var.terraform_sp_object_id
}
