# foundation/main.tf
# ============================================================
# FOUNDATION — Prerequisites for the IAM project
#
# This root module runs ONCE before the main Terraform root.
# It creates resources that must exist before the main pipeline
# can deploy, specifically:
#
#   1. The IAM resource group
#   2. Role Based Access Control Administrator (constrained)
#      — allows the Terraform SP to assign Sentinel Responder
#        to the Logic App's managed identity
#   3. Microsoft Sentinel Contributor
#      — allows the Terraform SP to create Sentinel analytics rules
#
# Triggered by: .github/workflows/bootstrap.yml (manual only)
# State file  : foundation.terraform.tfstate (separate from main)
# ============================================================

locals {
  resource_prefix       = "${var.company_name}-${var.environment}"
  iam_rg_name           = "rg-${local.resource_prefix}-iam"
  sentinel_responder_id = "3e150937-b8fe-4cfb-8069-0eaf05ecd056"
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

# ── Role Based Access Control Administrator (constrained) ─────────────────────
# Allows the Terraform SP to assign Microsoft Sentinel Responder to the
# Logic App's managed identity. Constrained so it cannot assign any other
# role or assign to any other principal type.
resource "azurerm_role_assignment" "terraform_sp_rbac_admin" {
  scope                 = azurerm_resource_group.iam.id
  role_definition_name  = "Role Based Access Control Administrator"
  principal_id          = var.terraform_sp_object_id
  principal_type        = "ServicePrincipal"

  condition_version = "2.0"
  condition         = <<-CONDITION
    ((!(ActionMatches{'Microsoft.Authorization/roleAssignments/write'})) OR (@Request[Microsoft.Authorization/roleAssignments:RoleDefinitionId] ForAnyOfAnyValues:GuidEquals {${local.sentinel_responder_id}} AND @Request[Microsoft.Authorization/roleAssignments:PrincipalType] ForAnyOfAnyValues:StringEqualsIgnoreCase {'ServicePrincipal', 'ManagedIdentity'})) AND ((!(ActionMatches{'Microsoft.Authorization/roleAssignments/delete'})) OR (@Resource[Microsoft.Authorization/roleAssignments:RoleDefinitionId] ForAnyOfAnyValues:GuidEquals {${local.sentinel_responder_id}} AND @Resource[Microsoft.Authorization/roleAssignments:PrincipalType] ForAnyOfAnyValues:StringEqualsIgnoreCase {'ServicePrincipal', 'ManagedIdentity'}))
  CONDITION
}

# ── Microsoft Sentinel Contributor ────────────────────────────────────────────
# Allows the Terraform SP to create and manage Sentinel analytics rules,
# alert rules, and other Sentinel resources in the IAM resource group.
resource "azurerm_role_assignment" "terraform_sp_sentinel_contributor" {
  scope                 = azurerm_resource_group.iam.id
  role_definition_name  = "Microsoft Sentinel Contributor"
  principal_id          = var.terraform_sp_object_id
  principal_type        = "ServicePrincipal"
}
