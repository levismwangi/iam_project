# ROOT main.tf — Wires all modules together
#
# NOTE: The IAM resource group is created by the foundation/ module,
# not here. It is referenced via a data source below. Run the
# bootstrap pipeline (bootstrap.yml) before the first apply.

locals {
  resource_prefix = "${var.company_name}-${var.environment}"
}

# ── IAM Resource Group (managed by foundation/) ───────────────────────────────
# Created by foundation/main.tf. The bootstrap pipeline must run
# before this root module to ensure the resource group exists.
data "azurerm_resource_group" "iam" {
  name = "rg-${local.resource_prefix}-iam"
}

# ── Module: Users ─────────────────────────────────────────────────────────────
module "users" {
  source        = "./modules/users"
  users         = var.users
  tenant_domain = var.tenant_domain
  temp_password = data.azurerm_key_vault_secret.temp_password.value
}

# ── Module: Groups ────────────────────────────────────────────────────────────
module "groups" {
  source       = "./modules/groups"
  departments  = var.departments
  users        = module.users.user_objects
  company_name = var.company_name
}

# Tenant is not licensed for Conditional Access — module disabled.
# Uncomment once Entra ID P2 license is available.
/*
module "conditional_access" {
  source               = "./modules/conditional_access"
  it_group_object_id   = module.groups.group_object_ids["IT"]
  break_glass_group_id = module.groups.break_glass_group_id
  environment          = var.environment
}
*/

# ── Module: App Registrations ─────────────────────────────────────────────────
module "app_registrations" {
  source       = "./modules/app_registrations"
  applications = var.applications
  group_ids    = module.groups.group_object_ids

  app_group_assignments = {
    hr_portal_hr = {
      app_key   = "hr_portal"
      group_key = "HR"
    }
    finance_app_finance = {
      app_key   = "finance_app"
      group_key = "Finance"
    }
    sales_crm_sales = {
      app_key   = "sales_crm"
      group_key = "Sales"
    }
  }
}

# ── PIM locals ────────────────────────────────────────────────────────────────
data "azurerm_role_definition" "reader" {
  name = "Reader"
}

data "azurerm_subscription" "primary" {}

locals {
  reader_role_definition_id = "${data.azurerm_subscription.primary.id}${data.azurerm_role_definition.reader.id}"

  pim_rbac_eligible_assignments = {
    bob_subscription_reader = {
      scope              = data.azurerm_subscription.primary.id
      role_definition_id = local.reader_role_definition_id
      principal_key      = "bob_otieno"
      duration_hours     = 8
      justification      = "IT engineer requires temporary Reader access at the subscription level for troubleshooting"
    }
  }
}

# PIM module — disabled until Entra ID P2 license is available.
/*
module "pim" {
  source        = "./modules/pim"
  user_objects  = module.users.user_objects
  group_objects = module.groups.group_object_ids
  directory_role_eligible_assignments = var.pim_eligible_assignments
}
*/

# ── Module: Monitoring ────────────────────────────────────────────────────────
module "monitoring" {
  source              = "./modules/monitoring"
  resource_group_name = data.azurerm_resource_group.iam.name
  location            = var.location
  resource_prefix     = local.resource_prefix
  alert_email         = var.alert_email
  log_retention_days  = var.log_retention_days
}

# ── Key Vault (temp password) ─────────────────────────────────────────────────
data "azurerm_key_vault" "this" {
  name                = "kv-iam-project"
  resource_group_name = "rg-terraform-state"
}

data "azurerm_key_vault_secret" "temp_password" {
  name         = "user-temp-password"
  key_vault_id = data.azurerm_key_vault.this.id
}
