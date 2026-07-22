# ROOT main.tf — Wires all modules together
#
# The IAM resource group is created by foundation/ and referenced
# here via a data source. Run bootstrap.yml before the first apply.

locals {
  resource_prefix = "${var.company_name}-${var.environment}"
}

# ── IAM Resource Group (managed by foundation/) ───────────────────────────────
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

# ── Module: Monitoring ────────────────────────────────────────────────────────
module "monitoring" {
  source              = "./modules/monitoring"
  resource_group_name = data.azurerm_resource_group.iam.name
  location            = var.location
  resource_prefix     = local.resource_prefix
  alert_email         = var.alert_email
  log_retention_days  = var.log_retention_days
  tenant_id           = var.tenant_id
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
