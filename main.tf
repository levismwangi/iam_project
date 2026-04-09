# ROOT main.tf — Wires all modules together

locals {
  resource_prefix = "${var.company_name}-${var.environment}"
}


# Resource Group (used by monitoring + PIM)
resource "azurerm_resource_group" "iam" {
  name     = "rg-${local.resource_prefix}-iam"
  location = var.location

  tags = {
    environment = var.environment
    managed_by  = "terraform"
    project     = "iam-project"
  }
}

# Module: Users
module "users" {
  source        = "./modules/users"
  users         = var.users
  tenant_domain = var.tenant_domain
  temp_password = data.azurerm_key_vault_secret.temp_password.value
}


# Module: Groups
module "groups" {
  source = "./modules/groups"

  departments  = var.departments
  users        = module.users.user_objects
  company_name = var.company_name
}

#Tenant is not licensed for Conditional Access, so this module is currently disabled. To enable, uncomment the module block below and ensure you have the appropriate licenses in place.
/*
# Module: Conditional Access
module "conditional_access" {
  source = "./modules/conditional_access"

  it_group_object_id   = module.groups.group_object_ids["IT"]
  break_glass_group_id = module.groups.break_glass_group_id
  environment          = var.environment
}
*/
# Module: App Registrations
module "app_registrations" {
  source = "./modules/app_registrations"

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


# Module: PIM
module "pim" {
  source = "./modules/pim"

  pim_eligible_assignments = var.pim_eligible_assignments
  user_objects             = module.users.user_objects
}

# Module: Monitoring
module "monitoring" {
  source = "./modules/monitoring"

  resource_group_name = azurerm_resource_group.iam.name
  location            = var.location
  resource_prefix     = local.resource_prefix
  alert_email         = var.alert_email
  log_retention_days  = var.log_retention_days
}

#Key Vault (used for storing temp password)
data "azurerm_key_vault" "this" {
  name                = "kv-iam-project"
  resource_group_name = "rg-terraform-state"
}

data "azurerm_key_vault_secret" "temp_password" {
  name         = "user-temp-password"
  key_vault_id = data.azurerm_key_vault.this.id
}