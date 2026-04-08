# modules/app_registrations/main.tf

# App Registrations
resource "azuread_application" "this" {
  for_each     = var.applications
  display_name = each.value.name

  # Sign Audience — single tenant only (most secure default)
  sign_in_audience = "AzureADMyOrg"

  web {
    redirect_uris = each.value.redirect_uris
    logout_url    = each.value.logout_url

    implicit_grant {
      # Disable implicit grant — use auth code + PKCE instead
      access_token_issuance_enabled = false
      id_token_issuance_enabled     = false
    }
  }

  # Request MS Graph User.Read scope
  required_resource_access {
    resource_app_id = "00000003-0000-0000-c000-000000000000" # Microsoft Graph

    resource_access {
      id   = "e1fe6dd8-ba31-4d61-89e7-88639da4683d" # User.Read (delegated)
      type = "Scope"
    }

    resource_access {
      id   = "37f7f235-527c-4136-accd-4a02d197296e" # openid (delegated)
      type = "Scope"
    }

    resource_access {
      id   = "14dad69e-099b-42c9-810b-d002981feec1" # profile (delegated)
      type = "Scope"
    }
  }

  tags = ["iam-project", "terraform-managed"]
}

# Service Principals — required to assign users/groups to apps
resource "azuread_service_principal" "this" {
  for_each  = azuread_application.this
  client_id = each.value.client_id

  # Require explicit assignment — users cannot self-assign
  app_role_assignment_required = true

  tags = ["iam-project", "terraform-managed"]
}


# Client Secret for each app (rotate every 12 months)
resource "time_rotating" "secret_rotation" {
  for_each      = var.applications
  rotation_days = 365
}

resource "azuread_application_password" "this" {
  for_each       = azuread_application.this
  application_id = each.value.id
  display_name   = "terraform-managed-secret"

  rotate_when_changed = {
    rotation = time_rotating.secret_rotation[each.key].id
  }
}

# Group → App Assignments (RBAC)
resource "azuread_app_role_assignment" "this" {
  for_each = var.app_group_assignments

  # Default app role (access granted)
  app_role_id         = "00000000-0000-0000-0000-000000000000"
  principal_object_id = var.group_ids[each.value.group_key]
  resource_object_id  = azuread_service_principal.this[each.value.app_key].object_id
}
