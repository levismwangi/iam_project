#Tenant is not licensed for Conditional Access, so this module is currently disabled. To enable, uncomment the module block below and ensure you have the appropriate licenses in place.
# modules/conditional_access/main.tf
/*
locals {
  # Well-known role template IDs
  global_admin_role_id   = "62e90394-69f5-4237-9190-012177145e10"
  security_admin_role_id = "194ae4cb-b126-40b2-bd5b-6091b380977d"
  user_admin_role_id     = "fe930be7-5e62-47db-91af-98c3a49a38b1"
  privileged_auth_admin  = "7be44c8a-adaf-4e2a-84d6-ab2649e08a13"

  # In prod we enforce; in dev we audit first
  enforcement_state = var.environment == "prod" ? "enabled" : "enabledForReportingButNotEnforced"
}

# CA001 — Block Legacy Authentication
# Rationale: Legacy auth bypasses MFA — must be blocked unconditionally
resource "azuread_conditional_access_policy" "block_legacy_auth" {
  display_name = "CA001-Block-Legacy-Authentication"
  state        = "enabled" # Always enforced regardless of environment

  conditions {
    client_app_types = ["exchangeActiveSync", "other"]

    users {
      included_users  = ["All"]
      excluded_groups = var.break_glass_group_id != null ? [var.break_glass_group_id] : []
    }

    applications {
      included_applications = ["All"]
    }

    locations {
      included_locations = ["All"]
    }
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["block"]
  }
}

# CA002 — Require MFA for Admin Roles
# Rationale: Admins are high-value targets — always require MFA
resource "azuread_conditional_access_policy" "require_mfa_admins" {
  display_name = "CA002-Require-MFA-Admin-Roles"
  state        = "enabled"

  conditions {
    client_app_types = ["all"]

    users {
      included_roles  = [
        local.global_admin_role_id,
        local.security_admin_role_id,
        local.user_admin_role_id,
        local.privileged_auth_admin,
      ]
      excluded_groups = var.break_glass_group_id != null ? [var.break_glass_group_id] : []
    }

    applications {
      included_applications = ["All"]
    }

    locations {
      included_locations = ["All"]
    }
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["mfa"]
  }
}

# CA003 — Require MFA for All Users
# Rationale: Zero-trust baseline — every user must prove identity
resource "azuread_conditional_access_policy" "require_mfa_all_users" {
  display_name = "CA003-Require-MFA-All-Users"
  state        = local.enforcement_state

  conditions {
    client_app_types = ["all"]

    users {
      included_users  = ["All"]
      excluded_groups = var.break_glass_group_id != null ? [
      var.break_glass_group_id,
      var.it_group_object_id
    ]   :   [var.it_group_object_id]
    }

    applications {
      included_applications = ["All"]
    }

    locations {
      included_locations = ["All"]
    }
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["mfa"]
  }
}


# CA004 — Block Sign-ins from Risky Locations
# Rationale: Reduce attack surface by restricting non-trusted locations
resource "azuread_conditional_access_policy" "block_risky_locations" {
  display_name = "CA004-Block-Risky-Sign-in-Locations"
  state        = local.enforcement_state

  conditions {
    client_app_types    = ["all"]
    sign_in_risk_levels = ["high", "medium"]

    users {
      included_users  = ["All"]
      excluded_groups = var.break_glass_group_id != null ? [var.break_glass_group_id] : []
    }

    applications {
      included_applications = ["All"]
    }

    locations {
      included_locations = ["All"]
      excluded_locations = ["AllTrusted"]
    }
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["block"]
  }
}

# CA005 — Require MFA for Risky Sign-ins (low risk)
# Rationale: Step-up auth for low-risk sign-ins rather than hard blocking
resource "azuread_conditional_access_policy" "mfa_risky_signin" {
  display_name = "CA005-Require-MFA-Risky-Sign-in"
  state        = local.enforcement_state

  conditions {
    client_app_types    = ["all"]
    sign_in_risk_levels = ["low"]

    users {
      included_users  = ["All"]
      excluded_groups = var.break_glass_group_id != null ? [var.break_glass_group_id] : []
    }

    applications {
      included_applications = ["All"]
    }

    locations {
      included_locations = ["All"]
    }
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["mfa"]
  }
}


# CA006 — Require Password Change for High User Risk
# Rationale: Compromised credentials should trigger immediate remediation
resource "azuread_conditional_access_policy" "require_password_change_high_user_risk" {
  display_name = "CA006-Require-Password-Change-High-User-Risk"
  state        = local.enforcement_state

  conditions {
    client_app_types = ["all"]
    user_risk_levels = ["high"]

    users {
      included_users  = ["All"]
      excluded_groups = var.break_glass_group_id != null ? [var.break_glass_group_id] : []
    }

    applications {
      included_applications = ["All"]
    }

    locations {
      included_locations = ["All"]
    }
  }

  grant_controls {
    operator          = "AND"
    built_in_controls = ["mfa", "passwordChange"]
  }
}


# CA007 — Block Access for Unknown / Unsupported Device Platforms
# Rationale: Only known OS platforms should access corporate resources
resource "azuread_conditional_access_policy" "block_unknown_platforms" {
  display_name = "CA007-Block-Unknown-Device-Platforms"
  state        = local.enforcement_state

  conditions {
    client_app_types = ["all"]

    platforms {
      included_platforms = ["all"]
      excluded_platforms = ["android", "iOS", "windows", "macOS", "linux"]
    }

    users {
      included_users  = ["All"]
      excluded_groups = var.break_glass_group_id != null ? [var.break_glass_group_id] : []
    }

    applications {
      included_applications = ["All"]
    }

    locations {
      included_locations = ["All"]
    }
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["block"]
  }
}
*/
terraform {
  required_version = ">= 1.6.0"
}
