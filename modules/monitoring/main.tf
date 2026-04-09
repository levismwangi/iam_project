# modules/monitoring/main.tf
# Log Analytics + Sentinel + Alert Rules for IAM threat detection

# Log Analytics Workspace
resource "azurerm_log_analytics_workspace" "this" {
  name                = "law-${var.resource_prefix}-iam"
  location            = var.location
  resource_group_name = var.resource_group_name
  sku                 = "PerGB2018"
  retention_in_days   = var.log_retention_days

  tags = {
    managed_by = "terraform"
    project    = "iam-project"
  }
}


# Microsoft Sentinel — enabled on top of Log Analytics
resource "azurerm_sentinel_log_analytics_workspace_onboarding" "this" {
  workspace_id = azurerm_log_analytics_workspace.this.id
}


# Entra ID Diagnostic Settings → Log Analytics
# Streams audit logs and sign-in logs into the workspace
resource "azurerm_monitor_aad_diagnostic_setting" "this" {
  name                       = "diag-${var.resource_prefix}-entra-to-law"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.this.id

  enabled_log {
    category = "AuditLogs"
    retention_policy {
      enabled = false
      days    = 0
    }
  }

  enabled_log {
    category = "SignInLogs"
    retention_policy {
      enabled = false
      days    = 0
    }
  }

  enabled_log {
    category = "NonInteractiveUserSignInLogs"
    retention_policy {
      enabled = false
      days    = 0
    }
  }

  enabled_log {
    category = "ServicePrincipalSignInLogs"
    retention_policy {
      enabled = false
      days    = 0
    }
  }

  enabled_log {
    category = "ManagedIdentitySignInLogs"
    retention_policy {
      enabled = false
      days    = 0
    }
  }

  enabled_log {
    category = "RiskyUsers"
    retention_policy {
      enabled = false
      days    = 0
    }
  }

  enabled_log {
    category = "UserRiskEvents"
    retention_policy {
      enabled = false
      days    = 0
    }
  }
}


# Action Group — where alerts get sent
resource "azurerm_monitor_action_group" "iam_security" {
  name                = "ag-${var.resource_prefix}-iam-security"
  resource_group_name = var.resource_group_name
  short_name          = "iamsec"

  email_receiver {
    name                    = "security-team"
    email_address           = var.alert_email
    use_common_alert_schema = true
  }

  tags = {
    managed_by = "terraform"
    project    = "iam-project"
  }
}


# ALERT 1 — New Admin Role Assignment
# Detects: Someone granted a privileged role
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "new_admin_role" {
  name                = "alert-${var.resource_prefix}-new-admin-role-assignment"
  location            = var.location
  resource_group_name = var.resource_group_name
  description         = "Fires when a user is added to a privileged directory role"
  severity            = 2
  enabled             = true

  evaluation_frequency = "PT5M"
  window_duration      = "PT5M"

  scopes = [azurerm_log_analytics_workspace.this.id]

  criteria {
    query = <<-KQL
      AuditLogs
      | where OperationName in ("Add member to role", "Add eligible member to role")
      | where Result == "success"
      | extend InitiatedBy = tostring(InitiatedBy.user.userPrincipalName)
      | extend TargetUser  = tostring(TargetResources[0].userPrincipalName)
      | extend RoleName    = tostring(TargetResources[1].displayName)
      | project TimeGenerated, InitiatedBy, TargetUser, RoleName, OperationName
    KQL

    time_aggregation_method = "Count"
    threshold               = 0
    operator                = "GreaterThan"

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  action {
    action_groups = [azurerm_monitor_action_group.iam_security.id]
  }

  tags = {
    managed_by = "terraform"
    alert_type = "identity"
  }
}

# ALERT 2 — Bulk User Deletion
# Detects: Multiple users deleted in a short window — potential insider threat
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "bulk_user_deletion" {
  name                = "alert-${var.resource_prefix}-bulk-user-deletion"
  location            = var.location
  resource_group_name = var.resource_group_name
  description         = "Fires when 3 or more users are deleted within 5 minutes"
  severity            = 1
  enabled             = true

  evaluation_frequency = "PT5M"
  window_duration      = "PT5M"

  scopes = [azurerm_log_analytics_workspace.this.id]

  criteria {
    query = <<-KQL
      AuditLogs
      | where OperationName == "Delete user"
      | where Result == "success"
      | extend InitiatedBy = tostring(InitiatedBy.user.userPrincipalName)
      | extend DeletedUser = tostring(TargetResources[0].userPrincipalName)
      | summarize DeletionCount = count(), DeletedUsers = make_list(DeletedUser) by InitiatedBy, bin(TimeGenerated, 5m)
      | where DeletionCount >= 3
    KQL

    time_aggregation_method = "Count"
    threshold               = 0
    operator                = "GreaterThan"

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  action {
    action_groups = [azurerm_monitor_action_group.iam_security.id]
  }

  tags = {
    managed_by = "terraform"
    alert_type = "identity"
  }
}

# ALERT 3 — Conditional Access Policy Modified or Disabled
# Detects: Someone changed a CA policy — could open security gaps
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "ca_policy_change" {
  name                = "alert-${var.resource_prefix}-ca-policy-modified"
  location            = var.location
  resource_group_name = var.resource_group_name
  description         = "Fires when a Conditional Access policy is created, updated, or deleted"
  severity            = 2
  enabled             = true

  evaluation_frequency = "PT5M"
  window_duration      = "PT5M"

  scopes = [azurerm_log_analytics_workspace.this.id]

  criteria {
    query = <<-KQL
      AuditLogs
      | where OperationName in (
          "Add conditional access policy",
          "Update conditional access policy",
          "Delete conditional access policy"
        )
      | where Result == "success"
      | extend InitiatedBy  = tostring(InitiatedBy.user.userPrincipalName)
      | extend PolicyName   = tostring(TargetResources[0].displayName)
      | extend ChangeType   = OperationName
      | project TimeGenerated, InitiatedBy, PolicyName, ChangeType
    KQL

    time_aggregation_method = "Count"
    threshold               = 0
    operator                = "GreaterThan"

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  action {
    action_groups = [azurerm_monitor_action_group.iam_security.id]
  }

  tags = {
    managed_by = "terraform"
    alert_type = "policy"
  }
}


/*
# ALERT 4 — Sign-in from Outside Trusted Locations
# Detects: User signing in from an unexpected geography
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "signin_outside_trusted" {
  name                = "alert-${var.resource_prefix}-signin-untrusted-location"
  location            = var.location
  resource_group_name = var.resource_group_name
  description         = "Fires on successful sign-ins flagged as outside trusted locations"
  severity            = 3
  enabled             = true

  evaluation_frequency = "PT15M"
  window_duration      = "PT15M"

  scopes = [azurerm_log_analytics_workspace.this.id]
  depends_on = [azurerm_monitor_aad_diagnostic_setting.this]

  criteria {
    query = <<-KQL
      SignInLogs
      | where ResultType == 0
      | where NetworkLocationDetails !contains "trustedNamedLocation"
      | where RiskLevelDuringSignIn in ("medium", "high")
      | extend UserPrincipalName = UserPrincipalName
      | extend City    = tostring(LocationDetails.city)
      | extend Country = tostring(LocationDetails.countryOrRegion)
      | project TimeGenerated, UserPrincipalName, City, Country, IPAddress, RiskLevelDuringSignIn
    KQL

    time_aggregation_method = "Count"
    threshold               = 0
    operator                = "GreaterThan"

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  action {
    action_groups = [azurerm_monitor_action_group.iam_security.id]
  }

  tags = {
    managed_by = "terraform"
    alert_type = "signin"
  }
}

*/
# ALERT 5 — MFA Registration by New User
# Detects: A new MFA method registered — useful for detecting account takeover
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "mfa_registration" {
  name                = "alert-${var.resource_prefix}-new-mfa-registration"
  location            = var.location
  resource_group_name = var.resource_group_name
  description         = "Fires when a user registers a new MFA method"
  severity            = 3
  enabled             = true

  evaluation_frequency = "PT5M"
  window_duration      = "PT5M"

  scopes = [azurerm_log_analytics_workspace.this.id]

  criteria {
    query = <<-KQL
      AuditLogs
      | where OperationName == "User registered security info"
      | where Result == "success"
      | extend InitiatedBy = tostring(InitiatedBy.user.userPrincipalName)
      | extend AuthMethod  = tostring(TargetResources[0].displayName)
      | project TimeGenerated, InitiatedBy, AuthMethod
    KQL

    time_aggregation_method = "Count"
    threshold               = 0
    operator                = "GreaterThan"

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  action {
    action_groups = [azurerm_monitor_action_group.iam_security.id]
  }

  tags = {
    managed_by = "terraform"
    alert_type = "mfa"
  }
}

# ALERT 6 — PIM Role Activated Outside Business Hours
# Detects: Privileged role activated at unusual time — potential compromise
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "pim_outside_hours" {
  name                = "alert-${var.resource_prefix}-pim-activation-outside-hours"
  location            = var.location
  resource_group_name = var.resource_group_name
  description         = "Fires when a PIM role is activated outside 08:00-18:00 UTC"
  severity            = 2
  enabled             = true

  evaluation_frequency = "PT5M"
  window_duration      = "PT5M"

  scopes = [azurerm_log_analytics_workspace.this.id]

  criteria {
    query = <<-KQL
      AuditLogs
      | where OperationName == "Add member to role completed (PIM activation)"
      | where Result == "success"
      | extend Hour = hourofday(TimeGenerated)
      | where Hour < 8 or Hour > 18
      | extend InitiatedBy = tostring(InitiatedBy.user.userPrincipalName)
      | extend RoleName    = tostring(TargetResources[1].displayName)
      | project TimeGenerated, InitiatedBy, RoleName, Hour
    KQL

    time_aggregation_method = "Count"
    threshold               = 0
    operator                = "GreaterThan"

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  action {
    action_groups = [azurerm_monitor_action_group.iam_security.id]
  }

  tags = {
    managed_by = "terraform"
    alert_type = "pim"
  }
}


/*

# Sentinel Analytics Rule — Impossible Travel
# Detects: Same user signing in from two geographically distant locations
# within a short time window
resource "azurerm_sentinel_alert_rule_scheduled" "impossible_travel" {
  name                       = "sentinel-${var.resource_prefix}-impossible-travel"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.this.id
  display_name               = "Impossible Travel Detected"
  description                = "Detects sign-ins from two geographically distant locations within 1 hour"
  severity                   = "High"
  enabled                    = true
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  depends_on = [azurerm_monitor_aad_diagnostic_setting.this]

  query = <<-KQL
    let timeWindow = 60m;
    SignInLogs
    | where ResultType == 0
    | extend City    = tostring(LocationDetails.city)
    | extend Country = tostring(LocationDetails.countryOrRegion)
    | extend Lat     = toreal(LocationDetails.geoCoordinates.latitude)
    | extend Lon     = toreal(LocationDetails.geoCoordinates.longitude)
    | summarize
        Locations  = make_list(pack("city", City, "country", Country, "lat", Lat, "lon", Lon, "time", TimeGenerated)),
        SignInCount = count()
      by UserPrincipalName, bin(TimeGenerated, timeWindow)
    | where array_length(Locations) >= 2
    | mv-expand L1 = Locations, L2 = Locations
    | where L1 != L2
    | extend
        Lat1 = toreal(L1.lat), Lon1 = toreal(L1.lon),
        Lat2 = toreal(L2.lat), Lon2 = toreal(L2.lon)
    | extend DistanceKm = 6371 * acos(
        sin(Lat1 * pi() / 180) * sin(Lat2 * pi() / 180) +
        cos(Lat1 * pi() / 180) * cos(Lat2 * pi() / 180) *
        cos((Lon2 - Lon1) * pi() / 180)
      )
    | where DistanceKm > 500
    | project UserPrincipalName, DistanceKm, Location1 = L1, Location2 = L2, TimeGenerated
  KQL

  incident_configuration {
    create_incident = true

    grouping {
      enabled                 = true
      lookback_duration       = "PT1H"
      reopen_closed_incidents  = false
      entity_matching_method = "Selected"
      group_by_entities       = ["Account"]
      group_by_alert_details  = []
      group_by_custom_details = []
    }
  }

  entity_mapping {
    entity_type = "Account"

    field_mapping {
      identifier  = "FullName"
      column_name = "UserPrincipalName"
    }
  }
}

*/

terraform {
  required_version = ">= 1.6.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.90"
    }
  }
}
