# modules/monitoring/main.tf
# Log Analytics + Sentinel + Alert Rules for IAM threat detection

# ============================================================
# CORE INFRASTRUCTURE
# ============================================================

# Log Analytics Workspace
resource "azurerm_log_analytics_workspace" "this" {
  name                = "law-${var.resource_prefix}-iam-2"
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

# ============================================================
# ACTION GROUP — where alerts get sent
# ============================================================

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

# ============================================================
# PHASE 3 — LOGIC APP PLAYBOOK (SOAR)
# Auto-disables a user when account compromise is detected
# ============================================================

resource "azurerm_logic_app_workflow" "disable_user" {
  name                = "playbook-${var.resource_prefix}-disable-compromised-user"
  location            = var.location
  resource_group_name = var.resource_group_name

  # System-assigned identity so the Logic App can call Azure APIs
  identity {
    type = "SystemAssigned"
  }

  tags = {
    managed_by = "terraform"
    project    = "iam-project"
    purpose    = "soar-playbook"
  }
}

# Give the Logic app permission to act as a Sentinel Responder
# (needed to update incidents and trigger responses)
resource "time_sleep" "wait_for_logic_app_identity" {
  depends_on      = [azurerm_logic_app_workflow.disable_user]
  create_duration = "30s"
}
# Give the Logic App permission to act as a Sentinel Responder
# (needed to update incidents and trigger responses)
resource "azurerm_role_assignment" "logic_app_sentinel_responder" {
  scope                = azurerm_log_analytics_workspace.this.id
  role_definition_name = "Microsoft Sentinel Responder"
  principal_id         = azurerm_logic_app_workflow.disable_user.identity[0].principal_id
  depends_on           = [azurerm_logic_app_workflow.disable_user]
}

# ============================================================
# PHASE 1 & 2 — SENTINEL ANALYTICS RULES
# Migrated from scheduled query rules to proper Sentinel rules
# with incident creation, entity mapping, and MITRE tagging
# ============================================================

# SENTINEL RULE 1 — New Admin Role Assignment
# MITRE: Privilege Escalation — T1078 (Valid Accounts)
resource "azurerm_sentinel_alert_rule_scheduled" "new_admin_role" {
  name                       = "sentinel-${var.resource_prefix}-new-admin-role-assignment"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.this.id
  display_name               = "New Admin Role Assignment Detected"
  description                = "Fires when a user is added to a privileged directory role"
  severity                   = "Medium"
  enabled                    = true
  query_frequency            = "PT5M"
  query_period               = "PT5M"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  tactics                    = ["PrivilegeEscalation", "Persistence"]
  techniques                 = ["T1078"]
  depends_on                 = [azurerm_sentinel_log_analytics_workspace_onboarding.this]

  query = <<-KQL
    AuditLogs
    | where OperationName in ("Add member to role", "Add eligible member to role")
    | where Result == "success"
    | extend InitiatedBy = tostring(InitiatedBy.user.userPrincipalName)
    | extend TargetUser  = tostring(TargetResources[0].userPrincipalName)
    | extend RoleName    = tostring(TargetResources[1].displayName)
    | project TimeGenerated, InitiatedBy, TargetUser, RoleName, OperationName
  KQL



  entity_mapping {
    entity_type = "Account"
    field_mapping {
      identifier  = "FullName"
      column_name = "TargetUser"
    }
  }

  entity_mapping {
    entity_type = "Account"
    field_mapping {
      identifier  = "FullName"
      column_name = "InitiatedBy"
    }
  }
}

# SENTINEL RULE 2 — Bulk User Deletion
# MITRE: Impact — T1531 (Account Access Removal)
resource "azurerm_sentinel_alert_rule_scheduled" "bulk_user_deletion" {
  name                       = "sentinel-${var.resource_prefix}-bulk-user-deletion"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.this.id
  display_name               = "Bulk User Deletion Detected"
  description                = "Fires when 3 or more users are deleted within 5 minutes — potential insider threat or destructive attack"
  severity                   = "High"
  enabled                    = true
  query_frequency            = "PT5M"
  query_period               = "PT5M"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  tactics                    = ["Impact"]
  techniques                 = ["T1531"]
  depends_on                 = [azurerm_sentinel_log_analytics_workspace_onboarding.this]

  query = <<-KQL
    AuditLogs
    | where OperationName == "Delete user"
    | where Result == "success"
    | extend InitiatedBy = tostring(InitiatedBy.user.userPrincipalName)
    | extend DeletedUser = tostring(TargetResources[0].userPrincipalName)
    | summarize DeletionCount = count(), DeletedUsers = make_list(DeletedUser) by InitiatedBy, bin(TimeGenerated, 5m)
    | where DeletionCount >= 3
  KQL



  entity_mapping {
    entity_type = "Account"
    field_mapping {
      identifier  = "FullName"
      column_name = "InitiatedBy"
    }
  }
}

# SENTINEL RULE 3 — Conditional Access Policy Modified
# MITRE: Defense Evasion — T1556 (Modify Authentication Process)
resource "azurerm_sentinel_alert_rule_scheduled" "ca_policy_change" {
  name                       = "sentinel-${var.resource_prefix}-ca-policy-modified"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.this.id
  display_name               = "Conditional Access Policy Modified"
  description                = "Fires when a Conditional Access policy is created, updated, or deleted — could open security gaps"
  severity                   = "Medium"
  enabled                    = true
  query_frequency            = "PT5M"
  query_period               = "PT5M"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  tactics                    = ["DefenseEvasion", "Persistence"]
  techniques                 = ["T1556"]
  depends_on                 = [azurerm_sentinel_log_analytics_workspace_onboarding.this]

  query = <<-KQL
    AuditLogs
    | where OperationName in (
        "Add conditional access policy",
        "Update conditional access policy",
        "Delete conditional access policy"
      )
    | where Result == "success"
    | extend InitiatedBy = tostring(InitiatedBy.user.userPrincipalName)
    | extend PolicyName  = tostring(TargetResources[0].displayName)
    | extend ChangeType  = OperationName
    | project TimeGenerated, InitiatedBy, PolicyName, ChangeType
  KQL



  entity_mapping {
    entity_type = "Account"
    field_mapping {
      identifier  = "FullName"
      column_name = "InitiatedBy"
    }
  }
}

# SENTINEL RULE 4 — Sign-in from Outside Trusted Locations
# MITRE: Initial Access — T1078 (Valid Accounts)
resource "azurerm_sentinel_alert_rule_scheduled" "signin_outside_trusted" {
  name                       = "sentinel-${var.resource_prefix}-signin-untrusted-location"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.this.id
  display_name               = "Sign-in from Untrusted Location"
  description                = "Fires on successful sign-ins flagged as outside trusted locations with medium/high risk"
  severity                   = "Medium"
  enabled                    = true
  query_frequency            = "PT15M"
  query_period               = "PT15M"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  tactics                    = ["InitialAccess"]
  techniques                 = ["T1078"]
  depends_on                 = [azurerm_monitor_aad_diagnostic_setting.this, azurerm_sentinel_log_analytics_workspace_onboarding.this]

  query = <<-KQL
    SignInLogs
    | where ResultType == 0
    | where NetworkLocationDetails !contains "trustedNamedLocation"
    | where RiskLevelDuringSignIn in ("medium", "high")
    | extend City    = tostring(LocationDetails.city)
    | extend Country = tostring(LocationDetails.countryOrRegion)
    | project TimeGenerated, UserPrincipalName, City, Country, IPAddress, RiskLevelDuringSignIn
  KQL



  entity_mapping {
    entity_type = "Account"
    field_mapping {
      identifier  = "FullName"
      column_name = "UserPrincipalName"
    }
  }

  entity_mapping {
    entity_type = "IP"
    field_mapping {
      identifier  = "Address"
      column_name = "IPAddress"
    }
  }
}

# SENTINEL RULE 5 — New MFA Registration
# MITRE: Persistence — T1098 (Account Manipulation)
resource "azurerm_sentinel_alert_rule_scheduled" "mfa_registration" {
  name                       = "sentinel-${var.resource_prefix}-new-mfa-registration"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.this.id
  display_name               = "New MFA Method Registered"
  description                = "Fires when a user registers a new MFA method — useful for detecting account takeover"
  severity                   = "Low"
  enabled                    = true
  query_frequency            = "PT5M"
  query_period               = "PT5M"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  tactics                    = ["Persistence"]
  techniques                 = ["T1098"]
  depends_on                 = [azurerm_sentinel_log_analytics_workspace_onboarding.this]

  query = <<-KQL
    AuditLogs
    | where OperationName == "User registered security info"
    | where Result == "success"
    | extend InitiatedBy = tostring(InitiatedBy.user.userPrincipalName)
    | extend AuthMethod  = tostring(TargetResources[0].displayName)
    | project TimeGenerated, InitiatedBy, AuthMethod
  KQL



  entity_mapping {
    entity_type = "Account"
    field_mapping {
      identifier  = "FullName"
      column_name = "InitiatedBy"
    }
  }
}

# SENTINEL RULE 6 — PIM Role Activated Outside Business Hours
# MITRE: Privilege Escalation — T1078 (Valid Accounts)
resource "azurerm_sentinel_alert_rule_scheduled" "pim_outside_hours" {
  name                       = "sentinel-${var.resource_prefix}-pim-activation-outside-hours"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.this.id
  display_name               = "PIM Role Activated Outside Business Hours"
  description                = "Fires when a PIM role is activated outside 08:00-18:00 UTC — potential compromise"
  severity                   = "Medium"
  enabled                    = true
  query_frequency            = "PT5M"
  query_period               = "PT5M"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  tactics                    = ["PrivilegeEscalation"]
  techniques                 = ["T1078"]
  depends_on                 = [azurerm_sentinel_log_analytics_workspace_onboarding.this]

  query = <<-KQL
    AuditLogs
    | where OperationName == "Add member to role completed (PIM activation)"
    | where Result == "success"
    | extend Hour        = hourofday(TimeGenerated)
    | where Hour < 8 or Hour > 18
    | extend InitiatedBy = tostring(InitiatedBy.user.userPrincipalName)
    | extend RoleName    = tostring(TargetResources[1].displayName)
    | project TimeGenerated, InitiatedBy, RoleName, Hour
  KQL



  entity_mapping {
    entity_type = "Account"
    field_mapping {
      identifier  = "FullName"
      column_name = "InitiatedBy"
    }
  }
}

# SENTINEL RULE 7 — Impossible Travel (Phase 1 — uncommented)
# MITRE: Initial Access — T1078 (Valid Accounts)
# Detects: Same user signing in from two geographically distant locations
# within a short time window
resource "azurerm_sentinel_alert_rule_scheduled" "impossible_travel" {
  name                       = "sentinel-${var.resource_prefix}-impossible-travel"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.this.id
  display_name               = "Impossible Travel Detected"
  description                = "Detects sign-ins from two geographically distant locations within 1 hour — likely account compromise"
  severity                   = "High"
  enabled                    = true
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  tactics                    = ["InitialAccess"]
  techniques                 = ["T1078"]
  depends_on                 = [azurerm_monitor_aad_diagnostic_setting.this, azurerm_sentinel_log_analytics_workspace_onboarding.this]

  query = <<-KQL
    let timeWindow = 60m;
    SignInLogs
    | where ResultType == 0
    | extend City    = tostring(LocationDetails.city)
    | extend Country = tostring(LocationDetails.countryOrRegion)
    | extend Lat     = toreal(LocationDetails.geoCoordinates.latitude)
    | extend Lon     = toreal(LocationDetails.geoCoordinates.longitude)
    | summarize
        Locations   = make_list(pack("city", City, "country", Country, "lat", Lat, "lon", Lon, "time", TimeGenerated)),
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


  entity_mapping {
    entity_type = "Account"
    field_mapping {
      identifier  = "FullName"
      column_name = "UserPrincipalName"
    }
  }
}

# ============================================================
# LEGACY SCHEDULED QUERY RULES
# Kept for backward compatibility and email alerting
# These complement the Sentinel rules above
# ============================================================

resource "azurerm_monitor_scheduled_query_rules_alert_v2" "new_admin_role" {
  name                  = "alert-${var.resource_prefix}-new-admin-role-assignment"
  location              = var.location
  resource_group_name   = var.resource_group_name
  description           = "Fires when a user is added to a privileged directory role"
  severity              = 2
  enabled               = true
  skip_query_validation = true
  evaluation_frequency  = "PT5M"
  window_duration       = "PT5M"
  scopes                = [azurerm_log_analytics_workspace.this.id]

  criteria {
    query                   = <<-KQL
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

resource "azurerm_monitor_scheduled_query_rules_alert_v2" "bulk_user_deletion" {
  name                  = "alert-${var.resource_prefix}-bulk-user-deletion"
  location              = var.location
  resource_group_name   = var.resource_group_name
  description           = "Fires when 3 or more users are deleted within 5 minutes"
  severity              = 1
  enabled               = true
  skip_query_validation = true
  evaluation_frequency  = "PT5M"
  window_duration       = "PT5M"
  scopes                = [azurerm_log_analytics_workspace.this.id]

  criteria {
    query                   = <<-KQL
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

resource "azurerm_monitor_scheduled_query_rules_alert_v2" "ca_policy_change" {
  name                  = "alert-${var.resource_prefix}-ca-policy-modified"
  location              = var.location
  resource_group_name   = var.resource_group_name
  description           = "Fires when a Conditional Access policy is created, updated, or deleted"
  severity              = 2
  enabled               = true
  skip_query_validation = true
  evaluation_frequency  = "PT5M"
  window_duration       = "PT5M"
  scopes                = [azurerm_log_analytics_workspace.this.id]

  criteria {
    query                   = <<-KQL
      AuditLogs
      | where OperationName in (
          "Add conditional access policy",
          "Update conditional access policy",
          "Delete conditional access policy"
        )
      | where Result == "success"
      | extend InitiatedBy = tostring(InitiatedBy.user.userPrincipalName)
      | extend PolicyName  = tostring(TargetResources[0].displayName)
      | extend ChangeType  = OperationName
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

resource "azurerm_monitor_scheduled_query_rules_alert_v2" "signin_outside_trusted" {
  name                  = "alert-${var.resource_prefix}-signin-untrusted-location"
  location              = var.location
  resource_group_name   = var.resource_group_name
  description           = "Fires on successful sign-ins flagged as outside trusted locations"
  severity              = 3
  enabled               = true
  skip_query_validation = true
  evaluation_frequency  = "PT15M"
  window_duration       = "PT15M"
  scopes                = [azurerm_log_analytics_workspace.this.id]
  depends_on            = [azurerm_monitor_aad_diagnostic_setting.this]

  criteria {
    query                   = <<-KQL
      SignInLogs
      | where ResultType == 0
      | where NetworkLocationDetails !contains "trustedNamedLocation"
      | where RiskLevelDuringSignIn in ("medium", "high")
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

resource "azurerm_monitor_scheduled_query_rules_alert_v2" "mfa_registration" {
  name                  = "alert-${var.resource_prefix}-new-mfa-registration"
  location              = var.location
  resource_group_name   = var.resource_group_name
  description           = "Fires when a user registers a new MFA method"
  severity              = 3
  enabled               = true
  skip_query_validation = true
  evaluation_frequency  = "PT5M"
  window_duration       = "PT5M"
  scopes                = [azurerm_log_analytics_workspace.this.id]

  criteria {
    query                   = <<-KQL
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

resource "azurerm_monitor_scheduled_query_rules_alert_v2" "pim_outside_hours" {
  name                  = "alert-${var.resource_prefix}-pim-activation-outside-hours"
  location              = var.location
  resource_group_name   = var.resource_group_name
  description           = "Fires when a PIM role is activated outside 08:00-18:00 UTC"
  severity              = 2
  enabled               = true
  skip_query_validation = true
  evaluation_frequency  = "PT5M"
  window_duration       = "PT5M"
  scopes                = [azurerm_log_analytics_workspace.this.id]

  criteria {
    query                   = <<-KQL
      AuditLogs
      | where OperationName == "Add member to role completed (PIM activation)"
      | where Result == "success"
      | extend Hour        = hourofday(TimeGenerated)
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

# ============================================================
# SENTINEL RULE 8 — Illicit Consent Grant (OAuth Token Theft)
# MITRE: Credential Access / Persistence — T1528 (Steal Application
# Access Token), T1550.001 (Use Alternate Authentication Material)
#
# THREAT MODEL
# Unlike credential-based attacks, this technique never touches the
# user's password and is invisible to MFA and Conditional Access.
# The attacker tricks a user into granting OAuth consent to a
# malicious multi-tenant app requesting high-privilege Graph scopes
# (mail, files, directory). The app receives a refresh token that
# persists independently of the user's password — surviving password
# resets and even MFA re-enrollment — giving the attacker durable,
# silent access to mailbox/file data with no further sign-in events
# to alert on.
#
# DETECTION LOGIC
# A single consent event is not inherently malicious — users grant
# app consent constantly as part of normal SaaS adoption. The signal
# here is the *combination* of:
#   1. A consent event for a genuinely sensitive scope (not just
#      profile/openid, but mail, files, or directory write access)
#   2. The granting account itself, surfaced for triage
# This intentionally avoids naive "any consent = alert" noise, which
# is the most common reason consent-grant detections get disabled in
# real SOCs within a week of going live.
# ============================================================

resource "azurerm_sentinel_alert_rule_scheduled" "illicit_consent_grant" {
  name                       = "sentinel-${var.resource_prefix}-illicit-consent-grant"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.this.id
  display_name               = "Illicit Consent Grant — High-Privilege OAuth Scope"
  description                = <<-DESC
    Fires when a user grants OAuth consent to an application requesting
    high-privilege Microsoft Graph scopes (mail, files, or directory
    access). This pattern is consistent with consent phishing / illicit
    consent grant attacks, where a malicious multi-tenant app is used to
    obtain a persistent refresh token that bypasses MFA and survives
    password resets. Investigate the application's publisher, age, and
    tenant scope before assuming legitimacy.
  DESC
  severity                   = "High"
  enabled                    = true
  query_frequency            = "PT15M"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  tactics                    = ["CredentialAccess", "Persistence"]
  techniques                 = ["T1528"]
  depends_on                 = [azurerm_sentinel_log_analytics_workspace_onboarding.this]

  # skip_query_validation intentionally NOT set here — this query only
  # references AuditLogs, which is already validated and flowing from
  # the existing rules in this module.

  query = <<-KQL
    let HighRiskScopes = dynamic([
      "Mail.Read", "Mail.ReadWrite", "Mail.Send",
      "Files.Read.All", "Files.ReadWrite.All",
      "Directory.Read.All", "Directory.ReadWrite.All",
      "offline_access", "full_access_as_app"
    ]);
    AuditLogs
    | where OperationName == "Consent to application"
    | where Result == "success"
    | extend AppDisplayName  = tostring(TargetResources[0].displayName)
    | extend AppObjectId     = tostring(TargetResources[0].id)
    | extend ConsentedBy     = tostring(InitiatedBy.user.userPrincipalName)
    | extend ModifiedProps   = TargetResources[0].modifiedProperties
    | mv-expand ModifiedProps
    | extend PropName  = tostring(ModifiedProps.displayName)
    | extend PropValue = tostring(ModifiedProps.newValue)
    | where PropName == "ConsentAction.Permissions"
    | where PropValue has_any (HighRiskScopes)
    | project TimeGenerated, ConsentedBy, AppDisplayName, AppObjectId, GrantedScopes = PropValue
    | summarize GrantEvents = count(), Scopes = make_set(GrantedScopes) by ConsentedBy, AppDisplayName, AppObjectId, bin(TimeGenerated, 15m)
  KQL

  entity_mapping {
    entity_type = "Account"
    field_mapping {
      identifier  = "FullName"
      column_name = "ConsentedBy"
    }
  }

  entity_mapping {
    entity_type = "AzureResource"
    field_mapping {
      identifier  = "ResourceId"
      column_name = "AppObjectId"
    }
  }
}

# ============================================================
# PROVIDER REQUIREMENTS
# ============================================================

terraform {
  required_version = ">= 1.6.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.90"
    }
    time = {
      source  = "hashicorp/time"
      version = "~> 0.11"
    }
  }
}
