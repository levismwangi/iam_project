output "log_analytics_workspace_id" {
  description = "Resource ID of the Log Analytics workspace"
  value       = azurerm_log_analytics_workspace.this.id
}

output "log_analytics_workspace_name" {
  description = "Name of the Log Analytics workspace"
  value       = azurerm_log_analytics_workspace.this.name
}

output "action_group_id" {
  description = "Resource ID of the IAM security action group"
  value       = azurerm_monitor_action_group.iam_security.id
}


output "alert_rule_ids" {
  description = "Map of legacy scheduled-query alert rule names to resource IDs (email-alerting layer)"
  value = {
    new_admin_role_assignment = azurerm_monitor_scheduled_query_rules_alert_v2.new_admin_role.id
    bulk_user_deletion        = azurerm_monitor_scheduled_query_rules_alert_v2.bulk_user_deletion.id
    ca_policy_change          = azurerm_monitor_scheduled_query_rules_alert_v2.ca_policy_change.id
    //signin_outside_trusted     = azurerm_monitor_scheduled_query_rules_alert_v2.signin_outside_trusted.id
    mfa_registration = azurerm_monitor_scheduled_query_rules_alert_v2.mfa_registration.id
    //pim_outside_hours          = azurerm_monitor_scheduled_query_rules_alert_v2.pim_outside_hours.id
  }
}

output "sentinel_rule_ids" {
  description = "Map of Sentinel-native analytics rule names to resource IDs (incident-creating layer)"
  value = {
    new_admin_role_assignment = azurerm_sentinel_alert_rule_scheduled.new_admin_role.id
    bulk_user_deletion        = azurerm_sentinel_alert_rule_scheduled.bulk_user_deletion.id
    ca_policy_change          = azurerm_sentinel_alert_rule_scheduled.ca_policy_change.id
    mfa_registration          = azurerm_sentinel_alert_rule_scheduled.mfa_registration.id
    pim_outside_hours         = azurerm_sentinel_alert_rule_scheduled.pim_outside_hours.id
    illicit_consent_grant     = azurerm_sentinel_alert_rule_scheduled.illicit_consent_grant.id
    prt_replay_detection      = azurerm_sentinel_alert_rule_scheduled.prt_replay_detection.id
  }
}

output "prt_watchlist_name" {
  description = "Name of the Sentinel watchlist backing PRT replay detection — used by watchlist-refresh.yml to target the correct watchlist alias"
  value       = azurerm_sentinel_watchlist.known_user_app_device.name
}

output "sentinel_workspace_id" {
  description = "Sentinel onboarding workspace ID"
  value       = azurerm_sentinel_log_analytics_workspace_onboarding.this.id
}
