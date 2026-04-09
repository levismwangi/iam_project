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
  description = "Map of alert rule names to resource IDs"
  value = {
    new_admin_role_assignment = azurerm_monitor_scheduled_query_rules_alert_v2.new_admin_role.id
    bulk_user_deletion        = azurerm_monitor_scheduled_query_rules_alert_v2.bulk_user_deletion.id
    ca_policy_change          = azurerm_monitor_scheduled_query_rules_alert_v2.ca_policy_change.id
    //signin_outside_trusted     = azurerm_monitor_scheduled_query_rules_alert_v2.signin_outside_trusted.id
    mfa_registration = azurerm_monitor_scheduled_query_rules_alert_v2.mfa_registration.id
    //pim_outside_hours          = azurerm_monitor_scheduled_query_rules_alert_v2.pim_outside_hours.id
  }
}

output "sentinel_workspace_id" {
  description = "Sentinel onboarding workspace ID"
  value       = azurerm_sentinel_log_analytics_workspace_onboarding.this.id
}
