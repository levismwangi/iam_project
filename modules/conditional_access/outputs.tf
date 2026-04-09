/*
output "policy_ids" {
  description = "Map of policy name to ID"
  value = {
    block_legacy_auth                    = azuread_conditional_access_policy.block_legacy_auth.id
    require_mfa_admins                   = azuread_conditional_access_policy.require_mfa_admins.id
    require_mfa_all_users                = azuread_conditional_access_policy.require_mfa_all_users.id
    block_risky_locations                = azuread_conditional_access_policy.block_risky_locations.id
    mfa_risky_signin                     = azuread_conditional_access_policy.mfa_risky_signin.id
    require_password_change_high_risk    = azuread_conditional_access_policy.require_password_change_high_user_risk.id
    block_unknown_platforms              = azuread_conditional_access_policy.block_unknown_platforms.id
  }
}
*/
