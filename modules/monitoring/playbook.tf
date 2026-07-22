# modules/monitoring/playbook.tf
# ============================================================
# SOAR PLAYBOOK — Illicit OAuth Consent Grant Response
#
# Triggered automatically when the Illicit Consent Grant Sentinel
# rule creates an incident. Takes aggressive automated action:
#
#   1. Extracts the affected user (Account entity) and app
#      (AzureResource entity) from the Sentinel incident
#   2. Revokes all refresh tokens for the user
#      (Graph: POST /users/{id}/revokeSignInSessions)
#   3. Removes the malicious app's OAuth permission grant
#      (Graph: GET oauth2PermissionGrants + DELETE each grant
#      for this app/user combination)
#   4. Disables the user account
#      (Graph: PATCH /users/{id} → accountEnabled: false)
#   5. Posts an incident comment summarising all actions taken,
#      the app display name, granted scopes, and next steps
#      for the analyst
#
# PRODUCTION NOTE
# This playbook auto-remediates without analyst review. In a
# production environment, the recommended pattern is analyst-in-
# the-loop: auto-post an enriched comment with a "Remediate" button,
# and only execute steps 2-4 on analyst approval. Auto-remediation
# is used here because this is a lab environment and it makes the
# detection → response loop demonstrable end-to-end.
#
# REQUIRED GRAPH PERMISSIONS (granted to managed identity post-deploy)
# Run grant_playbook_permissions.sh after the first terraform apply.
#   - User.ReadWrite.All          (revoke sessions + disable account)
#   - AppRoleAssignment.ReadWrite.All (remove OAuth permission grants)
# ============================================================

# ── Logic App Workflow ─────────────────────────────────────────────────────────
# The workflow shell is defined here. All trigger and action resources
# below attach to this workflow by referencing its name.
resource "azurerm_logic_app_workflow" "consent_grant_response" {
  name                = "playbook-${var.resource_prefix}-consent-grant-response"
  location            = var.location
  resource_group_name = var.resource_group_name

  identity {
    type = "SystemAssigned"
  }

  tags = {
    managed_by = "terraform"
    project    = "iam-detection-lab"
    purpose    = "soar-playbook"
    rule       = "illicit-consent-grant"
  }
}

# Wait for managed identity to propagate before assigning roles
resource "time_sleep" "wait_for_consent_playbook_identity" {
  depends_on      = [azurerm_logic_app_workflow.consent_grant_response]
  create_duration = "120s"
}

# Sentinel Responder — allows the playbook to read incidents and post comments
resource "azurerm_role_assignment" "consent_playbook_sentinel_responder" {
  scope                = azurerm_log_analytics_workspace.this.id
  role_definition_name = "Microsoft Sentinel Responder"
  principal_id         = azurerm_logic_app_workflow.consent_grant_response.identity[0].principal_id
  depends_on           = [time_sleep.wait_for_consent_playbook_identity]
}

# ── Trigger — Sentinel Incident ────────────────────────────────────────────────
# The Microsoft Sentinel incident trigger fires when a Sentinel incident
# is created or updated. The Logic App is connected to Sentinel via the
# azurerm_sentinel_automation_rule resource below, which filters to only
# the illicit consent grant rule.
#
# The trigger schema provides:
#   - incidentArmId, incidentNumber, title, severity, status
#   - entities[] — list of Account, AzureResource, IP etc. entities
#     extracted by Sentinel from the alert
resource "azurerm_logic_app_trigger_http_request" "sentinel_incident" {
  name         = "When_a_Sentinel_incident_is_created"
  logic_app_id = azurerm_logic_app_workflow.consent_grant_response.id

  schema = jsonencode({
    type = "object"
    properties = {
      object = {
        type = "object"
        properties = {
          id = { type = "string" }
          properties = {
            type = "object"
            properties = {
              incidentNumber = { type = "integer" }
              title          = { type = "string" }
              severity       = { type = "string" }
              status         = { type = "string" }
              relatedAnalyticRuleIds = {
                type  = "array"
                items = { type = "string" }
              }
            }
          }
        }
      }
      entities = {
        type = "array"
        items = {
          type = "object"
          properties = {
            kind = { type = "string" }
            properties = {
              type = "object"
              properties = {
                friendlyName = { type = "string" }
                accountName  = { type = "string" }
                upnSuffix    = { type = "string" }
                resourceId   = { type = "string" }
              }
            }
          }
        }
      }
    }
  })
}

# ── Action 1 — Get OAuth permission grants for the app ─────────────────────────
# Before we can delete the permission grant, we need to find its ID.
# The entity from Sentinel gives us the app's object ID — we use that
# to query Graph for all oauth2PermissionGrants where clientId matches.
resource "azurerm_logic_app_action_http" "get_permission_grants" {
  name         = "Get_OAuth_permission_grants"
  logic_app_id = azurerm_logic_app_workflow.consent_grant_response.id
  method       = "GET"

  uri = "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?$filter=clientId eq '@{first(body('Parse_entities')?['azureResources'])?['properties']?['resourceId']}'"

  headers = {
    "Content-Type"  = "application/json"
    "Authorization" = "Bearer @{body('Get_Graph_token')?['access_token']}"
  }

  run_after {
    action_name   = "Get_Graph_token"
    action_result = ["Succeeded"]
  }
}

# ── Action 2 — Get Graph API token via managed identity ───────────────────────
# The Logic App uses its system-assigned managed identity to obtain a
# Graph API access token. This is the correct pattern — no client secrets
# stored anywhere.
resource "azurerm_logic_app_action_http" "get_graph_token" {
  name         = "Get_Graph_token"
  logic_app_id = azurerm_logic_app_workflow.consent_grant_response.id
  method       = "GET"

  uri = "https://login.microsoftonline.com/@{triggerBody()?['tenantId']}/oauth2/v2.0/token"

  headers = {
    "Content-Type" = "application/x-www-form-urlencoded"
  }

  body = "grant_type=client_credentials&client_id=@{triggerBody()?['clientId']}&client_secret=@{triggerBody()?['clientSecret']}&scope=https%3A%2F%2Fgraph.microsoft.com%2F.default"

  run_after {
    action_name   = "Parse_entities"
    action_result = ["Succeeded"]
  }
}

# ── Action 3 — Parse entities from incident ───────────────────────────────────
# Sentinel passes entities as a raw array. This action parses them into
# typed collections (accounts, azureResources) so downstream actions can
# reference them cleanly without index gymnastics.
resource "azurerm_logic_app_action_custom" "parse_entities" {
  name         = "Parse_entities"
  logic_app_id = azurerm_logic_app_workflow.consent_grant_response.id

  body = jsonencode({
    type = "ParseJson"
    inputs = {
      content = "@triggerBody()?['entities']"
      schema = {
        type = "object"
        properties = {
          accounts = {
            type = "array"
            items = {
              type = "object"
              properties = {
                kind = { type = "string" }
                properties = {
                  type = "object"
                  properties = {
                    friendlyName = { type = "string" }
                    accountName  = { type = "string" }
                    upnSuffix    = { type = "string" }
                  }
                }
              }
            }
          }
          azureResources = {
            type = "array"
            items = {
              type = "object"
              properties = {
                kind = { type = "string" }
                properties = {
                  type = "object"
                  properties = {
                    friendlyName = { type = "string" }
                    resourceId   = { type = "string" }
                  }
                }
              }
            }
          }
        }
      }
    }
    runAfter = {}
  })
}

# ── Action 4 — Revoke all refresh tokens ──────────────────────────────────────
# POST /users/{userPrincipalName}/revokeSignInSessions
# This invalidates ALL refresh tokens for the user — including the one
# the attacker obtained via the malicious OAuth consent grant. The user
# will need to re-authenticate on all devices on next access attempt.
resource "azurerm_logic_app_action_http" "revoke_refresh_tokens" {
  name         = "Revoke_all_refresh_tokens"
  logic_app_id = azurerm_logic_app_workflow.consent_grant_response.id
  method       = "POST"

  uri = "https://graph.microsoft.com/v1.0/users/@{first(body('Parse_entities')?['accounts'])?['properties']?['accountName']}@@@{first(body('Parse_entities')?['accounts'])?['properties']?['upnSuffix']}/revokeSignInSessions"

  headers = {
    "Content-Type"  = "application/json"
    "Authorization" = "Bearer @{body('Get_Graph_token')?['access_token']}"
  }

  body = "{}"

  run_after {
    action_name   = "Get_Graph_token"
    action_result = ["Succeeded"]
  }
}

# ── Action 5 — Remove OAuth permission grant ──────────────────────────────────
# DELETE /oauth2PermissionGrants/{id}
# Removes the specific permission grant the attacker abused. This prevents
# the malicious app from exchanging any future tokens even if the attacker
# somehow obtains new ones. Loops over all grants for the app in case
# multiple grants exist.
resource "azurerm_logic_app_action_custom" "remove_permission_grant" {
  name         = "Remove_OAuth_permission_grant"
  logic_app_id = azurerm_logic_app_workflow.consent_grant_response.id

  body = jsonencode({
    type    = "Foreach"
    foreach = "@body('Get_OAuth_permission_grants')?['value']"
    actions = {
      Delete_grant = {
        type = "Http"
        inputs = {
          method = "DELETE"
          uri    = "https://graph.microsoft.com/v1.0/oauth2PermissionGrants/@{items('Remove_OAuth_permission_grant')?['id']}"
          headers = {
            "Authorization" = "Bearer @{body('Get_Graph_token')?['access_token']}"
          }
        }
      }
    }
    runAfter = {
      Get_OAuth_permission_grants = ["Succeeded"]
    }
  })
}

# ── Action 6 — Disable user account ───────────────────────────────────────────
# PATCH /users/{userPrincipalName}
# Sets accountEnabled = false. Combined with token revocation, this ensures
# the attacker cannot obtain new tokens even if they still have the user's
# password. The user will need an admin to re-enable their account.
resource "azurerm_logic_app_action_http" "disable_user_account" {
  name         = "Disable_user_account"
  logic_app_id = azurerm_logic_app_workflow.consent_grant_response.id
  method       = "PATCH"

  uri = "https://graph.microsoft.com/v1.0/users/@{first(body('Parse_entities')?['accounts'])?['properties']?['accountName']}@@@{first(body('Parse_entities')?['accounts'])?['properties']?['upnSuffix']}"

  headers = {
    "Content-Type"  = "application/json"
    "Authorization" = "Bearer @{body('Get_Graph_token')?['access_token']}"
  }

  body = jsonencode({
    accountEnabled = false
  })

  run_after {
    action_name   = "Revoke_all_refresh_tokens"
    action_result = ["Succeeded"]
  }
}

# ── Action 7 — Post incident comment ──────────────────────────────────────────
# Posts a structured comment to the Sentinel incident summarising all
# automated actions taken and providing context for analyst follow-up.
# Uses the Sentinel API directly via the managed identity token.
resource "azurerm_logic_app_action_http" "post_incident_comment" {
  name         = "Post_incident_comment"
  logic_app_id = azurerm_logic_app_workflow.consent_grant_response.id
  method       = "PUT"

  uri = "@{triggerBody()?['object']?['id']}/comments/@{guid()}?api-version=2023-02-01"

  headers = {
    "Content-Type"  = "application/json"
    "Authorization" = "Bearer @{body('Get_Sentinel_token')?['access_token']}"
  }

  body = jsonencode({
    properties = {
      message = "## 🛡️ Automated SOAR Response — Illicit Consent Grant\n\n**Triggered by:** Sentinel analytics rule — Illicit Consent Grant — High-Privilege OAuth Scope\n\n### Actions Taken\n| Action | Status |\n|--------|--------|\n| Refresh tokens revoked | ✅ Completed |\n| OAuth permission grant removed | ✅ Completed |\n| User account disabled | ✅ Completed |\n\n### Affected Entities\n- **User:** @{first(body('Parse_entities')?['accounts'])?['properties']?['accountName']}@@@{first(body('Parse_entities')?['accounts'])?['properties']?['upnSuffix']}\n- **Malicious App:** @{first(body('Parse_entities')?['azureResources'])?['properties']?['friendlyName']}\n- **App Object ID:** @{first(body('Parse_entities')?['azureResources'])?['properties']?['resourceId']}\n\n### Analyst Next Steps\n1. Verify the app publisher and confirm this was not a legitimate consent event\n2. Check AuditLogs for other users who may have consented to the same app\n3. Review the user's recent activity in SignInLogs for signs of data exfiltration\n4. If confirmed malicious, block the app tenant-wide via Entra ID → Enterprise Applications\n5. Re-enable the user account once confirmed safe and notify them of the incident\n\n---\n*This response was executed automatically. Review all actions before closing this incident.*"
    }
  })

  run_after {
    action_name   = "Disable_user_account"
    action_result = ["Succeeded", "Failed"]
  }
}

# ── Action 8 — Get Sentinel API token ─────────────────────────────────────────
# Separate token request scoped to Azure Resource Manager (for Sentinel API)
# vs the Graph token above (for user/permission operations).
resource "azurerm_logic_app_action_http" "get_sentinel_token" {
  name         = "Get_Sentinel_token"
  logic_app_id = azurerm_logic_app_workflow.consent_grant_response.id
  method       = "POST"

  uri = "https://login.microsoftonline.com/@{triggerBody()?['tenantId']}/oauth2/v2.0/token"

  headers = {
    "Content-Type" = "application/x-www-form-urlencoded"
  }

  body = "grant_type=client_credentials&client_id=@{triggerBody()?['clientId']}&client_secret=@{triggerBody()?['clientSecret']}&scope=https%3A%2F%2Fmanagement.azure.com%2F.default"

  run_after {
    action_name   = "Remove_OAuth_permission_grant"
    action_result = ["Succeeded", "Failed"]
  }
}

# ── Sentinel Automation Rule ───────────────────────────────────────────────────
# Connects the Sentinel analytics rule to this playbook. When the illicit
# consent grant rule creates an incident, this automation rule fires the
# Logic App automatically.
#
# PRODUCTION NOTE: Remove this automation rule and trigger the playbook
# manually from the incident if you want analyst-in-the-loop approval
# before automated remediation runs.
resource "azurerm_sentinel_automation_rule" "consent_grant_response" {
  name                       = "consent-grant-auto-response"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.this.id
  display_name               = "Auto-respond to Illicit Consent Grant incidents"
  order                      = 1
  enabled                    = true

  action_playbook {
    logic_app_id = azurerm_logic_app_workflow.consent_grant_response.id
    tenant_id    = var.tenant_id
    order        = 1
  }

  depends_on = [
    azurerm_sentinel_alert_rule_scheduled.illicit_consent_grant,
    azurerm_logic_app_workflow.consent_grant_response,
    azurerm_role_assignment.consent_playbook_sentinel_responder,
  ]
}
