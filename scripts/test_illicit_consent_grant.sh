#!/usr/bin/env bash
#
# test_illicit_consent_grant.sh
#
# Quick validation test for the "Illicit Consent Grant" Sentinel rule
# (azurerm_sentinel_alert_rule_scheduled.illicit_consent_grant in
# modules/monitoring/main.tf).
#
# WHAT THIS DOES
#   1. Registers a throwaway single-tenant test app requesting the
#      Mail.Read delegated Graph scope (one of the rule's HighRiskScopes).
#   2. Creates a service principal for it so it can actually be consented to.
#   3. Prints an admin-consent URL for you to open in a browser and click
#      "Accept" — this generates a REAL "Consent to application" AuditLogs
#      event, the same signal the rule looks for.
#   4. Polls AuditLogs for that event so you know the moment it lands.
#   5. Runs the rule's exact KQL query directly against the workspace,
#      so you get a pass/fail immediately instead of waiting up to 15
#      minutes for the scheduled rule to run on its own cadence.
#   6. Polls Sentinel's SecurityIncident table for up to 20 minutes so it
#      tells you directly once the incident actually appears, instead of
#      you having to go check the portal yourself.
#   7. Cleans up the test app at the end (with your confirmation).
#
# This is a detection-validation test against your OWN tenant/workspace —
# it does not touch or affect any other identity, app, or organization.
#
# REQUIRES: az CLI logged in with rights to create app registrations
# and query the Log Analytics workspace (same SP/account used for the
# rest of this project is sufficient).
#
# Env vars required:
#   WORKSPACE_NAME   Log Analytics workspace name (e.g. law-contoso-dev-iam-2)
#   RESOURCE_GROUP   Resource group the workspace lives in
#
# Usage:
#   WORKSPACE_NAME=law-contoso-dev-iam-2 RESOURCE_GROUP=rg-contoso-dev-iam \
#     ./scripts/test_illicit_consent_grant.sh

set -euo pipefail

: "${WORKSPACE_NAME:?Set WORKSPACE_NAME to your Log Analytics workspace name}"
: "${RESOURCE_GROUP:?Set RESOURCE_GROUP to the resource group containing that workspace}"

APP_NAME="test-illicit-consent-grant-$(date +%s)"
GRAPH_APP_ID="00000003-0000-0000-c000-000000000000" # Microsoft Graph, fixed well-known ID
TENANT_ID=$(az account show --query tenantId -o tsv)

echo "=== Step 1/7: Resolving Mail.Read delegated scope ID from Microsoft Graph ==="
MAIL_READ_SCOPE_ID=$(az ad sp show --id "$GRAPH_APP_ID" \
  --query "oauth2PermissionScopes[?value=='Mail.Read'].id" -o tsv)

if [[ -z "$MAIL_READ_SCOPE_ID" ]]; then
  echo "Could not resolve Mail.Read scope ID — aborting." >&2
  exit 1
fi
echo "Mail.Read scope ID: $MAIL_READ_SCOPE_ID"

echo ""
echo "=== Step 2/7: Registering test app '$APP_NAME' ==="
REDIRECT_URI="https://login.microsoftonline.com/common/oauth2/nativeclient"
APP_ID=$(az ad app create \
  --display-name "$APP_NAME" \
  --sign-in-audience AzureADMyOrg \
  --web-redirect-uris "$REDIRECT_URI" \
  --required-resource-access "[{\"resourceAppId\":\"$GRAPH_APP_ID\",\"resourceAccess\":[{\"id\":\"$MAIL_READ_SCOPE_ID\",\"type\":\"Scope\"}]}]" \
  --query appId -o tsv)
echo "App registered. Client ID: $APP_ID"

echo ""
echo "=== Step 3/7: Creating service principal (required before it can be consented to) ==="
az ad sp create --id "$APP_ID" >/dev/null
echo "Service principal created."

# redirect_uri must be passed explicitly and match a registered URI on the
# app, or the consent flow fails with AADSTS500113 "No reply address is
# registered for the application" once it tries to redirect back after Accept.
CONSENT_URL="https://login.microsoftonline.com/${TENANT_ID}/adminconsent?client_id=${APP_ID}&redirect_uri=${REDIRECT_URI}"

echo ""
echo "=== Step 4/7: Manual step — grant consent ==="
echo "Open this URL in a browser, signed in as any user in your test tenant,"
echo "and click Accept. This is what generates the real audit event:"
echo ""
echo "  $CONSENT_URL"
echo ""
read -r -p "Press Enter once you've clicked Accept... "

echo ""
echo "=== Step 5/7: Polling AuditLogs for the consent event (up to 15 minutes) ==="
echo "Diagnostic log ingestion from Entra ID into Log Analytics regularly"
echo "takes several minutes — this is expected, not a sign anything is wrong."
FOUND=""
for i in $(seq 1 90); do
  RESULT=$(az monitor log-analytics query \
    --workspace "$WORKSPACE_NAME" \
    --analytics-query "AuditLogs | where OperationName == 'Consent to application' | where TargetResources[0].displayName == '$APP_NAME' | project TimeGenerated, InitiatedBy=tostring(InitiatedBy.user.userPrincipalName)" \
    -o json 2>/dev/null || echo "[]")

  if [[ "$RESULT" != "[]" && -n "$RESULT" ]]; then
    FOUND="1"
    echo "Consent event found in AuditLogs:"
    echo "$RESULT"
    break
  fi
  echo "  ...not seen yet (attempt $i/90), waiting 10s"
  sleep 10
done

if [[ -z "$FOUND" ]]; then
  echo "Consent event still hasn't shown up after 15 minutes. Re-run this"
  echo "query manually once it does — skipping straight to cleanup:"
  echo "  AuditLogs | where OperationName == 'Consent to application' | where TargetResources[0].displayName == '$APP_NAME'"
fi

if [[ -n "$FOUND" ]]; then
  echo ""
  echo "=== Step 6/7: Running the rule's exact detection KQL ==="
  RULE_RESULT=$(az monitor log-analytics query \
    --workspace "$WORKSPACE_NAME" \
    --analytics-query "let HighRiskScopes = dynamic([\"Mail.Read\", \"Mail.ReadWrite\", \"Mail.Send\", \"Files.Read.All\", \"Files.ReadWrite.All\", \"Directory.Read.All\", \"Directory.ReadWrite.All\", \"offline_access\", \"full_access_as_app\"]); AuditLogs | where OperationName == 'Consent to application' | where Result == 'success' | extend AppDisplayName = tostring(TargetResources[0].displayName) | extend AppObjectId = tostring(TargetResources[0].id) | extend ConsentedBy = tostring(InitiatedBy.user.userPrincipalName) | extend ModifiedProps = TargetResources[0].modifiedProperties | mv-expand ModifiedProps | extend PropName = tostring(ModifiedProps.displayName) | extend PropValue = tostring(ModifiedProps.newValue) | where PropName == 'ConsentAction.Permissions' | where PropValue has_any (HighRiskScopes) | where AppDisplayName == '$APP_NAME' | project TimeGenerated, ConsentedBy, AppDisplayName, AppObjectId, GrantedScopes = PropValue" \
    -o json 2>/dev/null || echo "[]")

  echo "$RULE_RESULT"
  echo ""
  if [[ "$RULE_RESULT" != "[]" && -n "$RULE_RESULT" ]]; then
    RULE_MATCHED="1"
    echo "PASS — the rule's query matched this consent event. The Sentinel"
    echo "scheduled rule should raise an incident on its next 15-minute run."
  else
    echo "NO MATCH — the raw consent event IS in AuditLogs (Step 5 found it),"
    echo "but the rule's query with the HighRiskScopes filter and"
    echo "ConsentAction.Permissions field didn't match it. This is worth"
    echo "investigating directly — check ModifiedProperties on the raw event:"
    echo "  AuditLogs | where OperationName == 'Consent to application' | where TargetResources[0].displayName == '$APP_NAME' | project TargetResources"
  fi
fi

if [[ -n "${RULE_MATCHED:-}" ]]; then
  echo ""
  echo "=== Step 7/7: Polling Sentinel for the resulting incident (up to 20 minutes) ==="
  echo "This accounts for the rule's own 15-minute schedule plus a buffer —"
  echo "you don't need to go check the portal, this will tell you directly."
  INCIDENT_FOUND=""
  for i in $(seq 1 40); do
    INCIDENT_RESULT=$(az monitor log-analytics query \
      --workspace "$WORKSPACE_NAME" \
      --analytics-query "SecurityIncident | where Title == 'Illicit Consent Grant — High-Privilege OAuth Scope' | where TimeGenerated > ago(1h) | summarize arg_max(TimeGenerated, *) by IncidentNumber | project TimeGenerated, IncidentNumber, Title, Severity, Status" \
      -o json 2>/dev/null || echo "[]")

    if [[ "$INCIDENT_RESULT" != "[]" && -n "$INCIDENT_RESULT" ]]; then
      INCIDENT_FOUND="1"
      echo ""
      echo "INCIDENT CREATED — the rule fired:"
      echo "$INCIDENT_RESULT"
      break
    fi
    echo "  ...no incident yet (attempt $i/40), waiting 30s"
    sleep 30
  done

  if [[ -z "$INCIDENT_FOUND" ]]; then
    echo ""
    echo "No incident showed up within 20 minutes. Since Step 6 showed a PASS,"
    echo "this usually just means the analytics rule hasn't had its next"
    echo "scheduled run yet, or the Sentinel Contributor role assignment"
    echo "(granted by the foundation module) hasn't fully propagated. Check:"
    echo "  - Sentinel -> Analytics -> this rule -> 'Last run' timestamp"
    echo "  - Re-run manually: SecurityIncident | where Title == 'Illicit Consent Grant — High-Privilege OAuth Scope' | order by TimeGenerated desc"
  fi
else
  echo ""
  echo "=== Step 7/7: Skipped — no confirmed rule match to wait on an incident for ==="
fi

echo ""
read -r -p "Clean up: delete the test app registration now? [y/N] " CLEANUP
if [[ "$CLEANUP" =~ ^[Yy]$ ]]; then
  az ad app delete --id "$APP_ID"
  echo "Test app deleted."
else
  echo "Leaving test app in place. Delete it later with:"
  echo "  az ad app delete --id $APP_ID"
fi
