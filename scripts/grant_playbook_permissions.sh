#!/usr/bin/env bash
# =============================================================================
# grant_playbook_permissions.sh
#
# Grants the consent grant response Logic App's managed identity the
# Microsoft Graph API permissions it needs to execute automated remediation:
#
#   - User.ReadWrite.All          → revoke sessions + disable user account
#   - AppRoleAssignment.ReadWrite.All → remove OAuth permission grants
#
# Run this ONCE after the first terraform apply.
# Safe to re-run — duplicate assignments are detected and skipped.
#
# Prerequisites:
#   - Azure CLI logged in as Global Administrator
#   - The Logic App must already be deployed (run terraform apply first)
# =============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

info()    { echo -e "${BLUE}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }
step()    { echo -e "\n${BOLD}${BLUE}▶ $*${NC}"; }

step "Checking prerequisites"
command -v az >/dev/null 2>&1 || error "Azure CLI not found"
az account show >/dev/null 2>&1 || error "Not logged in. Run: az login"
success "Prerequisites OK"

step "Collecting values"
echo ""
read -rp "  Resource group name (e.g. rg-contoso-dev-iam) : " RESOURCE_GROUP
read -rp "  Logic App name (e.g. playbook-contoso-dev-consent-grant-response) : " LOGIC_APP_NAME

step "Getting Logic App managed identity object ID"
PRINCIPAL_ID=$(az resource show \
  --resource-group "$RESOURCE_GROUP" \
  --name "$LOGIC_APP_NAME" \
  --resource-type "Microsoft.Logic/workflows" \
  --query "identity.principalId" -o tsv)

[[ -z "$PRINCIPAL_ID" ]] && error "Could not find Logic App or it has no managed identity. Has terraform apply run successfully?"
info "Managed identity object ID: $PRINCIPAL_ID"

step "Getting Microsoft Graph service principal ID"
GRAPH_SP_ID=$(az ad sp show --id "00000003-0000-0000-c000-000000000000" --query id -o tsv)
info "Graph SP ID: $GRAPH_SP_ID"

grant_app_role() {
  local ROLE_NAME=$1
  local ROLE_ID=$2

  info "Checking if $ROLE_NAME is already granted..."
  EXISTING=$(az rest \
    --method GET \
    --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$PRINCIPAL_ID/appRoleAssignments" \
    --query "value[?appRoleId=='$ROLE_ID'].id | [0]" -o tsv 2>/dev/null || echo "")

  if [[ -n "$EXISTING" ]]; then
    info "  $ROLE_NAME already granted — skipping"
  else
    az rest \
      --method POST \
      --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$PRINCIPAL_ID/appRoleAssignments" \
      --body "{
        \"principalId\": \"$PRINCIPAL_ID\",
        \"resourceId\": \"$GRAPH_SP_ID\",
        \"appRoleId\": \"$ROLE_ID\"
      }" \
      --output none
    success "  $ROLE_NAME granted"
  fi
}

step "Granting Graph API permissions"

# User.ReadWrite.All — revoke sessions + disable user account
grant_app_role "User.ReadWrite.All" "741f803b-c850-494e-b5df-cde7c675a1ca"

# AppRoleAssignment.ReadWrite.All — remove OAuth permission grants
grant_app_role "AppRoleAssignment.ReadWrite.All" "06b708a9-e830-4db3-a914-8e69da51d44f"

echo ""
echo -e "${BOLD}${GREEN}════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${GREEN}  Graph permissions granted successfully.               ${NC}"
echo -e "${BOLD}${GREEN}════════════════════════════════════════════════════════${NC}"
echo ""
echo "  The Logic App can now:"
echo "  • Revoke all refresh tokens for a compromised user"
echo "  • Remove malicious OAuth permission grants"
echo "  • Disable user accounts"
echo ""
echo -e "${BLUE}  Next step:${NC} Test the playbook by triggering the Illicit Consent"
echo "  Grant Sentinel rule and verifying the automated response fires."
echo ""
