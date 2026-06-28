#!/usr/bin/env bash
# =============================================================================
# bootstrap.sh — One-shot setup for the IAM project (dev environment)
#
# What this does:
#   1. Collects required values interactively
#   2. Creates a Service Principal with the required Graph API permissions
#   3. Grants admin consent on all Graph permissions
#   4. Assigns Security Administrator role to the SP
#   5. Configures OIDC federated credentials (main, dev env, PR)
#   6. Creates remote state storage (resource group, storage account, container)
#   7. Creates Key Vault + grants you Secrets Officer access
#   8. Grants SP Key Vault Secrets User access
#   9. Prompts for temp password and stores it in Key Vault
#  10. Generates terraform.tfvars
#  11. Prints all GitHub secrets you need to configure
#
# Prerequisites:
#   - Azure CLI installed and logged in (az login)
#   - Sufficient permissions: Global Administrator or Privileged Role Administrator
#   - jq installed (sudo apt install jq / brew install jq)
# =============================================================================

set -euo pipefail

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

info()    { echo -e "${BLUE}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }
step()    { echo -e "\n${BOLD}${BLUE}▶ $*${NC}"; }

# ── Preflight checks ─────────────────────────────────────────────────────────
step "Checking prerequisites"

command -v az  >/dev/null 2>&1 || error "Azure CLI not found. Install from https://aka.ms/installazurecli"
command -v jq  >/dev/null 2>&1 || error "jq not found. Install with: sudo apt install jq  (or brew install jq)"

az account show >/dev/null 2>&1 || error "Not logged in. Run: az login"
success "Prerequisites OK"

# ── Collect inputs ────────────────────────────────────────────────────────────
step "Collecting configuration values"
echo ""

read -rp "  Tenant ID                   : " TENANT_ID
read -rp "  Subscription ID             : " SUBSCRIPTION_ID
read -rp "  Tenant domain (e.g. x.onmicrosoft.com): " TENANT_DOMAIN
read -rp "  Company / project name      : " COMPANY_NAME
read -rp "  GitHub org or username      : " GITHUB_ORG
read -rp "  GitHub repo name            : " GITHUB_REPO
read -rp "  Azure region (default: southafricanorth): " LOCATION
LOCATION="${LOCATION:-southafricanorth}"
read -rp "  Alert email                 : " ALERT_EMAIL

# Derived names
SP_NAME="sp-terraform-iam-dev"
RG_NAME="rg-terraform-state"
STORAGE_ACCOUNT="tfstateiam${COMPANY_NAME,,}"   # lowercase company name appended
STORAGE_ACCOUNT="${STORAGE_ACCOUNT:0:24}"        # storage account names max 24 chars
CONTAINER_NAME="tfstate"
KV_NAME="kv-iam-${COMPANY_NAME,,}"
KV_NAME="${KV_NAME:0:24}"                        # key vault names max 24 chars

echo ""
info "Will create the following resources:"
echo "    Service Principal : $SP_NAME"
echo "    Resource group    : $RG_NAME"
echo "    Storage account   : $STORAGE_ACCOUNT"
echo "    Key Vault         : $KV_NAME"
echo "    Region            : $LOCATION"
echo ""
read -rp "  Looks good? (y/N): " CONFIRM
[[ "${CONFIRM,,}" == "y" ]] || { info "Aborted."; exit 0; }

# ── Step 1: Create the Service Principal ─────────────────────────────────────
step "Creating Service Principal: $SP_NAME"

SP_JSON=$(az ad sp create-for-rbac \
  --name "$SP_NAME" \
  --role "Contributor" \
  --scopes "/subscriptions/$SUBSCRIPTION_ID" \
  --output json)

APP_CLIENT_ID=$(echo "$SP_JSON" | jq -r '.appId')
SP_OBJECT_ID=$(az ad sp show --id "$APP_CLIENT_ID" --query id -o tsv)
APP_OBJECT_ID=$(az ad app show --id "$APP_CLIENT_ID" --query id -o tsv)

success "Service Principal created — Client ID: $APP_CLIENT_ID"

# ── Step 2: Grant Graph API permissions ───────────────────────────────────────
step "Granting Microsoft Graph API permissions"

GRAPH_APP_ID="00000003-0000-0000-c000-000000000000"

declare -A GRAPH_PERMISSIONS=(
  ["Application.ReadWrite.All"]="1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9"
  ["Directory.ReadWrite.All"]="19dbc75e-c2e2-444c-a770-ec69d8559fc7"
  ["Policy.ReadWrite.ConditionalAccess"]="01c0a623-fc9b-48e9-b794-0756f8e8f067"
  ["RoleManagement.ReadWrite.Directory"]="9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8"
  ["PrivilegedAccess.ReadWrite.AzureAD"]="854d9ab1-6657-4ec8-be45-823027bcd009"
  ["RoleEligibilitySchedule.ReadWrite.Directory"]="feb947fd-e330-4a52-8ce4-c4e621d5d969"
  ["User.ReadWrite.All"]="741f803b-c850-494e-b5df-cde7c675a1ca"
)

for PERM_NAME in "${!GRAPH_PERMISSIONS[@]}"; do
  PERM_ID="${GRAPH_PERMISSIONS[$PERM_NAME]}"
  info "  Adding $PERM_NAME"
  az ad app permission add \
    --id "$APP_CLIENT_ID" \
    --api "$GRAPH_APP_ID" \
    --api-permissions "${PERM_ID}=Role" \
    --output none
done

success "Graph API permissions added"

# ── Step 3: Admin consent ─────────────────────────────────────────────────────
step "Granting admin consent on Graph permissions"
info "Waiting 15 seconds for permissions to register before consenting..."
sleep 15

az ad app permission admin-consent --id "$APP_CLIENT_ID" --output none
success "Admin consent granted"

# ── Step 4: Assign Security Administrator role ────────────────────────────────
step "Assigning Security Administrator role to SP"

SEC_ADMIN_ROLE_ID=$(az rest \
  --method GET \
  --uri "https://graph.microsoft.com/v1.0/directoryRoles" \
  --query "value[?displayName=='Security Administrator'].id | [0]" \
  -o tsv 2>/dev/null || echo "")

if [[ -z "$SEC_ADMIN_ROLE_ID" ]]; then
  # Role may not be activated yet — activate it first
  SEC_ADMIN_TEMPLATE_ID="194ae4cb-b126-40b2-bd5b-6091b380977d"
  info "Activating Security Administrator role in tenant..."
  az rest \
    --method POST \
    --uri "https://graph.microsoft.com/v1.0/directoryRoles" \
    --body "{\"roleTemplateId\": \"$SEC_ADMIN_TEMPLATE_ID\"}" \
    --output none
  sleep 5
  SEC_ADMIN_ROLE_ID=$(az rest \
    --method GET \
    --uri "https://graph.microsoft.com/v1.0/directoryRoles" \
    --query "value[?displayName=='Security Administrator'].id | [0]" \
    -o tsv)
fi

az rest \
  --method POST \
  --uri "https://graph.microsoft.com/v1.0/directoryRoles/$SEC_ADMIN_ROLE_ID/members/\$ref" \
  --body "{\"@odata.id\": \"https://graph.microsoft.com/v1.0/directoryObjects/$SP_OBJECT_ID\"}" \
  --output none 2>/dev/null || warn "Security Administrator may already be assigned — continuing"

success "Security Administrator role assigned"

# ── Step 5: OIDC Federated credentials ───────────────────────────────────────
step "Configuring OIDC federated credentials"

create_federated_credential() {
  local NAME=$1
  local SUBJECT=$2
  info "  Creating credential: $NAME (subject: $SUBJECT)"
  az ad app federated-credential create \
    --id "$APP_CLIENT_ID" \
    --parameters "{
      \"name\": \"$NAME\",
      \"issuer\": \"https://token.actions.githubusercontent.com\",
      \"subject\": \"$SUBJECT\",
      \"audiences\": [\"api://AzureADTokenExchange\"]
    }" \
    --output none
}

create_federated_credential \
  "github-main" \
  "repo:${GITHUB_ORG}/${GITHUB_REPO}:ref:refs/heads/main"

create_federated_credential \
  "github-env-dev" \
  "repo:${GITHUB_ORG}/${GITHUB_REPO}:environment:dev"

create_federated_credential \
  "github-pr" \
  "repo:${GITHUB_ORG}/${GITHUB_REPO}:pull_request"

success "OIDC federated credentials configured"

# ── Step 6: Remote state storage ──────────────────────────────────────────────
step "Creating Terraform remote state storage"

info "  Creating resource group: $RG_NAME"
az group create \
  --name "$RG_NAME" \
  --location "$LOCATION" \
  --output none

info "  Creating storage account: $STORAGE_ACCOUNT"
az storage account create \
  --name "$STORAGE_ACCOUNT" \
  --resource-group "$RG_NAME" \
  --location "$LOCATION" \
  --sku Standard_LRS \
  --encryption-services blob \
  --output none

info "  Creating blob container: $CONTAINER_NAME"
az storage container create \
  --name "$CONTAINER_NAME" \
  --account-name "$STORAGE_ACCOUNT" \
  --output none

STATE_ACCESS_KEY=$(az storage account keys list \
  --resource-group "$RG_NAME" \
  --account-name "$STORAGE_ACCOUNT" \
  --query "[0].value" -o tsv)

success "Remote state storage ready"

# ── Step 7: Key Vault ─────────────────────────────────────────────────────────
step "Creating Key Vault: $KV_NAME"

az keyvault create \
  --name "$KV_NAME" \
  --resource-group "$RG_NAME" \
  --location "$LOCATION" \
  --sku standard \
  --output none

success "Key Vault created"

# ── Step 8: Grant yourself Secrets Officer access ─────────────────────────────
step "Granting your account Key Vault Secrets Officer access"

MY_OBJECT_ID=$(az ad signed-in-user show --query id -o tsv)

az role assignment create \
  --role "Key Vault Secrets Officer" \
  --assignee "$MY_OBJECT_ID" \
  --scope "/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RG_NAME/providers/Microsoft.KeyVault/vaults/$KV_NAME" \
  --output none

info "Waiting 30 seconds for role assignment to propagate..."
sleep 30
success "Secrets Officer access granted"

# ── Step 9: Grant SP Key Vault Secrets User access ────────────────────────────
step "Granting SP Key Vault Secrets User access"

az role assignment create \
  --role "Key Vault Secrets User" \
  --assignee "$APP_CLIENT_ID" \
  --scope "/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RG_NAME/providers/Microsoft.KeyVault/vaults/$KV_NAME" \
  --output none

success "SP Key Vault access granted"

# ── Step 10: Store temp password in Key Vault ─────────────────────────────────
step "Storing temporary user password in Key Vault"
echo ""
warn "Password must be 8+ characters with uppercase, lowercase, number, and special character."
echo ""

while true; do
  read -rsp "  Enter temp password (hidden): " TEMP_PASSWORD
  echo ""
  read -rsp "  Confirm temp password       : " TEMP_PASSWORD_CONFIRM
  echo ""
  if [[ "$TEMP_PASSWORD" == "$TEMP_PASSWORD_CONFIRM" ]]; then
    break
  else
    warn "Passwords do not match — try again."
  fi
done

az keyvault secret set \
  --vault-name "$KV_NAME" \
  --name "user-temp-password" \
  --value "$TEMP_PASSWORD" \
  --query "{name:name, id:id}" \
  -o table

unset TEMP_PASSWORD TEMP_PASSWORD_CONFIRM
success "Password stored in Key Vault"

# ── Step 11: Generate terraform.tfvars ────────────────────────────────────────
step "Generating terraform.tfvars"

cat > terraform.tfvars <<EOF
tenant_id                     = "$TENANT_ID"
subscription_id               = "$SUBSCRIPTION_ID"
tenant_domain                 = "$TENANT_DOMAIN"
company_name                  = "$COMPANY_NAME"
environment                   = "dev"
location                      = "$LOCATION"
alert_email                   = "$ALERT_EMAIL"
log_retention_days            = 30
key_vault_name                = "$KV_NAME"
bootstrap_resource_group_name = "$RG_NAME"
EOF

success "terraform.tfvars written"

# ── Step 12: Update providers.tf backend ──────────────────────────────────────
step "Updating providers.tf with your storage account name"

sed -i "s/storage_account_name = \"tfstateiam\"/storage_account_name = \"$STORAGE_ACCOUNT\"/" providers.tf
success "providers.tf updated"

# ── Done — print GitHub secrets ───────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${GREEN}  Bootstrap complete! Configure these GitHub secrets:   ${NC}"
echo -e "${BOLD}${GREEN}════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  Go to: ${BLUE}https://github.com/$GITHUB_ORG/$GITHUB_REPO/settings/secrets/actions${NC}"
echo ""
echo -e "  ${BOLD}Secret name${NC}                        ${BOLD}Value${NC}"
echo    "  ─────────────────────────────────────────────────────────"
printf  "  %-35s %s\n" "AZURE_CLIENT_ID_DEV"       "$APP_CLIENT_ID"
printf  "  %-35s %s\n" "AZURE_SUBSCRIPTION_ID_DEV" "$SUBSCRIPTION_ID"
printf  "  %-35s %s\n" "AZURE_TENANT_ID_DEV"       "$TENANT_ID"
printf  "  %-35s %s\n" "AZURE_TENANT_DOMAIN_DEV"   "$TENANT_DOMAIN"
printf  "  %-35s %s\n" "TF_STATE_ACCESS_KEY_DEV"   "$STATE_ACCESS_KEY"
printf  "  %-35s %s\n" "ALERT_EMAIL"               "$ALERT_EMAIL"
echo ""
echo -e "  ${BOLD}GitHub Environments:${NC}"
echo    "  Create 'dev' under Settings → Environments (no protection rules needed)"
echo ""
echo -e "  ${BOLD}Next steps:${NC}"
echo    "  1. Add the GitHub secrets above"
echo    "  2. Create the 'dev' environment in GitHub"
echo    "  3. Run: terraform init"
echo    "  4. Run: terraform validate"
echo    "  5. Push to main or trigger a manual workflow dispatch"
echo ""
echo -e "${YELLOW}  Note: SignInLogs alert rules may fail on first deploy.${NC}"
echo -e "${YELLOW}  See README Known Issues for the fix.${NC}"
echo ""