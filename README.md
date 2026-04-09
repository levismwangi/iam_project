# Enterprise IAM Project — Microsoft Entra ID + Terraform

A production-grade Identity and Access Management solution built on **Microsoft Entra ID**, fully provisioned via **Terraform IaC** with a **GitHub Actions CI/CD pipeline**.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                  Microsoft Entra ID Tenant               │
│                                                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────┐  │
│  │  Users   │  │  Groups  │  │   Apps   │  │  PIM   │  │
│  │ (5 dept) │  │(4 depts) │  │(3 apps)  │  │  JIT   │  │
│  └──────────┘  └──────────┘  └──────────┘  └────────┘  │
│                                                          │
│  ┌─────────────────────────────────────────────────────┐ │
│  │           Conditional Access Policies (7)            │ │
│  │  CA001 Block Legacy  │  CA002 MFA Admins            │ │
│  │  CA003 MFA All Users │  CA004 Risky Locations       │ │
│  │  CA005 Risky Sign-in │  CA006 Password Change       │ │
│  │  CA007 Unknown Platform                             │ │
│  └─────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼ Diagnostic Settings
┌─────────────────────────────────────────────────────────┐
│              Log Analytics Workspace + Sentinel          │
│                                                          │
│  Alert Rules:                                            │
│  • New admin role assignment                             │
│  • Bulk user deletion (3+ in 5 min)                     │
│  • Conditional Access policy modified                    │
│  • Sign-in outside trusted location                      │
│  • New MFA method registered                             │
│  • PIM activation outside business hours                 │
│  • Impossible travel (Sentinel)                          │
└─────────────────────────────────────────────────────────┘
```

---

## Project Structure

```
iam-project/
├── .github/
│   └── workflows/
│       └── terraform.yml          # CI/CD pipeline
├── modules/
│   ├── users/                     # Entra ID user provisioning
│   ├── groups/                    # Department security groups
│   ├── conditional_access/        # 7 CA policies
│   ├── pim/                       # JIT role assignments + policies
│   ├── app_registrations/         # App registrations + SSO + RBAC
│   └── monitoring/                # Log Analytics + Sentinel + Alerts
├── main.tf                        # Root module — wires everything together
├── variables.tf                   # All input variable definitions
├── outputs.tf                     # All output definitions
├── providers.tf                   # Provider + backend configuration
├── terraform.tfvars.example       # Variable file template
└── .gitignore
```

---

## Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Terraform CLI | >= 1.6.0 | IaC engine |
| Azure CLI | Latest | Authentication |
| Git | Any | Version control |
| VS Code + HCL extension | Any | IDE |

---

## Initial Setup

### 1. Create a Microsoft 365 Developer Tenant
Sign up at [developer.microsoft.com/microsoft-365/dev-program](https://developer.microsoft.com/microsoft-365/dev-program) — free 90-day renewable sandbox.

### 2. Create a Service Principal for Terraform

```bash
# Login to Azure CLI
az login --tenant <your-tenant-id>

# Create service principal with required permissions
az ad sp create-for-rbac \
  --name "sp-terraform-iam" \
  --role "Contributor" \
  --scopes "/subscriptions/<subscription-id>"
```

Then grant the service principal these **Entra ID API permissions** (App registrations → API permissions):
- `Directory.ReadWrite.All`
- `Policy.ReadWrite.ConditionalAccess`
- `RoleManagement.ReadWrite.Directory`
- `PrivilegedAccess.ReadWrite.AzureAD`

### 3. Configure OIDC Federated Identity (No Client Secrets)

This project uses **OIDC (Workload Identity Federation)** instead of long-lived client secrets. GitHub exchanges a short-lived JWT with Azure on every run — nothing sensitive is stored.

#### Create federated credentials for your app registration

Use JSON files to avoid PowerShell quoting issues:

```powershell
# Create JSON files
'{"name":"github-main","issuer":"https://token.actions.githubusercontent.com","subject":"repo:<org>/<repo>:ref:refs/heads/main","audiences":["api://AzureADTokenExchange"]}' | Out-File github-main.json
'{"name":"github-env-dev","issuer":"https://token.actions.githubusercontent.com","subject":"repo:<org>/<repo>:environment:dev","audiences":["api://AzureADTokenExchange"]}' | Out-File github-env-dev.json
'{"name":"github-pr","issuer":"https://token.actions.githubusercontent.com","subject":"repo:<org>/<repo>:pull_request","audiences":["api://AzureADTokenExchange"]}' | Out-File github-pr.json

# Register them
az ad app federated-credential create --id <APP_CLIENT_ID> --parameters github-main.json
az ad app federated-credential create --id <APP_CLIENT_ID> --parameters github-env-dev.json
az ad app federated-credential create --id <APP_CLIENT_ID> --parameters github-pr.json
```

> **Important:** Use the exact GitHub repo name (case-sensitive) in the subject claim. You can verify what subject GitHub sends by checking the `Azure Login` step logs in a failed run — line 20 shows the exact subject string.

Each subject covers a different trigger type:

| Credential | Subject | Covers |
|---|---|---|
| `github-main` | `repo:<org>/<repo>:ref:refs/heads/main` | Push to main |
| `github-env-dev` | `repo:<org>/<repo>:environment:dev` | `workflow_dispatch` targeting dev |
| `github-pr` | `repo:<org>/<repo>:pull_request` | Pull requests |

#### Configure providers.tf to use OIDC

```hcl
provider "azurerm" {
  features {}
  use_oidc = true
}

provider "azuread" {
  use_oidc = true
}
```

### 4. Grant Key Vault Access to the Service Principal

The SP needs permission to read secrets from Key Vault at plan/apply time:

```bash
az role assignment create \
  --role "Key Vault Secrets User" \
  --assignee <APP_CLIENT_ID> \
  --scope "/subscriptions/<SUBSCRIPTION_ID>/resourceGroups/<RG_NAME>/providers/Microsoft.KeyVault/vaults/<VAULT_NAME>"
```

> Role assignments can take 1–2 minutes to propagate in Azure. Wait before re-running the pipeline if you get a 403 immediately after granting access.

### 5. Create Terraform Remote State Storage

```bash
# Create resource group for state
az group create --name rg-terraform-state --location eastus

# Create storage account
az storage account create \
  --name tfstateiam \
  --resource-group rg-terraform-state \
  --sku Standard_LRS \
  --encryption-services blob

# Create container
az storage container create \
  --name tfstate \
  --account-name tfstateiam
```

### 6. Configure Variables

```bash
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your real tenant values
```

### 7. Deploy

```bash
terraform init
terraform validate
terraform plan
terraform apply
```

---

## CI/CD Pipeline

The GitHub Actions pipeline has 3 jobs:

| Job | Trigger | What it does |
|-----|---------|-------------|
| `validate` | Every push/PR | fmt check, validate, TFLint, Checkov |
| `plan` | Every push/PR + manual dispatch | Plans against target environment, posts diff to PR |
| `apply` | Manual dispatch (`action=apply`) | Applies the saved plan after environment approval |

### Required GitHub Secrets

No client secrets are stored — OIDC is used for Azure authentication.

| Secret | Description |
|--------|-------------|
| `AZURE_CLIENT_ID_DEV` | App registration client ID (DEV) |
| `AZURE_SUBSCRIPTION_ID_DEV` | Subscription ID (DEV) |
| `AZURE_TENANT_ID_DEV` | Tenant ID (DEV) |
| `AZURE_TENANT_DOMAIN_DEV` | e.g. contoso.onmicrosoft.com (DEV) |
| `TF_STATE_ACCESS_KEY_DEV` | Storage account access key for state (DEV) |
| `AZURE_CLIENT_ID_PROD` | App registration client ID (PROD) |
| `AZURE_SUBSCRIPTION_ID_PROD` | Subscription ID (PROD) |
| `AZURE_TENANT_ID_PROD` | Tenant ID (PROD) |
| `AZURE_TENANT_DOMAIN_PROD` | e.g. contoso.onmicrosoft.com (PROD) |
| `TF_STATE_ACCESS_KEY_PROD` | Storage account access key for state (PROD) |

> `AZURE_CLIENT_SECRET` is intentionally absent — OIDC eliminates the need for it.

---

## Security Design Decisions

| Decision | Rationale |
|----------|-----------|
| OIDC instead of client secrets | Short-lived tokens — no long-lived credentials stored in GitHub |
| CA policies start in report-only mode in `dev` | Prevents accidental lockout during testing |
| Break-glass group excluded from all CA policies | Ensures emergency access is always available |
| PIM requires MFA + justification on activation | Eliminates standing privileged access |
| App implicit grant disabled | Forces auth code + PKCE — more secure |
| `app_role_assignment_required = true` on SPs | Users cannot self-assign to apps |
| Remote state in Azure Storage | State is encrypted at rest, not stored in Git |
| `terraform.tfvars` in `.gitignore` | Prevents credentials leaking to Git |
| Key Vault Secrets User (not Owner) on SP | Least-privilege — read-only access to secrets |

---

## Monitoring — Alert Summary

| Alert | Severity | Detection |
|-------|----------|-----------|
| New admin role assignment | Medium | Immediate |
| Bulk user deletion (3+) | High | 5 min window |
| CA policy modified/deleted | Medium | Immediate |
| Sign-in from risky location | Low | 15 min window |
| New MFA method registered | Low | Immediate |
| PIM activation outside hours | Medium | Immediate |
| Impossible travel | High | 1 hr window (Sentinel) |

---

## Skills Demonstrated

- Microsoft Entra ID (users, groups, apps, CA, PIM)
- Terraform modular IaC with remote state
- Zero-trust security design
- Just-in-time privileged access (PIM)
- KQL query writing for threat detection
- Microsoft Sentinel SIEM integration
- GitHub Actions CI/CD with OIDC Workload Identity Federation
- Security scanning (Checkov, TFLint)