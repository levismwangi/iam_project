# Enterprise IAM Project — Microsoft Entra ID + Terraform

An Identity and Access Management solution built on **Microsoft Entra ID**, fully provisioned via **Terraform IaC** with a **GitHub Actions CI/CD pipeline**.

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

### 1. Get a Microsoft Entra ID Tenant

You need a tenant with **Entra ID P2 licence** for PIM and Identity Protection features. Pick whichever option works best for you:

---

#### Option A — Microsoft 365 Developer Program ⭐ Recommended
Free 90-day renewable sandbox with 25 user licences and E5 features included.

1. Sign up at [developer.microsoft.com/microsoft-365/dev-program](https://developer.microsoft.com/microsoft-365/dev-program)
2. Sign in with a personal Microsoft account
3. Choose **Set up E5 subscription**
4. Pick a company name — this becomes your `<name>.onmicrosoft.com` domain
5. Your tenant is ready in ~2 minutes

> Renewals are automatic as long as you show active development activity. If it expires, sign up again with the same account.

---

#### Option B — Microsoft 365 Business Premium Trial
Free 30-day trial with up to 25 users and full Entra ID P2 features.

1. Go to [microsoft.com/en-us/microsoft-365/business/compare-all-plans](https://www.microsoft.com/en-us/microsoft-365/business/compare-all-plans)
2. Select **Microsoft 365 Business Premium → Try free for 1 month**
3. Sign up with a new Microsoft account
4. No credit card required for the trial period

---

#### Option C — Azure Free Account + Entra ID P2 Trial
If you already have an Azure account, activate the Entra ID P2 trial directly.

1. Go to [portal.azure.com](https://portal.azure.com)
2. Navigate to **Entra ID → Licences → All products**
3. Click **Try/Buy → Free trial** on **Entra ID P2**
4. Activates immediately — 30 days free

> Note: PIM and Identity Protection (required for risk-based CA policies) need P2. The free Entra ID tier will deploy most of this project but PIM eligible assignments will fail.

---

#### Option C — Visual Studio Subscription (if you have one)
If you have a Visual Studio Professional or Enterprise subscription, it includes Azure credits and access to Microsoft 365 developer tools.

1. Go to [my.visualstudio.com](https://my.visualstudio.com)
2. Activate your **Azure DevTest** benefit
3. Use the included credits to run this project at no cost

---

#### Licence Requirements Summary

| Feature | Free | P1 | P2 |
|---------|------|----|----|
| Users & Groups | ✅ | ✅ | ✅ |
| App Registrations | ✅ | ✅ | ✅ |
| Conditional Access | ❌ | ✅ | ✅ |
| PIM (JIT Access) | ❌ | ❌ | ✅ |
| Identity Protection (risk policies) | ❌ | ❌ | ✅ |
| Log Analytics + Sentinel | ✅ | ✅ | ✅ |

**TL;DR** — You need at least P2 to deploy this project in full. The M365 Developer Program (Option A) is the easiest way to get it for free.

---

### 2. Find Your Tenant Domain

```bash
az login
az ad signed-in-user show --query "userPrincipalName" -o tsv
# Everything after @ is your tenant domain e.g. contoso.onmicrosoft.com
```

### 3. Grant Your Account the Required Roles

Before running Terraform, make sure your account has these roles assigned in Entra ID:

| Role | Required For |
|------|-------------|
| Global Administrator | Full tenant access |
| Privileged Role Administrator | PIM eligible assignments |
| Conditional Access Administrator | CA policy creation |

Assign via Portal: **Entra ID → Roles and administrators → search role → Add assignments → your account**

> If you skip the Privileged Role Administrator assignment, PIM deployment will fail with a 403 PermissionScopeNotGranted error.

### 4. Create Terraform Remote State Storage

```bash
# Create resource group for state
az group create --name rg-terraform-state --location eastus

# Create storage account (must be globally unique)
az storage account create \
  --name tfstateiam \
  --resource-group rg-terraform-state \
  --sku Standard_LRS \
  --encryption-services blob \
  --min-tls-version TLS1_2 \
  --allow-blob-public-access false

# Create container
az storage container create \
  --name tfstate \
  --account-name tfstateiam
```

### 5. Create and Configure Key Vault

The Key Vault stores the temporary password used for all new users. Terraform reads from it at deploy time so passwords are never hardcoded in the codebase.

#### Create the Key Vault

```bash
# Create the Key Vault (name must be globally unique)
az keyvault create \
  --name kv-iam-<yourname> \
  --resource-group rg-terraform-state \
  --location eastus \
  --sku standard
```

#### Grant yourself access to manage secrets

```bash
# Get your object ID
az ad signed-in-user show --query id -o tsv

# Assign Key Vault Secrets Officer role
az role assignment create \
  --role "Key Vault Secrets Officer" \
  --assignee <your-object-id-from-above> \
  --scope "/subscriptions/<subscription-id>/resourcegroups/rg-terraform-state/providers/Microsoft.KeyVault/vaults/kv-iam-<yourname>"
```

Wait 30 seconds for the role to propagate before proceeding.

#### Store the temporary password

The temp password is assigned to all new users on first login. They are forced to change it immediately so the value only needs to satisfy Azure AD complexity requirements:

- Minimum 8 characters
- Must include uppercase, lowercase, number and special character

Store it without exposing the value in your terminal:

```powershell
# PowerShell — prompts for password securely, suppresses output
$password = Read-Host -AsSecureString "Enter temp password"
$plaintext = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
  [Runtime.InteropServices.Marshal]::SecureStringToBSTR($password)
)
az keyvault secret set `
  --vault-name kv-iam-<yourname> `
  --name "user-temp-password" `
  --value $plaintext `
  --query "{name:name, id:id}" `
  -o table
```

The `--query` flag suppresses the secret value from the output — only the name and ID are printed.

#### Update your terraform.tfvars

After creating the Key Vault, add its name to your `terraform.tfvars`:

```hcl
key_vault_name                = "kv-iam-<yourname>"
bootstrap_resource_group_name = "rg-terraform-state"
```

> Terraform uses these values to look up the Key Vault and read the temp password secret at apply time.

---

### 6. Configure Variables

```bash
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your real tenant values
```

> Make sure `alert_email` is a real email address you own — Azure will reject placeholder addresses when creating the action group.

### 7. Deploy

```bash
terraform init
terraform validate
terraform plan
terraform apply
```

---

## Known Issues & Workarounds

### SignInLogs table not found
Alert rules that query `SignInLogs` will fail on first deploy because the table doesn't exist until sign-in data starts flowing into Log Analytics.

**Fix:**
1. Comment out `signin_outside_trusted` and `impossible_travel` in `modules/monitoring/main.tf`
2. Run `terraform apply` — everything else deploys including diagnostic settings
3. Sign out and back into the Portal with your admin account
4. Wait 10-15 minutes for the first sign-in logs to stream through
5. Verify the table exists: **Log Analytics → Logs → run `SignInLogs | take 5`**
6. Uncomment the two rules and re-run `terraform apply`

### PIM 403 PermissionScopeNotGranted
Terraform cannot create PIM eligible assignments without the **Privileged Role Administrator** role on your account.

**Fix:** Entra ID → Roles and administrators → Privileged Role Administrator → Add assignments → your account → wait 30 seconds → re-run `terraform apply`

### Key Vault Forbidden on secret set
If you get a 403 when setting Key Vault secrets via CLI, your account lacks an access policy or RBAC role on the vault.

**Fix:**
```bash
az role assignment create \
  --role "Key Vault Secrets Officer" \
  --assignee <your-object-id> \
  --scope "/subscriptions/<sub-id>/resourcegroups/<rg>/providers/Microsoft.KeyVault/vaults/<vault-name>"
```

---

## CI/CD Pipeline

The GitHub Actions pipeline has 3 jobs that run in sequence:

| Job | Trigger | What it does |
|-----|---------|-------------|
| `validate` | Every push/PR | fmt check, validate, TFLint, Checkov |
| `plan` | After validate passes | Plans against selected environment, posts diff to PR |
| `apply` | Manual dispatch with `action: apply` | Applies the saved plan after environment approval |

### Required GitHub Secrets

With OIDC there is no `AZURE_CLIENT_SECRET` — credentials are exchanged via a short-lived token at runtime. You only need to store these:

| Secret | Description |
|--------|-------------|
| `AZURE_CLIENT_ID_DEV` | Client ID of the service principal for dev |
| `AZURE_SUBSCRIPTION_ID_DEV` | Dev subscription ID |
| `AZURE_TENANT_ID_DEV` | Dev tenant ID |
| `TF_STATE_ACCESS_KEY_DEV` | Storage account access key for dev state |
| `AZURE_CLIENT_ID_PROD` | Client ID of the service principal for prod |
| `AZURE_SUBSCRIPTION_ID_PROD` | Prod subscription ID |
| `AZURE_TENANT_ID_PROD` | Prod tenant ID |
| `TF_STATE_ACCESS_KEY_PROD` | Storage account access key for prod state |

### Setting Up OIDC

OIDC requires a federated credential on your service principal so Azure trusts tokens issued by GitHub Actions. Run this once per environment:

```bash
# Get your service principal's object ID
$SP_OBJECT_ID = az ad sp show --id <client-id> --query id -o tsv

# Add federated credential for main branch (used by plan + apply)
az ad app federated-credential create \
  --id $SP_OBJECT_ID \
  --parameters '{
    "name": "github-main",
    "issuer": "https://token.actions.githubusercontent.com",
    "subject": "repo:<your-github-username>/<your-repo-name>:ref:refs/heads/main",
    "audiences": ["api://AzureADTokenExchange"]
  }'

# Add federated credential for PRs (used by plan on pull requests)
az ad app federated-credential create \
  --id $SP_OBJECT_ID \
  --parameters '{
    "name": "github-pr",
    "issuer": "https://token.actions.githubusercontent.com",
    "subject": "repo:<your-github-username>/<your-repo-name>:pull_request",
    "audiences": ["api://AzureADTokenExchange"]
  }'

# Add federated credential for the dev environment
az ad app federated-credential create \
  --id $SP_OBJECT_ID \
  --parameters '{
    "name": "github-env-dev",
    "issuer": "https://token.actions.githubusercontent.com",
    "subject": "repo:<your-github-username>/<your-repo-name>:environment:dev",
    "audiences": ["api://AzureADTokenExchange"]
  }'
```

Replace `<your-github-username>` and `<your-repo-name>` with your actual values.

---

## Security Design Decisions

| Decision | Rationale |
|----------|-----------|
| CA policies start in report-only mode in `dev` | Prevents accidental lockout during testing |
| Break-glass group excluded from all CA policies | Ensures emergency access is always available |
| PIM requires MFA + justification on activation | Eliminates standing privileged access |
| App implicit grant disabled | Forces auth code + PKCE — more secure |
| `app_role_assignment_required = true` on SPs | Users cannot self-assign to apps |
| Remote state in Azure Storage | State is encrypted at rest, not stored in Git |
| `terraform.tfvars` in `.gitignore` | Prevents credentials leaking to Git |

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
- GitHub Actions CI/CD with environment approvals
- Security scanning (Checkov, TFLint)