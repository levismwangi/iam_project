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

### 3. Create Terraform Remote State Storage

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

### 4. Configure Variables

```bash
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your real tenant values
```

### 5. Deploy

```bash
terraform init
terraform validate
terraform plan
terraform apply
```

---

## CI/CD Pipeline

The GitHub Actions pipeline has 5 jobs:

| Job | Trigger | What it does |
|-----|---------|-------------|
| `validate` | Every push/PR | fmt check, validate, TFLint, Checkov |
| `plan-dev` | Every PR | Plans against dev, posts diff to PR |
| `apply-dev` | Push to `main` | Auto-applies to dev environment |
| `plan-prod` | Manual dispatch | Plans against prod |
| `apply-prod` | Manual dispatch + approval | Applies to prod after reviewer approves |

### Required GitHub Secrets

| Secret | Description |
|--------|-------------|
| `AZURE_CLIENT_ID` | Service principal client ID |
| `AZURE_CLIENT_SECRET` | Service principal secret |
| `AZURE_SUBSCRIPTION_ID` | Subscription ID |
| `AZURE_TENANT_ID` | Tenant ID |
| `TF_STATE_ACCESS_KEY` | Storage account access key for state |
| `TENANT_DOMAIN` | e.g. contoso.onmicrosoft.com |
| `ALERT_EMAIL` | Security alert destination email |

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
