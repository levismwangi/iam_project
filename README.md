# Entra ID Cloud Threat Detection Lab — Terraform + Microsoft Sentinel

A project exploring **Microsoft Entra ID identity telemetry and threat detection**, provisioned via **Terraform IaC** with a **GitHub Actions CI/CD pipeline**.

> **Status: work in progress.** This is a personal lab, not a production security stack. Some detection rules are deployed but have not been validated end-to-end yet (see [Current Status & Limitations](#current-status--limitations)). Treat the KQL and architecture as a learning exercise, not a hardened reference design.

## About This Project

This is a **Log Analytics + Microsoft Sentinel threat-detection lab** built on top of Entra ID Users, Groups, and App Registrations in a free-tier tenant. Entra ID diagnostic settings stream audit and sign-in data into a Log Analytics workspace, which Sentinel is onboarded onto to run scheduled KQL detection rules covering things like privilege escalation, bulk deletions, OAuth consent phishing, and Primary Refresh Token (PRT) theft — with entity mapping, MITRE ATT&CK tagging, a watchlist-backed detection, and a SOAR playbook stub. Everything is provisioned through Terraform with a GitHub Actions CI/CD pipeline (OIDC auth, environment approval gates, drift detection, a separate destroy workflow, and a scheduled watchlist-refresh job).

## Architecture Overview

```mermaid
flowchart TB
    subgraph Tenant["Microsoft Entra ID Tenant (free tier)"]
        Users["Users\n5 seeded accounts"]
        Groups["Groups\n4 departments"]
        Apps["App Registrations\n3 apps"]
    end

    Tenant -->|Diagnostic Settings| LA["Log Analytics Workspace"]
    LA --> Sentinel["Microsoft Sentinel"]

    Sentinel --> Alert1["New admin role assignment"]
    Sentinel --> Alert2["Bulk user deletion (3+ in 5 min)"]
    Sentinel --> Alert3["Illicit OAuth consent grant"]
    Sentinel --> Alert4["New MFA method registered"]
    Sentinel --> Alert5["PRT theft / replay (composite score)"]
    Sentinel -.->|dormant, requires P2 license| Alert6["CA policy modified"]
    Sentinel -.->|dormant, requires P2 license| Alert7["PIM activation outside hours"]

    Sentinel --> Playbook["Logic App playbook\nauto-disable compromised user"]

    style Tenant fill:#e8f0fe,stroke:#4285f4
    style LA fill:#e6f4ea,stroke:#34a853
    style Sentinel fill:#fce8e6,stroke:#ea4335
```

### CI/CD Flow

Four separate workflow files, each with its own trigger and blast radius — deliberately not one mega-pipeline.

```mermaid
flowchart LR
    subgraph Foundation["bootstrap.yml — foundation (run once, separate state)"]
        FTrigger["Manual dispatch\naction=apply"] --> FTF["foundation/ terraform\nRG + Sentinel Contributor role"]
    end

    subgraph Main["terraform.yml — main pipeline"]
        Dev["Developer pushes\nto branch"] --> PR["Pull Request"]
        PR --> Validate["validate job\nfmt · validate · TFLint · Checkov"]
        Validate --> Plan["plan job\nposts diff as PR comment"]
        Plan --> Review["Code review\n+ plan review"]
        Review --> Merge["Merge to main"]
        Merge --> Dispatch["Manual dispatch\naction=apply"]
        Dispatch --> Gate{"GitHub Environment\napproval gate"}
        Gate -->|dev: no approval needed| ApplyDev["Apply to dev"]
        Gate -->|prod: required reviewer| ApplyProd["Apply to prod"]
    end

    subgraph Destroy["destroy.yml — standalone destroy"]
        DestroyTrigger["Manual dispatch\ndestroy.yml"] --> Confirm["confirm job\ntype 'destroy'"]
        Confirm --> DestroyGate{"GitHub Environment\napproval gate"}
        DestroyGate -->|dev| DestroyDev["Destroy dev"]
        DestroyGate -->|prod: required reviewer| DestroyProd["Destroy prod"]
    end

    subgraph Watchlist["watchlist-refresh.yml — daily baseline refresh"]
        WSchedule["Cron 03:00 UTC\nor manual dispatch"] --> WScript["refresh_prt_watchlist.py\nqueries 30d of sign-ins"]
        WScript --> WUpsert["Upserts items into\nKnownUserAppDevice watchlist\nvia REST API"]
    end

    Foundation -.->|must run before first apply| Main

    style Gate fill:#fef7e0,stroke:#f9ab00
    style ApplyProd fill:#fce8e6,stroke:#ea4335
    style DestroyGate fill:#fef7e0,stroke:#f9ab00
    style DestroyProd fill:#fce8e6,stroke:#ea4335
    style Confirm fill:#fce8e6,stroke:#ea4335
```

---

## Current Status & Limitations

This is an active, unfinished lab. Please read this section before assuming any of the detections below actually work end-to-end.

| Component | Status |
|---|---|
| Users / Groups / App Registrations | Deployed, working |
| Log Analytics + Entra diagnostic settings | Deployed, working |
| Sentinel onboarding | Deployed, working |
| New admin role assignment rule | Deployed, appears to fire correctly |
| Bulk user deletion rule | Deployed, appears to fire correctly |
| New MFA registration rule | Deployed, appears to fire correctly |
| **Illicit OAuth consent grant rule** | Deployed, **not yet validated with a real test consent grant** |
| **PRT theft / replay composite-score rule** | Deployed, **not yet validated** — depends on the watchlist baseline being populated by `watchlist-refresh.yml` at least once, and the whole scoring logic needs a real (or simulated) non-interactive sign-in to test against |
| CA policy modified rule | Present in code, but **dormant** — requires Entra ID P2 (Conditional Access), which I don't have for this project |
| PIM activation outside hours rule | Present in code, but **dormant** — requires Entra ID P2 (PIM), which I don't have for this project |
| PIM module | Written but **disabled** — requires Entra ID P2, which I don't have for this project |
| Conditional Access module | Written but **disabled** — requires Entra ID P2, which I don't have for this project |
| Logic App SOAR playbook | Deployed (workflow shell + Sentinel Responder role), the actual disable-user logic inside it is minimal/not fleshed out |

In short: the parts of this project I'm actually claiming as "working" right now are the Sentinel plumbing (Log Analytics, diagnostic settings, onboarding) and three of the simpler detection rules. The OAuth consent and PRT rules are the more interesting/complex pieces but are still pending tests, and the CA/PIM-dependent rules are dead code until I have a license to properly exercise them.

---

## Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Terraform CLI | >= 1.6.0 | IaC engine |
| Azure CLI | Latest | Authentication |
| Git | Any | Version control |
| jq | Any | Required by bootstrap script |
| Python 3 | Any | Required by `scripts/refresh_prt_watchlist.py` |
| VS Code + HCL extension | Any | IDE |

A free/standard Entra ID tenant (no P2 license) is sufficient for everything currently deployed. You do **not** need Entra ID P2, M365 E5, or the M365 Developer Program sandbox unless you want to re-enable and test the PIM/Conditional Access modules yourself.

---

## Initial Setup

### Option A — Bootstrap script (recommended)

A `bootstrap.sh` script is included in the repo root that automates all manual setup steps. Run it once before `terraform init`.

```bash
chmod +x bootstrap.sh
./bootstrap.sh
```

The script will prompt for:
- Tenant ID and Subscription ID
- Tenant domain (e.g. `contoso.onmicrosoft.com`)
- Company / project name
- GitHub org and repo name
- Azure region
- Alert email

It then handles everything in order:
1. Creates the Service Principal with Contributor role
2. Grants the required Microsoft Graph API permissions and admin consent
3. Assigns the Security Administrator role to the SP
4. Configures OIDC federated credentials (main, dev environment, PR)
5. Creates the remote state resource group, storage account, and container
6. Creates the Key Vault and grants your account Secrets Officer access
7. Grants the SP Key Vault Secrets User access
8. Prompts for the temporary user password and stores it in Key Vault
9. Generates `terraform.tfvars` automatically
10. Patches `providers.tf` with your storage account name
11. Prints all required GitHub secrets with their values

At the end, copy the printed secrets into **GitHub → Settings → Secrets → Actions**, then proceed to [Deploy](#deploy).

---

### Option B — Manual setup

If you prefer to run the steps yourself, follow the sections below.

#### 1. Create a Service Principal for Terraform

```bash
az login --tenant <your-tenant-id>

az ad sp create-for-rbac \
  --name "sp-terraform-iam" \
  --role "Contributor" \
  --scopes "/subscriptions/<subscription-id>"
```

Grant the SP these **Microsoft Graph API permissions** (App registrations → API permissions → Grant admin consent):

| Permission | Purpose |
|---|---|
| `Application.ReadWrite.All` | Create/manage app registrations and service principals |
| `Directory.ReadWrite.All` | Manage users, groups, and directory objects |
| `RoleManagement.ReadWrite.Directory` | Assign Entra ID roles (used for the Sentinel-related role assignments) |
| `User.ReadWrite.All` | Create, update, and delete user accounts |

> **Important:** All Graph API permissions require **admin consent** — granting the permission alone is not sufficient. Without consent, Terraform apply will fail with `Authorization_RequestDenied (403)`.

> **Note:** Use `Application.ReadWrite.All` and not `Application.ReadWrite.OwnedBy` — the narrower permission does not allow creating service principals or managing app passwords, which will cause 403 errors on `azuread_service_principal` and `azuread_application_password` resources.

> **Note:** `User.ReadWrite.All` is required for `terraform destroy` — without it the pipeline will fail with 403 when attempting to delete Entra ID users, even if apply succeeds.

Also assign the SP the **Security Administrator** Entra ID role to allow managing diagnostic settings:

1. Go to **Microsoft Entra ID** → **Roles and administrators**
2. Search for **Security Administrator** → **Add assignments** → select your SP

> This is required for the `azurerm_monitor_aad_diagnostic_setting` resource. Diagnostic settings for Entra ID live outside normal subscription scope and cannot be managed with Azure RBAC roles alone.

---

#### 2. Configure OIDC Federated Identity (No Client Secrets)

This project uses **OIDC (Workload Identity Federation)** — GitHub exchanges a short-lived JWT with Azure on every run. No client secrets are stored anywhere.

```bash
az ad app federated-credential create --id <APP_CLIENT_ID> --parameters '{
  "name": "github-main",
  "issuer": "https://token.actions.githubusercontent.com",
  "subject": "repo:<org>/<repo>:ref:refs/heads/main",
  "audiences": ["api://AzureADTokenExchange"]
}'

az ad app federated-credential create --id <APP_CLIENT_ID> --parameters '{
  "name": "github-env-dev",
  "issuer": "https://token.actions.githubusercontent.com",
  "subject": "repo:<org>/<repo>:environment:dev",
  "audiences": ["api://AzureADTokenExchange"]
}'

az ad app federated-credential create --id <APP_CLIENT_ID> --parameters '{
  "name": "github-pr",
  "issuer": "https://token.actions.githubusercontent.com",
  "subject": "repo:<org>/<repo>:pull_request",
  "audiences": ["api://AzureADTokenExchange"]
}'
```

---

#### 3. Create Remote State Storage

```bash
az group create --name rg-terraform-state --location <region>

az storage account create \
  --name tfstateiam \
  --resource-group rg-terraform-state \
  --location <region> \
  --sku Standard_LRS \
  --encryption-services blob

az storage container create \
  --name tfstate \
  --account-name tfstateiam
```

---

#### 4. Create Key Vault and Store Temp Password

```bash
az keyvault create \
  --name kv-iam-<yourname> \
  --resource-group rg-terraform-state \
  --location eastus \
  --sku standard

# Grant yourself Secrets Officer access
az role assignment create \
  --role "Key Vault Secrets Officer" \
  --assignee <your-object-id> \
  --scope "/subscriptions/<subscription-id>/resourcegroups/rg-terraform-state/providers/Microsoft.KeyVault/vaults/kv-iam-<yourname>"
```

Wait 30 seconds for the role to propagate, then store the password:

```bash
az keyvault secret set \
  --vault-name kv-iam-<yourname> \
  --name "user-temp-password" \
  --value "<your-temp-password>" \
  --query "{name:name, id:id}" \
  -o table
```

Grant the SP read access to the vault:

```bash
az role assignment create \
  --role "Key Vault Secrets User" \
  --assignee <APP_CLIENT_ID> \
  --scope "/subscriptions/<SUBSCRIPTION_ID>/resourceGroups/rg-terraform-state/providers/Microsoft.KeyVault/vaults/kv-iam-<yourname>"
```

---

#### 5. Configure Variables

```bash
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your tenant values
```

> Make sure `alert_email` is a real email address you own — Azure will reject placeholder addresses when creating the action group.

---

## Deploy

```bash
terraform init
terraform validate
terraform plan
terraform apply
```

---

## Known Issues & Workarounds

### AuthorizationFailed on azurerm_role_assignment (bootstrap.yml)
The `bootstrap.yml` foundation pipeline fails with a 403 `AuthorizationFailed` on `Microsoft.Authorization/roleAssignments/write` if the Terraform SP doesn't already hold a **Role Based Access Control Administrator** assignment on the subscription.

**Fix:** A human with Owner or User Access Administrator rights needs to grant the SP a condition-constrained RBAC Administrator role once, up front — scoped so the SP can only assign the two roles the foundation module needs (Sentinel Contributor and, indirectly, itself), never Owner. `bootstrap.sh` (Option A setup) does this automatically; if you're doing manual setup, this step has to happen before the first `bootstrap.yml` run.

### PRT replay rule needs the watchlist populated first
The `prt_replay_detection` rule explicitly suppresses all findings until the `KnownUserAppDevice` watchlist has at least one item (to avoid every sign-in scoring a false +2 on a cold-start empty baseline). Run `.github/workflows/watchlist-refresh.yml` manually at least once after deploying the monitoring module, before expecting this rule to produce anything.

### Illicit consent grant and PRT rules — untested
Both rules are deployed and syntactically valid, but I haven't yet generated a real (or safely simulated) test event for either — a genuine high-privilege OAuth consent grant, or a non-interactive sign-in pattern matching the PRT composite score. Until that's done, treat both as "should work based on the KQL logic" rather than "verified working."

### Key Vault Forbidden on secret set
If you get a 403 when setting Key Vault secrets via CLI, your account lacks an access policy or RBAC role on the vault.

**Fix:**
```bash
az role assignment create \
  --role "Key Vault Secrets Officer" \
  --assignee <your-object-id> \
  --scope "/subscriptions/<sub-id>/resourcegroups/<rg>/providers/Microsoft.KeyVault/vaults/<vault-name>"
```

### 403 on destroy — user deletion fails
If `terraform destroy` fails with `Authorization_RequestDenied` when deleting Entra ID users, the SP is missing `User.ReadWrite.All`.

**Fix:** Entra ID → App registrations → your SP → API permissions → Add `User.ReadWrite.All` (Application) → Grant admin consent → re-run destroy.

---

## CI/CD Pipeline

The project uses four workflow files under `.github/workflows/`, each scoped to a different job:

### `bootstrap.yml` — foundation pipeline

Runs the `foundation/` root module, which has its own state file (`foundation.terraform.tfstate`), separate from the main pipeline's state. It creates the IAM resource group and grants the Terraform SP the **Microsoft Sentinel Contributor** role on that resource group — a prerequisite the main pipeline needs before it can create Sentinel analytics rules.

Manual dispatch only — never runs automatically. Needs to be run:
- The first time you set up a new environment
- Any time `terraform destroy` wipes the IAM resource group and you need to recreate it

This pipeline itself depends on the Terraform SP already holding a condition-constrained **Role Based Access Control Administrator** assignment on the subscription, granted once by a human with Owner/User Access Administrator rights (`bootstrap.sh` does this automatically). The condition restricts the SP to assigning only two specific roles, so it can never self-escalate to Owner. Without that pre-existing assignment, this pipeline fails with a 403 on `Microsoft.Authorization/roleAssignments/write`.

**Run order:** `bootstrap.yml` first, then `terraform.yml` with `action=apply`.

### `terraform.yml` — main pipeline

| Job | Trigger | What it does |
|-----|---------|-------------|
| `validate` | Every push/PR | `fmt` check, `validate`, TFLint, Checkov security scan |
| `plan` | Every push/PR + manual dispatch | Plans against target environment, posts diff as PR comment |
| `apply` | Manual dispatch (`action=apply`) | Applies the saved plan after environment approval gate |

A nightly scheduled run (02:00 UTC) runs `plan` against prod in read-only mode to detect drift — any difference between live infrastructure and Terraform state is flagged as a warning in the Actions log.

### `destroy.yml` — standalone destroy pipeline

Kept intentionally separate from the main pipeline to reduce the risk of accidental invocation. Only triggered manually via `workflow_dispatch`.

**Two-layer protection before anything is deleted:**
1. A `confirm` job that fails immediately if the input field doesn't contain the word `destroy` exactly
2. The GitHub Environment approval gate, which requires a designated reviewer to approve before the destroy job runs

To invoke: **Actions → Terraform Destroy → Run workflow → select environment → type `destroy` → Run workflow**

> The destroy workflow shares the same concurrency group as the main pipeline (`terraform-<environment>`), so a running apply will block a destroy and vice versa.

### `watchlist-refresh.yml` — PRT baseline refresh

Runs daily (03:00 UTC) and on manual dispatch. Queries the last 30 days of sign-in logs for `UserPrincipalName + AppId + DeviceId` combinations and upserts them into the `KnownUserAppDevice` Sentinel watchlist via `scripts/refresh_prt_watchlist.py`. Kept outside the main Terraform pipeline because it manages watchlist *items*, not Terraform-managed resource state.

### Required GitHub Secrets

| Secret | Description |
|--------|-------------|
| `AZURE_CLIENT_ID_DEV` | App registration client ID (DEV) |
| `AZURE_SUBSCRIPTION_ID_DEV` | Subscription ID (DEV) |
| `AZURE_TENANT_ID_DEV` | Tenant ID (DEV) |
| `AZURE_TENANT_DOMAIN_DEV` | e.g. `contoso.onmicrosoft.com` (DEV) |
| `TF_STATE_ACCESS_KEY_DEV` | Storage account access key for state (DEV) |
| `ALERT_EMAIL` | Email address for Azure Monitor action group alerts |

> `AZURE_CLIENT_SECRET` is intentionally absent — OIDC eliminates the need for it.

> If you used `bootstrap.sh`, all secret values are printed at the end of the script — no need to look them up manually.

### Setting Up GitHub Environments

Go to **GitHub repo → Settings → Environments → New environment:**

- Create `dev` — no protection rules needed
- Create `prod` — add **Required reviewers** (add yourself) so prod requires manual approval before applying or destroying

---

## Security Design Decisions

| Decision | Rationale |
|----------|-----------|
| OIDC instead of client secrets | Short-lived tokens — no long-lived credentials stored in GitHub |
| Remote state in Azure Storage | State is encrypted at rest, not stored in Git |
| `terraform.tfvars` in `.gitignore` | Prevents credentials leaking to Git |
| Key Vault Secrets User (not Owner) on SP | Least-privilege — read-only access to secrets |
| Passwords stored in Key Vault | Never hardcoded — fetched at apply time, marked sensitive |
| Destroy in a separate workflow file | Reduces accidental invocation risk; requires typed confirmation + approval gate |
| PRT watchlist refresh kept outside Terraform | Terraform can't safely own append-only watchlist item content — see comment in `modules/monitoring/main.tf` |

---

## Monitoring — Detection Rule Summary

| Rule | Severity | Detection Window | Status |
|------|----------|-------------------|--------|
| New admin role assignment | Medium | Immediate | Deployed |
| Bulk user deletion (3+) | High | 5 min | Deployed |
| New MFA method registered | Low | Immediate | Deployed |
| Illicit OAuth consent grant (high-privilege scopes) | High | 1 hr | Deployed, **pending test with a real consent event** |
| PRT theft / replay (composite score) | High | 1 hr | Deployed, **pending test — also needs watchlist populated first** |
| CA policy modified/deleted | Medium | Immediate | In code, dormant (no CA policies in this tenant) |
| PIM activation outside hours | Medium | Immediate | In code, dormant (PIM module disabled) |

All rules are provisioned via the monitoring module (`azurerm_sentinel_alert_rule_scheduled`) and run KQL queries on a defined cadence against the Log Analytics workspace. Full definitions, MITRE ATT&CK tagging, and detection-logic writeups are in `modules/monitoring/main.tf`.

---

## What's Actually Demonstrated Here

- Terraform modular IaC with remote state, targeting Microsoft Entra ID + Azure Monitor/Sentinel
- KQL query writing for identity threat detection, including a multi-signal composite-scoring rule (PRT replay)
- Microsoft Sentinel SIEM integration: workspace onboarding, scheduled analytics rules, entity mapping, MITRE ATT&CK tagging, watchlists
- GitHub Actions CI/CD with OIDC Workload Identity Federation, environment approval gates, and a scheduled data-refresh job outside the main IaC pipeline
- Security scanning in CI (Checkov, TFLint)
- Working around real licensing constraints (P2-gated features) by scoping down to what's actually testable, rather than building against services I can't verify

This is a learning project — not a claim of production security engineering experience. Several detection rules are still unverified and the PIM/Conditional Access modules are unused code kept for reference, not working features.
