# Contributing

This is a personal learning project but contributions, suggestions, and issue reports are welcome.

---

## Development Setup

### Prerequisites

- Terraform >= 1.6.0
- Azure CLI (latest)
- Python >= 3.10
- jq
- TFLint
- Checkov (`pip install checkov`)

### Local validation (no Azure required)

```bash
terraform init -backend=false
terraform validate
tflint --recursive
checkov -d . --framework terraform
```

### Running against a dev tenant

1. Follow the [Initial Setup](README.md#initial-setup) steps to configure a dev tenant
2. Copy `terraform.tfvars.example` to `terraform.tfvars` and fill in your values
3. Run `terraform plan` to preview changes before applying

---

## Project Structure

```
foundation/     — Run once. Creates resource group + grants SP roles.
modules/
  monitoring/   — Core detection stack. Most active development happens here.
  users/        — Entra ID user provisioning
  groups/       — Department groups
  app_registrations/ — OAuth app registrations
scripts/        — Out-of-band automation (watchlist refresh)
.github/workflows/ — CI/CD pipelines
```

---

## Adding a New Detection Rule

1. Add the rule in `modules/monitoring/main.tf`
2. All rules must:
   - Have `depends_on = [time_sleep.wait_for_sentinel_permissions]`
   - Include `tactics` and `techniques` mapped to valid MITRE ATT&CK IDs (parent format `T####` only — sub-techniques are rejected by the Sentinel API)
   - Include at least one `entity_mapping` block
   - Have a descriptive `description` explaining the threat model, not just what it detects
3. If the rule queries `SignInLogs`, comment it out by default and add a note — the table doesn't exist on fresh deploys. See [Known Issues](KNOWN_ISSUES.md#5-signinlogs-table).
4. Add the rule to the detection rules table in `README.md`
5. Add a corresponding legacy `azurerm_monitor_scheduled_query_rules_alert_v2` for email alerting

---

## Coding Conventions

### Terraform

- Resource naming: `<type>-${var.resource_prefix}-<descriptor>`
- All resources get `managed_by = "terraform"` and `project = "iam-detection-lab"` tags
- Propagation waits use `time_sleep` resources with explicit `depends_on` — never use `triggers` or inline delays
- Comments explain _why_, not _what_ — the code already shows what it does

### KQL

- Use `let` statements for reusable values and subqueries
- Prefer `extend` over inline expressions in `project`
- Always filter on `Result == "success"` or `ResultType == 0` before any other filters — reduces scan cost
- `project` only the columns the entity mappings and analysts actually need

### Python (watchlist script)

- Follow PEP 8
- All API calls wrapped in try/except with meaningful error messages
- Deterministic item keys for idempotent upserts

---

## Pull Request Guidelines

- Keep PRs focused — one detection rule or one change per PR
- Include a brief description of the threat model for any new rule
- Run `terraform validate` and `tflint` locally before pushing
- The pipeline will run Checkov — fix any HIGH/CRITICAL findings before merging

---

## Reporting Issues

Open a GitHub issue with:

- What you were trying to do
- The exact error message
- Whether it's a fresh deploy or an existing environment
- Azure region (some SKUs and behaviours vary by region)

Check [KNOWN_ISSUES.md](KNOWN_ISSUES.md) first — most issues hit during development are documented there.
