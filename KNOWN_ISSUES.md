# Known Issues & Workarounds

Real issues hit during the build of this project, documented so you don't spend hours debugging the same things.

---

## 1. `azurerm_monitor_aad_diagnostic_setting` — Provider Inconsistency on First Deploy

**Error:**
```
Provider produced inconsistent result after apply
Root object was present, but now absent.
```

**What happened:**
Azure's API reports the diagnostic setting as created successfully, but when Terraform immediately reads it back to populate state, Entra ID's control plane hasn't finished propagating it. Terraform sees a discrepancy between "you told me this exists" and "now it doesn't" and errors out defensively.

**Fix:**
Re-run `terraform apply`. The resource was actually created on Azure's side — the import will either find it or Terraform will reconcile state cleanly on retry.

If the second run fails with "resource already exists", import it manually:
```bash
terraform import module.monitoring.azurerm_monitor_aad_diagnostic_setting.this \
  /providers/Microsoft.AADIAM/diagnosticSettings/diag-<prefix>-entra-to-law
```

**Root cause:** Known provider flakiness with Entra ID tenant-level resources — they sit outside normal ARM propagation and have slower, less predictable consistency timing. Tracked in hashicorp/terraform-provider-azurerm.

---

## 2. Sentinel Rules — 401 Unauthorized on First Deploy

**Error:**
```
unexpected status 401 (401 Unauthorized) with error: Unauthorized:
Make sure you have the necessary permissions on all the workspaces in your query.
```

**What happened:**
The Terraform SP has Sentinel Contributor assigned at the resource group level (by the foundation module). Azure propagates RBAC from parent to child resources asynchronously. Terraform creates the Log Analytics workspace and immediately tries to create Sentinel rules against it — before the Sentinel Contributor role has propagated to the workspace child resource.

**Fix:**
The `time_sleep.wait_for_sentinel_permissions` resource in `modules/monitoring/main.tf` handles this. On a fresh deploy the wait is set to 300 seconds. On subsequent applies (workspace already exists) the sleep is skipped.

If you still hit 401s after a destroy/recreate, increase `create_duration` in `time_sleep.wait_for_sentinel_permissions`.

---

## 3. Logic App Role Assignment — 403 on Managed Identity

**Error:**
```
StatusCode=403 AuthorizationFailed: does not have authorization to perform action
'Microsoft.Authorization/roleAssignments/write'
```

**What happened:**
The `time_sleep.wait_for_logic_app_identity` resource waits for the Logic App's system-assigned managed identity to propagate in Entra ID before assigning the Sentinel Responder role to it. If the wait isn't long enough, the role assignment call arrives before the identity is fully provisioned — Azure returns a misleading 403 instead of a clearer "principal not found".

**Fix:**
The sleep is set to 120 seconds. If you still hit this on a fresh deploy, re-run apply — the Logic App and its identity already exist in state, so Terraform skips creating them and goes straight to the role assignment, by which point the identity has had time to propagate.

---

## 4. RBAC Administrator ABAC Condition — Fails at Child Resource Scope

**Error:**
```
has an authorization with ABAC condition that is not fulfilled to perform action
'Microsoft.Authorization/roleAssignments/write'
```

**What happened:**
An ABAC condition was added to the RBAC Administrator role assignment constraining it to only assign Microsoft Sentinel Responder to ServicePrincipal/ManagedIdentity types. This worked at the resource group scope but failed when Terraform tried to create the role assignment at the Log Analytics workspace scope (a child resource) — Azure's condition evaluation engine evaluates the condition at the exact scope of the action, and the condition reference to `@Request[...RoleDefinitionId]` doesn't resolve correctly across scope inheritance boundaries.

**Fix:**
The RBAC Administrator assignment is granted at subscription scope without a condition. The SP's blast radius is already constrained by its other role assignments (Contributor + Sentinel Contributor only). The Logic App's Terraform resource itself hardcodes Sentinel Responder as the role being assigned, so the unconstrained RBAC Admin is acceptable in practice.

**Production recommendation:** Use a separate automation account with tightly scoped permissions for role assignment operations, rather than the same SP used for infrastructure provisioning.

---

## 5. SignInLogs Table — Doesn't Exist on First Deploy

**Error:**
```
BadRequest: Failed to run the analytics rule query. One of the tables does not exist.
```

**What happened:**
The `SignInLogs` table in Log Analytics doesn't exist until actual sign-in data starts flowing into the workspace. On a fresh deploy with no prior sign-in events, Sentinel rejects any analytics rule that queries this table.

**Affected rules:** `signin_outside_trusted`, `impossible_travel` (both commented out by default)

**Fix:**
1. Sign out and back into the Azure portal with your admin account
2. Wait 10–15 minutes for the first sign-in logs to stream through
3. Verify: **Log Analytics → Logs → run `SignInLogs | take 5`**
4. Uncomment the two rules in `modules/monitoring/main.tf`
5. Re-run `terraform apply`

---

## 6. PRT Detection Rule — KQL Semantic Error on `project`

**Error:**
```
SEM0100: 'project' operator: Failed to resolve scalar expression named 'UserAppDeviceKey'
```

**What happened:**
The original PRT detection query used `join kind=leftanti` to exclude known-good User+App+Device combinations. After a `leftanti` join, the join key column (`UserAppDeviceKey`) is technically in scope from the left table, but Sentinel's query validator is stricter than the Log Analytics playground and rejects it in subsequent `project` statements. Re-extending the column after the join also failed validation.

**Fix:**
Replaced `join kind=leftanti KnownGood on UserAppDeviceKey` with `| where UserAppDeviceKey !in (KnownGood)`. The `!in` operator achieves identical logic (exclude rows whose key appears in the watchlist set) but avoids the join column scope issue entirely.

---

## 7. Terraform Sub-Technique Format — T1550.001 Rejected

**Error:**
```
Invalid data model. The technique 'T1550.001' is invalid. The expected format is 'T####'
```

**What happened:**
The Sentinel API only accepts MITRE technique IDs in the parent format (`T####`) — sub-techniques (`T####.###`) are rejected. The Terraform provider does not validate this before sending to the API.

**Fix:**
Use `T1550` instead of `T1550.001`. Ensure the parent tactic is included — `T1550` maps to `LateralMovement` and `DefenseEvasion`, so those must be in the `tactics` list or Sentinel will reject the combination.

---

## 8. Bootstrap Pipeline — SP Cannot Create Its Own Role Assignments

**Error:**
```
has an authorization with ABAC condition that is not fulfilled to perform action
'Microsoft.Authorization/roleAssignments/write'
```
when the bootstrap pipeline tries to create the RBAC Administrator assignment.

**What happened:**
The foundation module originally managed the RBAC Administrator role assignment. This created a chicken-and-egg problem: the SP needs RBAC Administrator to assign roles, but RBAC Administrator itself is a role assignment that requires a higher-privileged entity to create. The SP cannot bootstrap its own elevated permissions.

**Fix:**
Removed the RBAC Administrator assignment from the foundation module entirely. It is now created manually via CLI (by the Global Administrator account) and is intentionally outside Terraform state. See [Initial Setup → Step 2](README.md) for the exact command.

---

## 9. Watchlist Items — Cannot Be Managed in Terraform State

**Why watchlist items are managed out-of-band:**

`azurerm_sentinel_watchlist` creates the watchlist container but has no argument for seeding or managing item content. The underlying Sentinel Watchlist API's `rawContent` field is append-only on PUT — passing items on repeated `terraform apply` runs would result in duplicate entries accumulating in the watchlist.

`azurerm_sentinel_watchlist_item` exists as a separate resource for item-level management, but provisioning one resource per item doesn't fit a rolling daily-refreshed baseline of potentially thousands of User+App+Device combinations.

**Solution:** Terraform owns the empty watchlist container. All item population and refresh is handled out-of-band by `.github/workflows/watchlist-refresh.yml` via the Sentinel Watchlist Items REST API, which supports proper upsert semantics via deterministic item key matching.

Referenced in provider issue: hashicorp/terraform-provider-azurerm#14258
