# modules/pim/variables.tf

# ── Shared lookups ────────────────────────────────────────────────────────
# Users and groups are looked up by an arbitrary "key" you choose, so that
# other variables (below) can reference "alice" instead of a raw object ID.

variable "user_objects" {
  description = "Map of user_key => user object (must include object_id)"
  type = map(object({
    object_id = string
  }))
  default = {}
}

variable "group_objects" {
  description = "Map of group_key => group object (must include object_id)"
  type = map(object({
    object_id = string
  }))
  default = {}
}

# ── 1. Entra ID Directory Role eligibility ──────────────────────────────
# NOTE: Activation policy (max duration, approval, MFA) for directory roles
# is NOT configurable via Terraform as of azuread provider v3.8.0 — there is
# no azuread_directory_role_management_policy resource. Configure manually:
# Entra ID → Roles and administrators → <Role> → Settings.

variable "directory_role_eligible_assignments" {
  description = "Map of assignment_key => directory role eligibility to grant"
  type = map(object({
    role_display_name = string # e.g. "Helpdesk Administrator"
    user_key           = string # key into var.user_objects
    justification      = string
  }))
  default = {}
}

# ── 2. Azure AD Group eligibility (membership or ownership) ─────────────
# Activation policy IS configurable here via azuread_group_role_management_policy.

variable "group_eligible_assignments" {
  description = "Map of assignment_key => group eligibility to grant"
  type = map(object({
    group_key       = string      # key into var.group_objects
    principal_key   = string      # key into var.user_objects (the person becoming eligible)
    assignment_type = string      # "member" or "owner"
    justification   = string
  }))
  default = {}
}

variable "group_activation_policies" {
  description = "Map of group_key => activation policy settings for that group's PIM-eligible roles"
  type = map(object({
    role_id                             = string # "member" or "owner"
    maximum_duration                    = string # ISO8601, e.g. "PT8H"
    require_approval                    = bool
    require_justification               = optional(bool, true)
    require_multifactor_authentication  = optional(bool, true)
    approver_group_key                  = optional(string) # key into var.group_objects, required if require_approval = true
  }))
  default = {}
}

# ── 3. Azure RBAC role eligibility (subscriptions, resource groups, etc.) ─
# Scope is provided per-assignment so this works for subscription-level,
# resource-group-level, or any mix, without changing the variable shape later.

variable "rbac_eligible_assignments" {
  description = "Map of assignment_key => Azure RBAC role eligibility to grant"
  type = map(object({
    scope              = string      # full resource ID of the scope, e.g. subscription or resource group ID
    role_definition_id = string      # full role definition resource ID (see locals/data lookups in azure_rbac.tf)
    principal_key      = string      # key into var.user_objects
    duration_hours      = optional(number) # null/omitted = no expiration on eligibility itself
    justification       = string
    ticket_number        = optional(string)
    ticket_system         = optional(string)
  }))
  default = {}
}

variable "rbac_activation_policies" {
  description = "Map of policy_key => activation policy settings for an Azure RBAC role at a given scope"
  type = map(object({
    scope                               = string
    role_definition_id                 = string
    maximum_duration                    = string # ISO8601, e.g. "PT1H"
    require_approval                    = bool
    require_justification               = optional(bool, true)
    require_multifactor_authentication  = optional(bool, true)
    approver_group_key                  = optional(string) # key into var.group_objects, required if require_approval = true
    active_assignment_expire_after      = optional(string, "P365D")
  }))
  default = {}
}
