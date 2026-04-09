variable "pim_eligible_assignments" {
  description = "Map of PIM eligible role assignments"
  type = map(object({
    user_key          = string
    role_display_name = string
    justification     = string
    duration_months   = number
  }))
}

variable "user_objects" {
  description = "Full user objects from the users module"
  type        = any
}
