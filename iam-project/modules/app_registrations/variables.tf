variable "applications" {
  description = "Map of applications to register"
  type = map(object({
    name          = string
    redirect_uris = list(string)
    logout_url    = string
  }))
}

variable "group_ids" {
  description = "Map of department name to group object ID (from groups module)"
  type        = map(string)
}

variable "app_group_assignments" {
  description = "Map of app-to-group assignments"
  type = map(object({
    app_key   = string
    group_key = string
  }))
}
