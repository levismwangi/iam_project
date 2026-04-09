variable "departments" {
  description = "List of department names"
  type        = list(string)
}

variable "users" {
  description = "User objects from the users module"
  type        = any
}

variable "company_name" {
  description = "Company name for group naming"
  type        = string
}
