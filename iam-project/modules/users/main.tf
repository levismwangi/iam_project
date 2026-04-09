# modules/users/main.tf

resource "azuread_user" "this" {
  for_each = var.users

  display_name          = each.value.display_name
  given_name            = each.value.first_name
  surname               = each.value.last_name
  user_principal_name   = "${lower(replace(each.value.first_name, " ", ""))}.${lower(replace(each.value.last_name, " ", ""))}@${var.tenant_domain}"
  mail_nickname         = "${lower(replace(each.value.first_name, " ", ""))}.${lower(replace(each.value.last_name, " ", ""))}"
  password              = var.temp_password
  force_password_change = true
  department            = each.value.department
  job_title             = each.value.job_title
  account_enabled       = true

  lifecycle {
    # Prevent Terraform from resetting password on every apply
    ignore_changes = [password]
  }
}
