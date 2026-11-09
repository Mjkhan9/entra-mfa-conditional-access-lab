# Microsoft Graph application permissions for the function app's managed identity (read-only)
#
#   Policy.Read.All                - Conditional Access policies and security defaults (posture check)
#   RoleManagement.Read.Directory  - admin role assignments (privileged_single_factor detection)
#
# Least privilege: nothing here can change a user, a policy or a role. Granting app roles needs
# Privileged Role Administrator (or Global Administrator) for whoever runs terraform apply.
# Set grant_graph_read = false to skip; the posture check then works only in demo mode.

data "azuread_application_published_app_ids" "well_known" {}

data "azuread_service_principal" "msgraph" {
  client_id = data.azuread_application_published_app_ids.well_known.result["MicrosoftGraph"]
}

resource "azuread_app_role_assignment" "graph_read" {
  for_each = var.grant_graph_read ? toset(["Policy.Read.All", "RoleManagement.Read.Directory"]) : toset([])

  app_role_id         = data.azuread_service_principal.msgraph.app_role_ids[each.value]
  principal_object_id = azurerm_function_app_flex_consumption.main.identity[0].principal_id
  resource_object_id  = data.azuread_service_principal.msgraph.object_id
}
