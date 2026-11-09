# Read-only Graph permission for the function app's managed identity, used by the posture check
# (Conditional Access policies + security defaults). Needs Privileged Role Administrator or
# Global Administrator to grant. Set grant_graph_read = false to skip it; /api/posture then
# only works with ?demo=1.

data "azuread_application_published_app_ids" "well_known" {}

data "azuread_service_principal" "msgraph" {
  client_id = data.azuread_application_published_app_ids.well_known.result["MicrosoftGraph"]
}

resource "azuread_app_role_assignment" "graph_read" {
  for_each = var.grant_graph_read ? toset(["Policy.Read.All"]) : toset([])

  app_role_id         = data.azuread_service_principal.msgraph.app_role_ids[each.value]
  principal_object_id = azurerm_function_app_flex_consumption.main.identity[0].principal_id
  resource_object_id  = data.azuread_service_principal.msgraph.object_id
}
