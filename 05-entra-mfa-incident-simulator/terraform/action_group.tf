# Action group for incident alerts

resource "azurerm_monitor_action_group" "incidents" {
  name                = "ag-${local.name_prefix}"
  resource_group_name = azurerm_resource_group.main.name
  short_name          = "mfa-alerts"

  # Email receiver (optional - only if email provided)
  dynamic "email_receiver" {
    for_each = var.alert_email != "" ? [var.alert_email] : []
    content {
      name                    = "incident-email"
      email_address           = email_receiver.value
      use_common_alert_schema = true
    }
  }

  tags = local.tags
}

output "action_group_id" {
  description = "Action group ID for incident alerts"
  value       = azurerm_monitor_action_group.incidents.id
}
