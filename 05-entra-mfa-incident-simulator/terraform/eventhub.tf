# Event Hub for real-time sign-in log detection

# Note: In production, Entra diagnostic settings stream SignInLogs into this hub and the
# detect function processes every record as it arrives. For the simulator we call the HTTP
# endpoint directly. The hub is always created so the trigger has something to bind to;
# the tenant-level diagnostic setting is opt-in (enable_entra_log_export) because it needs
# Entra ID P1 and the Security Administrator role.

resource "azurerm_eventhub_namespace" "main" {
  name                = "evhns-${local.name_prefix}-${random_string.suffix.result}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  sku                 = "Basic"
  capacity            = 1
  tags                = local.tags
}

resource "azurerm_eventhub" "signin_logs" {
  name              = "signin-logs"
  namespace_id      = azurerm_eventhub_namespace.main.id
  partition_count   = 2
  message_retention = 1
}

# Send-only rule used by the diagnostic setting (never the root manage key)
resource "azurerm_eventhub_namespace_authorization_rule" "diagnostics" {
  name                = "entra-diagnostics-send"
  namespace_name      = azurerm_eventhub_namespace.main.name
  resource_group_name = azurerm_resource_group.main.name
  listen              = false
  send                = true
  manage              = false
}

# Entra ID -> SignInLogs -> event hub (real-time) + Log Analytics (KQL investigation)
resource "azurerm_monitor_aad_diagnostic_setting" "signin_logs" {
  count = var.enable_entra_log_export ? 1 : 0

  name                           = "${local.name_prefix}-signin-logs"
  eventhub_authorization_rule_id = azurerm_eventhub_namespace_authorization_rule.diagnostics.id
  eventhub_name                  = azurerm_eventhub.signin_logs.name
  log_analytics_workspace_id     = azurerm_log_analytics_workspace.main.id

  enabled_log {
    category = "SignInLogs"
  }
}

output "eventhub_namespace" {
  description = "Event Hubs namespace receiving the sign-in log stream"
  value       = azurerm_eventhub_namespace.main.name
}

output "eventhub_name" {
  description = "Event hub the detect function listens to"
  value       = azurerm_eventhub.signin_logs.name
}
