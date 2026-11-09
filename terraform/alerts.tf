# Azure Monitor metric alerts
#
# Cost design: log search alert rules bill per rule per month (USD 1.50 each at a 5-minute frequency),
# while metric alerts are free for the first 10 monitored time series per subscription. Every rule
# here watches a platform metric that already exists for free:
#   - Cosmos DB TotalRequests on the incidents container: Create = new incident, Patch = resolution
#   - Application Insights requests/failed: function errors
# Monitored time series: 2 + 1 + 2 + 1 = 6 (limit for free: 10). Adding a dimension value adds one.
# Per-incident detail (scenario, severity, user) stays in Cosmos DB and the workbook.

locals {
  incident_writes = ["Create", "Upsert"] # how Cosmos DB reports a new document (create_item / upsert_item)
}

# Alert: new incident stored
resource "azurerm_monitor_metric_alert" "incident_created" {
  name                = "alert-${local.name_prefix}-incident-created"
  resource_group_name = azurerm_resource_group.main.name
  scopes              = [azurerm_cosmosdb_account.main.id]
  description         = "A new MFA incident was stored by the simulator / detector"
  severity            = 2
  frequency           = "PT1M"
  window_size         = "PT5M"
  auto_mitigate       = true

  criteria {
    metric_namespace = "Microsoft.DocumentDB/databaseAccounts"
    metric_name      = "TotalRequests"
    aggregation      = "Count"
    operator         = "GreaterThan"
    threshold        = 0

    dimension {
      name     = "CollectionName"
      operator = "Include"
      values   = [azurerm_cosmosdb_sql_container.incidents.name]
    }
    dimension {
      name     = "OperationType"
      operator = "Include"
      values   = local.incident_writes
    }
  }

  action {
    action_group_id = azurerm_monitor_action_group.incidents.id
  }

  tags = local.tags
}

# Alert: incident resolved by the responder (patch of status / resolution time)
resource "azurerm_monitor_metric_alert" "incident_resolved" {
  name                = "alert-${local.name_prefix}-incident-resolved"
  resource_group_name = azurerm_resource_group.main.name
  scopes              = [azurerm_cosmosdb_account.main.id]
  description         = "A smart lockout incident was resolved after its cooldown"
  severity            = 4
  frequency           = "PT1M"
  window_size         = "PT5M"
  auto_mitigate       = true

  criteria {
    metric_namespace = "Microsoft.DocumentDB/databaseAccounts"
    metric_name      = "TotalRequests"
    aggregation      = "Count"
    operator         = "GreaterThan"
    threshold        = 0

    dimension {
      name     = "CollectionName"
      operator = "Include"
      values   = [azurerm_cosmosdb_sql_container.incidents.name]
    }
    dimension {
      name     = "OperationType"
      operator = "Include"
      values   = ["Patch"]
    }
  }

  action {
    action_group_id = azurerm_monitor_action_group.incidents.id
  }

  tags = local.tags
}

# Alert: high incident volume (more than 10 new incidents in 5 minutes)
resource "azurerm_monitor_metric_alert" "high_incident_volume" {
  name                = "alert-${local.name_prefix}-high-incident-volume"
  resource_group_name = azurerm_resource_group.main.name
  scopes              = [azurerm_cosmosdb_account.main.id]
  description         = "More than 10 MFA incidents in 5 minutes"
  severity            = 1
  frequency           = "PT1M"
  window_size         = "PT5M"
  auto_mitigate       = true

  criteria {
    metric_namespace = "Microsoft.DocumentDB/databaseAccounts"
    metric_name      = "TotalRequests"
    aggregation      = "Count"
    operator         = "GreaterThan"
    threshold        = 10

    dimension {
      name     = "CollectionName"
      operator = "Include"
      values   = [azurerm_cosmosdb_sql_container.incidents.name]
    }
    dimension {
      name     = "OperationType"
      operator = "Include"
      values   = local.incident_writes
    }
  }

  action {
    action_group_id = azurerm_monitor_action_group.incidents.id
  }

  tags = local.tags
}

# Alert: function failures (Application Insights standard metric)
resource "azurerm_monitor_metric_alert" "function_errors" {
  name                = "alert-${local.name_prefix}-function-errors"
  resource_group_name = azurerm_resource_group.main.name
  scopes              = [azurerm_application_insights.main.id]
  description         = "More than 5 failed function requests in 5 minutes"
  severity            = 2
  frequency           = "PT1M"
  window_size         = "PT5M"
  auto_mitigate       = true

  criteria {
    metric_namespace = "microsoft.insights/components"
    metric_name      = "requests/failed"
    aggregation      = "Count"
    operator         = "GreaterThan"
    threshold        = 5
  }

  action {
    action_group_id = azurerm_monitor_action_group.incidents.id
  }

  tags = local.tags
}
