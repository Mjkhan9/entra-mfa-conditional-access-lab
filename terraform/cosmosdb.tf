# Cosmos DB for incident storage

resource "azurerm_cosmosdb_account" "main" {
  name                = "cosmos-${local.name_prefix}-${random_string.suffix.result}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  offer_type          = "Standard"
  kind                = "GlobalDocumentDB"

  # Serverless: pay per request, same idea as on-demand capacity
  capabilities {
    name = "EnableServerless"
  }

  consistency_policy {
    consistency_level = "Session"
  }

  geo_location {
    location          = azurerm_resource_group.main.location
    failover_priority = 0
  }

  # Continuous backup (7-day tier) for audit compliance
  backup {
    type = "Continuous"
    tier = "Continuous7Days"
  }

  # Keys off: every client (function app, portal Data Explorer) authenticates with Entra ID
  local_authentication_disabled = true

  tags = local.tags
}

resource "azurerm_cosmosdb_sql_database" "incidents" {
  name                = "incidents-db"
  resource_group_name = azurerm_resource_group.main.name
  account_name        = azurerm_cosmosdb_account.main.name
}

resource "azurerm_cosmosdb_sql_container" "incidents" {
  name                = "incidents"
  resource_group_name = azurerm_resource_group.main.name
  account_name        = azurerm_cosmosdb_account.main.name
  database_name       = azurerm_cosmosdb_sql_database.incidents.name

  # Partition by scenario so the responder's "open smart_lockout incidents" query stays in one partition
  partition_key_paths   = ["/scenario"]
  partition_key_version = 2

  # Enable TTL; each incident carries its own ttl (seconds) for automatic cleanup
  default_ttl = -1
}

# One record per resolution (audit trail). Cosmos DB request metrics report document creates but not
# partial updates (patch), so the incident-resolved metric alert watches creates in this container.
resource "azurerm_cosmosdb_sql_container" "resolutions" {
  name                  = "resolutions"
  resource_group_name   = azurerm_resource_group.main.name
  account_name          = azurerm_cosmosdb_account.main.name
  database_name         = azurerm_cosmosdb_sql_database.incidents.name
  partition_key_paths   = ["/scenario"]
  partition_key_version = 2
  default_ttl           = -1
}

# Let the person running Terraform browse incidents in Data Explorer (keys are disabled)
resource "azurerm_cosmosdb_sql_role_assignment" "deployer" {
  name                = uuidv5("dns", "${local.name_prefix}-deployer-cosmos")
  resource_group_name = azurerm_resource_group.main.name
  account_name        = azurerm_cosmosdb_account.main.name
  role_definition_id  = "${azurerm_cosmosdb_account.main.id}/sqlRoleDefinitions/00000000-0000-0000-0000-000000000002"
  principal_id        = data.azurerm_client_config.current.object_id
  scope               = azurerm_cosmosdb_account.main.id
}

# Output the container details for the function app settings
output "incidents_container_name" {
  description = "Cosmos DB container holding incidents"
  value       = azurerm_cosmosdb_sql_container.incidents.name
}

output "cosmos_endpoint" {
  description = "Cosmos DB account endpoint"
  value       = azurerm_cosmosdb_account.main.endpoint
}
