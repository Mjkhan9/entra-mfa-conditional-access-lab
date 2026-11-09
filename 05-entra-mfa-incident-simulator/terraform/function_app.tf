# Function app hosting the simulator, detector and responder functions

# Storage account required by the Functions host (checkpoints, timer locks)
resource "azurerm_storage_account" "functions" {
  name                     = "stmfaincident${random_string.suffix.result}"
  resource_group_name      = azurerm_resource_group.main.name
  location                 = azurerm_resource_group.main.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  min_tls_version          = "TLS1_2"
  tags                     = local.tags
}

# Blob container that holds the deployment package (Flex Consumption)
resource "azurerm_storage_container" "deployments" {
  name                  = "app-package"
  storage_account_id    = azurerm_storage_account.functions.id
  container_access_type = "private"
}

# Flex Consumption plan (pay per execution; Linux Consumption Y1 is legacy)
resource "azurerm_service_plan" "main" {
  name                = "plan-${local.name_prefix}"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  os_type             = "Linux"
  sku_name            = "FC1"
  tags                = local.tags
}

# One function app, three functions (simulate / detect / respond) - see ../functions/function_app.py
resource "azurerm_function_app_flex_consumption" "main" {
  name                = "func-${local.name_prefix}-${random_string.suffix.result}"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  service_plan_id     = azurerm_service_plan.main.id

  storage_container_type      = "blobContainer"
  storage_container_endpoint  = "${azurerm_storage_account.functions.primary_blob_endpoint}${azurerm_storage_container.deployments.name}"
  storage_authentication_type = "StorageAccountConnectionString"
  storage_access_key          = azurerm_storage_account.functions.primary_access_key
  runtime_name                = "python"
  runtime_version             = "3.12"
  maximum_instance_count      = 40
  instance_memory_in_mb       = 2048
  https_only                  = true

  # System-assigned managed identity: Cosmos DB and Event Hubs are reached without any keys
  identity {
    type = "SystemAssigned"
  }

  site_config {
    application_insights_connection_string = azurerm_application_insights.main.connection_string
  }

  app_settings = {
    COSMOS_ENDPOINT   = azurerm_cosmosdb_account.main.endpoint
    COSMOS_DATABASE   = azurerm_cosmosdb_sql_database.incidents.name
    COSMOS_CONTAINER  = azurerm_cosmosdb_sql_container.incidents.name
    INCIDENT_TTL_DAYS = tostring(var.incident_retention_days)
    ENVIRONMENT       = var.environment

    # Event Hub trigger (identity-based connection, no connection string)
    EVENTHUB_NAME                                 = azurerm_eventhub.signin_logs.name
    "EventHubConnection__fullyQualifiedNamespace" = "${azurerm_eventhub_namespace.main.name}.servicebus.windows.net"

    # Responder timer trigger
    RESPONDER_SCHEDULE = var.responder_schedule
    # Flex Consumption builds Python dependencies remotely on publish; no build settings needed
  }

  tags = local.tags
}

# Permissions for the managed identity

# Read the sign-in log stream
resource "azurerm_role_assignment" "eventhub_receiver" {
  scope                = azurerm_eventhub_namespace.main.id
  role_definition_name = "Azure Event Hubs Data Receiver"
  principal_id         = azurerm_function_app_flex_consumption.main.identity[0].principal_id
}

# Read and write incidents (Cosmos DB built-in Data Contributor, data plane)
resource "azurerm_cosmosdb_sql_role_assignment" "function_app" {
  name                = uuidv5("dns", "${local.name_prefix}-function-app-cosmos")
  resource_group_name = azurerm_resource_group.main.name
  account_name        = azurerm_cosmosdb_account.main.name
  role_definition_id  = "${azurerm_cosmosdb_account.main.id}/sqlRoleDefinitions/00000000-0000-0000-0000-000000000002"
  principal_id        = azurerm_function_app_flex_consumption.main.identity[0].principal_id
  scope               = azurerm_cosmosdb_account.main.id
}

# Outputs
output "function_app_name" {
  description = "Function app name (used by func azure functionapp publish)"
  value       = azurerm_function_app_flex_consumption.main.name
}

output "function_app_hostname" {
  description = "Function app hostname"
  value       = azurerm_function_app_flex_consumption.main.default_hostname
}

output "resource_group_name" {
  description = "Resource group holding every resource"
  value       = azurerm_resource_group.main.name
}
