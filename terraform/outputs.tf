# Consolidated outputs for MFA Incident Simulator

output "project_info" {
  description = "Project deployment information"
  value = {
    project_name    = var.project_name
    environment     = var.environment
    location        = azurerm_resource_group.main.location
    subscription_id = local.subscription_id
    tenant_id       = local.tenant_id
    resource_group  = azurerm_resource_group.main.name
  }
}

output "deploy_code_command" {
  description = "Publish the functions after terraform apply (run from the functions folder)"
  value       = "func azure functionapp publish ${azurerm_function_app_flex_consumption.main.name} --python"
}

output "invoke_commands" {
  description = "Commands to invoke the simulator"
  value = {
    get_function_key = <<-EOT
      KEY=$(az functionapp keys list \
        --resource-group ${azurerm_resource_group.main.name} \
        --name ${azurerm_function_app_flex_consumption.main.name} \
        --query functionKeys.default -o tsv)
    EOT

    detect_last_hour = <<-EOT
      curl -s -X POST "https://${azurerm_function_app_flex_consumption.main.default_hostname}/api/detect?code=$KEY" \
        -H "Content-Type: application/json" \
        -d '{"minutes": 60}'
    EOT

    posture = <<-EOT
      curl -s "https://${azurerm_function_app_flex_consumption.main.default_hostname}/api/posture?code=$KEY"
    EOT

    password_spray = <<-EOT
      curl -s -X POST "https://${azurerm_function_app_flex_consumption.main.default_hostname}/api/simulate?code=$KEY" \
        -H "Content-Type: application/json" \
        -d '{"scenario": "password_spray"}'
    EOT

    respond = <<-EOT
      curl -s -X POST "https://${azurerm_function_app_flex_consumption.main.default_hostname}/api/respond?code=$KEY"
    EOT

    mfa_auth_failure = <<-EOT
      curl -s -X POST "https://${azurerm_function_app_flex_consumption.main.default_hostname}/api/simulate?code=$KEY" \
        -H "Content-Type: application/json" \
        -d '{"scenario": "mfa_auth_failure", "user": "test-user"}'
    EOT

    smart_lockout = <<-EOT
      curl -s -X POST "https://${azurerm_function_app_flex_consumption.main.default_hostname}/api/simulate?code=$KEY" \
        -H "Content-Type: application/json" \
        -d '{"scenario": "smart_lockout", "user": "test-user"}'
    EOT

    policy_mismatch = <<-EOT
      curl -s -X POST "https://${azurerm_function_app_flex_consumption.main.default_hostname}/api/simulate?code=$KEY" \
        -H "Content-Type: application/json" \
        -d '{"scenario": "policy_mismatch", "user": "test-user"}'
    EOT
  }
}

output "useful_links" {
  description = "Azure portal links"
  value = {
    workbook       = "https://portal.azure.com/#resource${azurerm_application_insights_workbook.incidents.id}/workbook"
    cosmos_data    = "https://portal.azure.com/#resource${azurerm_cosmosdb_account.main.id}/dataExplorer"
    function_app   = "https://portal.azure.com/#resource${azurerm_function_app_flex_consumption.main.id}/appServices"
    action_group   = "https://portal.azure.com/#resource${azurerm_monitor_action_group.incidents.id}/overview"
    log_analytics  = "https://portal.azure.com/#resource${azurerm_log_analytics_workspace.main.id}/logs"
    alert_rules    = "https://portal.azure.com/#view/Microsoft_Azure_Monitoring/AzureMonitoringBrowseBlade/~/alertRules"
    entra_sign_ins = "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/SignInLogsBlade"
  }
}
