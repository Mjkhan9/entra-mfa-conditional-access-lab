# Entra sign-in logs -> Log Analytics (detector mode source)

# The detect function pulls SigninLogs from the workspace on demand (functions/detector.py).
# No event hub: an Event Hubs namespace bills every hour it exists, even with no traffic, while
# workspace ingestion at this volume stays inside the free monthly allowance and queries are free.
# The tenant-level diagnostic setting is opt-in (enable_entra_log_export) because it needs
# Entra ID P1 and the Security Administrator role.
resource "azurerm_monitor_aad_diagnostic_setting" "signin_logs" {
  count = var.enable_entra_log_export ? 1 : 0

  name                       = "${local.name_prefix}-signin-logs"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  enabled_log {
    category = "SignInLogs"
  }
}
