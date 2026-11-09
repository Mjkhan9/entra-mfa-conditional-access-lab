# Azure Workbook - Single Pane of Glass
# 4 tiles maximum for focused situational awareness

locals {
  # Shared KQL prefix for the workbook queries (same event format as alerts.tf)
  wb_events = <<-KQL
    traces
    | where timestamp > ago(24h)
    | extend name = extract(@"^(\S+) ", 1, message)
    | where name in ("IncidentCount", "IncidentResolved", "ResolutionTimeSeconds")
    | extend d = parse_json(extract(@"^\S+ (.*)$", 1, message))
    | where tostring(d.Environment) == "${var.environment}"
  KQL
}

resource "azurerm_application_insights_workbook" "incidents" {
  name                = uuidv5("dns", "${local.name_prefix}-incidents-workbook")
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  display_name        = "MFA Incident Response - ${var.environment}"
  description         = "Incident volume, resolution time and recent activity for the MFA incident simulator"
  source_id           = lower(azurerm_application_insights.main.id)

  data_json = jsonencode({
    version = "Notebook/1.0"
    items = [
      {
        type = 1
        name = "title"
        content = {
          json = "## MFA Incident Response - situational awareness\nIncidents written by the simulate / detect / respond functions over the last 24 hours."
        }
      },
      # Tile 1: Incident Count by Scenario (last 24h)
      {
        type        = 3
        name        = "incidents-by-scenario"
        customWidth = "50"
        content = {
          version       = "KqlItem/1.0"
          title         = "Incidents by Scenario (24h)"
          query         = "${local.wb_events}| where name == \"IncidentCount\"\n| summarize Incidents = count() by bin(timestamp, 1h), Scenario = tostring(d.Scenario)"
          size          = 0
          queryType     = 0
          resourceType  = "microsoft.insights/components"
          visualization = "barchart"
          timeContext   = { durationMs = 86400000 }
        }
      },
      # Tile 2: Incident volume over time
      {
        type        = 3
        name        = "incident-volume"
        customWidth = "50"
        content = {
          version       = "KqlItem/1.0"
          title         = "Incident Volume Over Time"
          query         = "${local.wb_events}| where name == \"IncidentCount\"\n| summarize [\"Total Incidents\"] = count() by bin(timestamp, 5m)"
          size          = 0
          queryType     = 0
          resourceType  = "microsoft.insights/components"
          visualization = "timechart"
          timeContext   = { durationMs = 86400000 }
        }
      },
      # Tile 3: Resolution Time (Simulated MTTR)
      {
        type        = 3
        name        = "resolution-time"
        customWidth = "50"
        content = {
          version       = "KqlItem/1.0"
          title         = "Simulated Resolution Time"
          query         = "${local.wb_events}| where name == \"ResolutionTimeSeconds\"\n| summarize [\"Avg Resolution (s)\"] = avg(todouble(d.value)) by bin(timestamp, 5m)"
          size          = 0
          queryType     = 0
          resourceType  = "microsoft.insights/components"
          visualization = "timechart"
          timeContext   = { durationMs = 86400000 }
        }
      },
      # Tile 4: Recent incident activity (single values)
      {
        type        = 3
        name        = "recent-activity"
        customWidth = "50"
        content = {
          version       = "KqlItem/1.0"
          title         = "Recent Incident Activity (24h)"
          query         = "${local.wb_events}| summarize HIGH = countif(name == \"IncidentCount\" and tostring(d.Severity) == \"HIGH\"), MEDIUM = countif(name == \"IncidentCount\" and tostring(d.Severity) == \"MEDIUM\"), Resolved = countif(name == \"IncidentResolved\")\n| extend p = pack(\"HIGH\", HIGH, \"MEDIUM\", MEDIUM, \"Resolved\", Resolved)\n| mv-expand kind=array p\n| project Metric = tostring(p[0]), Value = toint(p[1])"
          size          = 0
          queryType     = 0
          resourceType  = "microsoft.insights/components"
          visualization = "tiles"
          timeContext   = { durationMs = 86400000 }
          tileSettings = {
            showBorder   = true
            titleContent = { columnMatch = "Metric", formatter = 1 }
            leftContent = {
              columnMatch   = "Value"
              formatter     = 12
              formatOptions = { palette = "auto" }
              numberFormat  = { unit = 17, options = { maximumSignificantDigits = 3, maximumFractionDigits = 2 } }
            }
          }
        }
      }
    ]
    isLocked            = false
    fallbackResourceIds = [azurerm_application_insights.main.id]
    "$schema"           = "https://github.com/Microsoft/Application-Insights-Workbooks/blob/master/schema/workbook.json"
  })

  tags = local.tags
}

output "workbook_url" {
  description = "Azure Workbook URL"
  value       = "https://portal.azure.com/#resource${azurerm_application_insights_workbook.incidents.id}/workbook"
}
