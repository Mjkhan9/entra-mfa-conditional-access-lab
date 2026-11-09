# Azure Monitor alert rules (log alerts over Application Insights)
# The functions write structured events: '<EventName> {json}'. Every rule parses that payload.

locals {
  # Shared KQL prefix: parse the JSON payload written by emit_event()
  parse_event = "| extend d = parse_json(extract(@\"^\\S+ (.*)$\", 1, message))"
}

# Alert: every new incident (and every resolution) - this is the notification path
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "incident_created" {
  name                = "alert-${local.name_prefix}-incident-created"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  display_name        = "MFA incident detected"
  description         = "A new MFA incident was created (or resolved) by the simulator / detector"
  severity            = 2
  enabled             = true

  scopes               = [azurerm_application_insights.main.id]
  evaluation_frequency = "PT5M"
  window_duration      = "PT5M"

  criteria {
    query = <<-QUERY
      traces
      | where message startswith "IncidentAlert "
      ${local.parse_event}
      | project timestamp,
                Event      = tostring(d.event),
                IncidentId = tostring(d.incident_id),
                Scenario   = tostring(d.scenario),
                Severity   = tostring(coalesce(d.severity, d.original_severity)),
                User       = tostring(d.user)
    QUERY

    time_aggregation_method = "Count"
    operator                = "GreaterThan"
    threshold               = 0

    # One alert per incident
    dimension {
      name     = "IncidentId"
      operator = "Include"
      values   = ["*"]
    }
    dimension {
      name     = "Event"
      operator = "Include"
      values   = ["*"]
    }

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  auto_mitigation_enabled = true

  action {
    action_groups = [azurerm_monitor_action_group.incidents.id]
    email_subject = "[MFA incident] new incident activity"
  }

  tags = local.tags
}

# Alert: High incident volume (>10 incidents in 5 minutes)
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "high_incident_volume" {
  name                = "alert-${local.name_prefix}-high-incident-volume"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  display_name        = "High volume of MFA incidents"
  description         = "More than 10 MFA incidents in 5 minutes"
  severity            = 1
  enabled             = true

  scopes               = [azurerm_application_insights.main.id]
  evaluation_frequency = "PT5M"
  window_duration      = "PT5M"

  criteria {
    query = <<-QUERY
      traces
      | where message startswith "IncidentCount "
      ${local.parse_event}
      | where tostring(d.Environment) == "${var.environment}"
    QUERY

    time_aggregation_method = "Count"
    operator                = "GreaterThan"
    threshold               = 10

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  auto_mitigation_enabled = true

  action {
    action_groups = [azurerm_monitor_action_group.incidents.id]
  }

  tags = local.tags
}

# Alert: Critical severity incidents
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "critical_incidents" {
  name                = "alert-${local.name_prefix}-critical-incidents"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  display_name        = "Critical MFA incident"
  description         = "Critical severity MFA incident detected"
  severity            = 0
  enabled             = true

  scopes               = [azurerm_application_insights.main.id]
  evaluation_frequency = "PT5M"
  window_duration      = "PT5M"

  criteria {
    query = <<-QUERY
      traces
      | where message startswith "IncidentCount "
      ${local.parse_event}
      | where tostring(d.Environment) == "${var.environment}" and tostring(d.Severity) == "CRITICAL"
    QUERY

    time_aggregation_method = "Count"
    operator                = "GreaterThan"
    threshold               = 0

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  auto_mitigation_enabled = true

  action {
    action_groups = [azurerm_monitor_action_group.incidents.id]
  }

  tags = local.tags
}

# Alert: Slow resolution time (>10 minutes average, three 5-minute periods in a row)
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "slow_resolution" {
  name                = "alert-${local.name_prefix}-slow-resolution"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  display_name        = "Slow MFA incident resolution"
  description         = "Average resolution time exceeds 10 minutes"
  severity            = 3
  enabled             = true

  scopes               = [azurerm_application_insights.main.id]
  evaluation_frequency = "PT5M"
  window_duration      = "PT5M"

  criteria {
    query = <<-QUERY
      traces
      | where message startswith "ResolutionTimeSeconds "
      ${local.parse_event}
      | where tostring(d.Environment) == "${var.environment}"
      | project timestamp, Seconds = todouble(d.value)
    QUERY

    time_aggregation_method = "Average"
    metric_measure_column   = "Seconds"
    operator                = "GreaterThan"
    threshold               = 600

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 3
      number_of_evaluation_periods             = 3
    }
  }

  auto_mitigation_enabled = true

  action {
    action_groups = [azurerm_monitor_action_group.incidents.id]
  }

  tags = local.tags
}

# Alert: Function failures (uses the built-in request telemetry)
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "function_errors" {
  name                = "alert-${local.name_prefix}-function-errors"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  display_name        = "MFA incident function errors"
  description         = "High number of failed function executions"
  severity            = 2
  enabled             = true

  scopes               = [azurerm_application_insights.main.id]
  evaluation_frequency = "PT5M"
  window_duration      = "PT5M"

  criteria {
    query = <<-QUERY
      requests
      | where success == false
      | where cloud_RoleName =~ "${azurerm_linux_function_app.main.name}"
    QUERY

    time_aggregation_method = "Count"
    operator                = "GreaterThan"
    threshold               = 5

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  auto_mitigation_enabled = true

  action {
    action_groups = [azurerm_monitor_action_group.incidents.id]
  }

  tags = local.tags
}
