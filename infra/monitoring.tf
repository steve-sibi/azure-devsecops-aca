locals {
  monitor_category = "Observability"
  monitor_enabled  = var.monitor_alerts_enabled && length(var.monitor_action_group_email_receivers) > 0

  kql_api_5xx = <<-KQL
    ContainerAppConsoleLogs_CL
    | where TimeGenerated > ago(10m)
    | extend logData = parse_json(Log_s)
    | where tostring(logData.service) == "api"
    | where toint(logData.http_status_code) >= 500
    | project TimeGenerated, service=tostring(logData.service), route=tostring(logData.http_route), status=toint(logData.http_status_code), correlation_id=tostring(logData.correlation_id), trace_id=tostring(logData.trace_id), message=tostring(logData.message)
  KQL

  kql_pipeline_errors = <<-KQL
    ContainerAppConsoleLogs_CL
    | where TimeGenerated > ago(10m)
    | extend logData = parse_json(Log_s)
    | where tostring(logData.service) in ("fetcher", "worker")
    | where tostring(logData.level) in ("ERROR", "CRITICAL", "WARNING")
    | where tostring(logData.message) has_any ("error", "failed", "DLQ", "blocked", "retry")
    | project TimeGenerated, service=tostring(logData.service), level=tostring(logData.level), message=tostring(logData.message), job_id=tostring(logData.job_id), correlation_id=tostring(logData.correlation_id), trace_id=tostring(logData.trace_id)
  KQL

  kql_queue_backlog = <<-KQL
    AzureMetrics
    | where TimeGenerated > ago(10m)
    | where ResourceProvider == "MICROSOFT.SERVICEBUS"
    | where MetricName in ("ActiveMessages", "Active Messages")
    | summarize MaxActive = max(Total) by ResourceId
    | where MaxActive > ${var.monitor_queue_backlog_threshold}
  KQL

  kql_deadletter_growth = <<-KQL
    AzureMetrics
    | where TimeGenerated > ago(10m)
    | where ResourceProvider == "MICROSOFT.SERVICEBUS"
    | where MetricName in ("DeadletteredMessages", "Deadlettered Messages")
    | summarize MaxDeadlettered = max(Total) by ResourceId
    | where MaxDeadlettered > ${var.monitor_deadletter_threshold}
  KQL

  kql_stalled_pipeline = <<-KQL
    let queue_active = toscalar(
      AzureMetrics
      | where TimeGenerated > ago(15m)
      | where ResourceProvider == "MICROSOFT.SERVICEBUS"
      | where MetricName in ("ActiveMessages", "Active Messages")
      | summarize MaxActive = max(Total)
    );
    let completed_scans = toscalar(
      ContainerAppConsoleLogs_CL
      | where TimeGenerated > ago(15m)
      | extend logData = parse_json(Log_s)
      | where tostring(logData.message) == "Scan completed successfully"
      | summarize Count = count()
    );
    print queue_active=queue_active, completed_scans=completed_scans
    | where queue_active > 0 and completed_scans == 0
  KQL
}

resource "azurerm_log_analytics_saved_search" "api_5xx" {
  name                       = "${var.prefix}-api-5xx"
  display_name               = "API 5xx Errors (10m)"
  category                   = local.monitor_category
  log_analytics_workspace_id = data.azurerm_log_analytics_workspace.la.id
  query                      = local.kql_api_5xx
}

resource "azurerm_log_analytics_saved_search" "pipeline_errors" {
  name                       = "${var.prefix}-pipeline-errors"
  display_name               = "Pipeline Errors/Warnings (10m)"
  category                   = local.monitor_category
  log_analytics_workspace_id = data.azurerm_log_analytics_workspace.la.id
  query                      = local.kql_pipeline_errors
}

resource "azurerm_log_analytics_saved_search" "queue_backlog" {
  name                       = "${var.prefix}-queue-backlog"
  display_name               = "Service Bus Queue Backlog (10m)"
  category                   = local.monitor_category
  log_analytics_workspace_id = data.azurerm_log_analytics_workspace.la.id
  query                      = local.kql_queue_backlog
}

resource "azurerm_log_analytics_saved_search" "deadletter_growth" {
  name                       = "${var.prefix}-deadletter-growth"
  display_name               = "Service Bus Deadletter Growth (10m)"
  category                   = local.monitor_category
  log_analytics_workspace_id = data.azurerm_log_analytics_workspace.la.id
  query                      = local.kql_deadletter_growth
}

resource "azurerm_log_analytics_saved_search" "stalled_pipeline" {
  name                       = "${var.prefix}-stalled-pipeline"
  display_name               = "Stalled Pipeline Detector (15m)"
  category                   = local.monitor_category
  log_analytics_workspace_id = data.azurerm_log_analytics_workspace.la.id
  query                      = local.kql_stalled_pipeline
}

resource "azurerm_monitor_action_group" "observability" {
  count               = local.monitor_enabled ? 1 : 0
  name                = "${var.prefix}-ops-ag"
  resource_group_name = data.azurerm_resource_group.rg.name
  short_name          = substr(replace("${var.prefix}ops", "-", ""), 0, 12)

  dynamic "email_receiver" {
    for_each = var.monitor_action_group_email_receivers
    content {
      name                    = "email-${email_receiver.key + 1}"
      email_address           = email_receiver.value
      use_common_alert_schema = true
    }
  }
}

resource "azurerm_monitor_scheduled_query_rules_alert_v2" "api_5xx" {
  count                = local.monitor_enabled ? 1 : 0
  name                 = "${var.prefix}-api-5xx-alert"
  resource_group_name  = data.azurerm_resource_group.rg.name
  location             = data.azurerm_resource_group.rg.location
  description          = "API 5xx errors exceed threshold."
  severity             = 2
  enabled              = true
  scopes               = [data.azurerm_log_analytics_workspace.la.id]
  evaluation_frequency = "PT5M"
  window_duration      = "PT10M"

  criteria {
    query                   = local.kql_api_5xx
    time_aggregation_method = "Count"
    operator                = "GreaterThan"
    threshold               = var.monitor_api_5xx_threshold
  }

  action {
    action_groups = [azurerm_monitor_action_group.observability[0].id]
  }
}

resource "azurerm_monitor_scheduled_query_rules_alert_v2" "pipeline_errors" {
  count                = local.monitor_enabled ? 1 : 0
  name                 = "${var.prefix}-pipeline-errors-alert"
  resource_group_name  = data.azurerm_resource_group.rg.name
  location             = data.azurerm_resource_group.rg.location
  description          = "Pipeline blocked/error/retrying events exceed threshold."
  severity             = 2
  enabled              = true
  scopes               = [data.azurerm_log_analytics_workspace.la.id]
  evaluation_frequency = "PT5M"
  window_duration      = "PT10M"

  criteria {
    query                   = local.kql_pipeline_errors
    time_aggregation_method = "Count"
    operator                = "GreaterThan"
    threshold               = var.monitor_pipeline_error_threshold
  }

  action {
    action_groups = [azurerm_monitor_action_group.observability[0].id]
  }
}

resource "azurerm_monitor_scheduled_query_rules_alert_v2" "queue_backlog" {
  count                = local.monitor_enabled ? 1 : 0
  name                 = "${var.prefix}-queue-backlog-alert"
  resource_group_name  = data.azurerm_resource_group.rg.name
  location             = data.azurerm_resource_group.rg.location
  description          = "Service Bus queue backlog sustained above threshold."
  severity             = 3
  enabled              = true
  scopes               = [data.azurerm_log_analytics_workspace.la.id]
  evaluation_frequency = "PT5M"
  window_duration      = "PT10M"

  criteria {
    query                   = local.kql_queue_backlog
    time_aggregation_method = "Count"
    operator                = "GreaterThan"
    threshold               = 0
  }

  action {
    action_groups = [azurerm_monitor_action_group.observability[0].id]
  }
}

resource "azurerm_monitor_scheduled_query_rules_alert_v2" "deadletter_growth" {
  count                = local.monitor_enabled ? 1 : 0
  name                 = "${var.prefix}-deadletter-alert"
  resource_group_name  = data.azurerm_resource_group.rg.name
  location             = data.azurerm_resource_group.rg.location
  description          = "Service Bus dead-letter messages exceed threshold."
  severity             = 2
  enabled              = true
  scopes               = [data.azurerm_log_analytics_workspace.la.id]
  evaluation_frequency = "PT5M"
  window_duration      = "PT10M"

  criteria {
    query                   = local.kql_deadletter_growth
    time_aggregation_method = "Count"
    operator                = "GreaterThan"
    threshold               = 0
  }

  action {
    action_groups = [azurerm_monitor_action_group.observability[0].id]
  }
}

resource "azurerm_monitor_scheduled_query_rules_alert_v2" "stalled_pipeline" {
  count                = local.monitor_enabled ? 1 : 0
  name                 = "${var.prefix}-stalled-pipeline-alert"
  resource_group_name  = data.azurerm_resource_group.rg.name
  location             = data.azurerm_resource_group.rg.location
  description          = "Queue has active messages but no scan completions."
  severity             = 2
  enabled              = true
  scopes               = [data.azurerm_log_analytics_workspace.la.id]
  evaluation_frequency = "PT5M"
  window_duration      = "PT15M"

  criteria {
    query                   = local.kql_stalled_pipeline
    time_aggregation_method = "Count"
    operator                = "GreaterThan"
    threshold               = 0
  }

  action {
    action_groups = [azurerm_monitor_action_group.observability[0].id]
  }
}

resource "azurerm_application_insights_workbook" "observability" {
  count               = var.monitor_workbook_enabled ? 1 : 0
  name                = uuidv5("url", "https://observability.${var.prefix}.workbook")
  resource_group_name = data.azurerm_resource_group.rg.name
  location            = data.azurerm_resource_group.rg.location
  display_name        = "${var.prefix} Observability"
  source_id           = azurerm_application_insights.appi.id
  data_json = jsonencode(
    {
      version = "Notebook/1.0"
      items = [
        {
          type = 1
          content = {
            json = "# ${var.prefix} Observability Workbook\n\nUse this workbook with the saved searches and alerts deployed by Terraform."
          }
        },
        {
          type = 3
          content = {
            version      = "KqlItem/1.0"
            query        = local.kql_api_5xx
            size         = 0
            title        = "API 5xx Errors"
            queryType    = 0
            resourceType = "microsoft.operationalinsights/workspaces"
          }
        },
        {
          type = 3
          content = {
            version      = "KqlItem/1.0"
            query        = local.kql_pipeline_errors
            size         = 0
            title        = "Pipeline Errors"
            queryType    = 0
            resourceType = "microsoft.operationalinsights/workspaces"
          }
        },
      ]
    }
  )
}
