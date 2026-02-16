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
    | project TimeGenerated, service=tostring(logData.service), level=tostring(logData.level), message=tostring(logData.message), job_id=tostring(logData.job_id), correlation_id=tostring(logData.correlation_id), trace_id=tostring(logData.trace_id), delivery_count=toint(logData.delivery_count), error_code=tostring(logData.error_code), dlq_reason=tostring(logData.dlq_reason)
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

  monitor_saved_searches = {
    api_5xx = {
      name_suffix  = "api-5xx"
      display_name = "API 5xx Errors (10m)"
      query        = local.kql_api_5xx
    }
    pipeline_errors = {
      name_suffix  = "pipeline-errors"
      display_name = "Pipeline Errors/Warnings (10m)"
      query        = local.kql_pipeline_errors
    }
    queue_backlog = {
      name_suffix  = "queue-backlog"
      display_name = "Service Bus Queue Backlog (10m)"
      query        = local.kql_queue_backlog
    }
    deadletter_growth = {
      name_suffix  = "deadletter-growth"
      display_name = "Service Bus Deadletter Growth (10m)"
      query        = local.kql_deadletter_growth
    }
    stalled_pipeline = {
      name_suffix  = "stalled-pipeline"
      display_name = "Stalled Pipeline Detector (15m)"
      query        = local.kql_stalled_pipeline
    }
  }

  monitor_alerts = {
    api_5xx = {
      name_suffix          = "api-5xx-alert"
      description          = "API 5xx errors exceed threshold."
      severity             = 2
      evaluation_frequency = "PT5M"
      window_duration      = "PT10M"
      query                = local.kql_api_5xx
      threshold            = var.monitor_api_5xx_threshold
    }
    pipeline_errors = {
      name_suffix          = "pipeline-errors-alert"
      description          = "Pipeline blocked/error/retrying events exceed threshold."
      severity             = 2
      evaluation_frequency = "PT5M"
      window_duration      = "PT10M"
      query                = local.kql_pipeline_errors
      threshold            = var.monitor_pipeline_error_threshold
    }
    queue_backlog = {
      name_suffix          = "queue-backlog-alert"
      description          = "Service Bus queue backlog sustained above threshold."
      severity             = 3
      evaluation_frequency = "PT5M"
      window_duration      = "PT10M"
      query                = local.kql_queue_backlog
      threshold            = 0
    }
    deadletter_growth = {
      name_suffix          = "deadletter-alert"
      description          = "Service Bus dead-letter messages exceed threshold."
      severity             = 2
      evaluation_frequency = "PT5M"
      window_duration      = "PT10M"
      query                = local.kql_deadletter_growth
      threshold            = 0
    }
    stalled_pipeline = {
      name_suffix          = "stalled-pipeline-alert"
      description          = "Queue has active messages but no scan completions."
      severity             = 2
      evaluation_frequency = "PT5M"
      window_duration      = "PT15M"
      query                = local.kql_stalled_pipeline
      threshold            = 0
    }
  }
}

resource "azurerm_log_analytics_saved_search" "saved_search" {
  for_each = local.monitor_saved_searches

  name                       = "${var.prefix}-${each.value.name_suffix}"
  display_name               = each.value.display_name
  category                   = local.monitor_category
  log_analytics_workspace_id = data.azurerm_log_analytics_workspace.la.id
  query                      = each.value.query
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

resource "azurerm_monitor_scheduled_query_rules_alert_v2" "alert" {
  for_each = local.monitor_enabled ? local.monitor_alerts : {}

  name                 = "${var.prefix}-${each.value.name_suffix}"
  resource_group_name  = data.azurerm_resource_group.rg.name
  location             = data.azurerm_resource_group.rg.location
  description          = each.value.description
  severity             = each.value.severity
  enabled              = true
  scopes               = [data.azurerm_log_analytics_workspace.la.id]
  evaluation_frequency = each.value.evaluation_frequency
  window_duration      = each.value.window_duration

  criteria {
    query                   = each.value.query
    time_aggregation_method = "Count"
    operator                = "GreaterThan"
    threshold               = each.value.threshold
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
  source_id           = lower(azurerm_application_insights.appi.id)
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
