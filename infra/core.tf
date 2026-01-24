# Existing RG
data "azurerm_resource_group" "rg" {
  name = var.resource_group_name
}

# Existing foundation (read-only)
data "azurerm_log_analytics_workspace" "la" {
  name                = local.la_name
  resource_group_name = data.azurerm_resource_group.rg.name
}

data "azurerm_container_registry" "acr" {
  name                = local.acr_name
  resource_group_name = data.azurerm_resource_group.rg.name
}

data "azurerm_key_vault" "kv" {
  name                = local.kv_name
  resource_group_name = data.azurerm_resource_group.rg.name
}

resource "azurerm_servicebus_namespace" "sb" {
  name                = local.sb_ns_name
  location            = data.azurerm_resource_group.rg.location
  resource_group_name = data.azurerm_resource_group.rg.name
  sku                 = var.servicebus_sku
  minimum_tls_version = "1.2"
  tags                = var.tags

  identity {
    type = "SystemAssigned"
  }
}

data "azurerm_client_config" "current" {}

# --- User-assigned identity we can grant perms to BEFORE the apps exist ---
resource "azurerm_user_assigned_identity" "uami" {
  name                = local.uami_name
  location            = data.azurerm_resource_group.rg.location
  resource_group_name = data.azurerm_resource_group.rg.name
  tags                = var.tags
}

# Application Insights (workspace-linked)
resource "azurerm_application_insights" "appi" {
  name                = local.ai_name
  location            = data.azurerm_resource_group.rg.location
  resource_group_name = data.azurerm_resource_group.rg.name
  application_type    = "web"
  workspace_id        = data.azurerm_log_analytics_workspace.la.id
  tags                = var.tags
}

# Service Bus queue
resource "azurerm_servicebus_queue" "q" {
  name                  = var.queue_name
  namespace_id          = azurerm_servicebus_namespace.sb.id
  max_size_in_megabytes = 1024
}

# Separate queue for the scan/analyzer stage (fetcher forwards here).
resource "azurerm_servicebus_queue" "q_scan" {
  name                  = local.scan_queue_name
  namespace_id          = azurerm_servicebus_namespace.sb.id
  max_size_in_megabytes = 1024
}

# Storage for scan results (Table)
resource "azurerm_storage_account" "results" {
  name                             = local.results_sa
  resource_group_name              = data.azurerm_resource_group.rg.name
  location                         = data.azurerm_resource_group.rg.location
  account_tier                     = "Standard"
  account_replication_type         = "GRS"
  min_tls_version                  = "TLS1_2"
  cross_tenant_replication_enabled = true
  allow_nested_items_to_be_public  = false
  https_traffic_only_enabled       = true
  tags                             = var.tags

  sas_policy {
    expiration_action = "Log"
    expiration_period = "30.00:00:00"
  }

  blob_properties {
    delete_retention_policy {
      days = 7
    }

    container_delete_retention_policy {
      days = 7
    }
  }

  share_properties {
    retention_policy {
      days = 7
    }
  }

}

resource "azurerm_storage_table" "results" {
  name                 = local.results_table
  storage_account_name = azurerm_storage_account.results.name
}

resource "azurerm_storage_account_queue_properties" "results" {
  storage_account_id = azurerm_storage_account.results.id

  logging {
    delete                = true
    read                  = true
    retention_policy_days = 7
    version               = "1.0"
    write                 = true
  }

  minute_metrics {
    include_apis          = true
    retention_policy_days = 7
    version               = "1.0"
  }
}

# ---------- Least-privilege authorization rules at QUEUE scope ----------
resource "azurerm_servicebus_queue_authorization_rule" "q_send" {
  name     = "api-send"
  queue_id = azurerm_servicebus_queue.q.id
  send     = true
}

resource "azurerm_servicebus_queue_authorization_rule" "q_listen" {
  name     = "worker-listen"
  queue_id = azurerm_servicebus_queue.q.id
  listen   = true
}

# KEDA scaler needs Manage to read queue metrics
resource "azurerm_servicebus_queue_authorization_rule" "q_manage" {
  name     = "scale-manage"
  queue_id = azurerm_servicebus_queue.q.id

  # Manage implies both of these must be true
  manage = true
  listen = true
  send   = true
}

# ---------- Least-privilege authorization rules at SCAN QUEUE scope ----------
resource "azurerm_servicebus_queue_authorization_rule" "q_scan_send" {
  name     = "fetcher-send"
  queue_id = azurerm_servicebus_queue.q_scan.id
  send     = true
}

resource "azurerm_servicebus_queue_authorization_rule" "q_scan_listen" {
  name     = "worker-scan-listen"
  queue_id = azurerm_servicebus_queue.q_scan.id
  listen   = true
}

resource "azurerm_servicebus_queue_authorization_rule" "q_scan_manage" {
  name     = "scale-manage-scan"
  queue_id = azurerm_servicebus_queue.q_scan.id

  manage = true
  listen = true
  send   = true
}

# Container Apps Environment
resource "azurerm_container_app_environment" "env" {
  name                       = local.env_name
  location                   = data.azurerm_resource_group.rg.location
  resource_group_name        = data.azurerm_resource_group.rg.name
  log_analytics_workspace_id = data.azurerm_log_analytics_workspace.la.id
  tags                       = var.tags
}

resource "azurerm_storage_share" "artifacts" {
  count                = var.create_apps ? 1 : 0
  name                 = local.artifacts_share
  storage_account_name = azurerm_storage_account.results.name
  quota                = var.artifacts_share_quota_gb
}

resource "azurerm_container_app_environment_storage" "artifacts" {
  count                        = var.create_apps ? 1 : 0
  name                         = local.artifacts_storage
  container_app_environment_id = azurerm_container_app_environment.env.id

  account_name = azurerm_storage_account.results.name
  share_name   = azurerm_storage_share.artifacts[0].name
  access_key   = azurerm_storage_account.results.primary_access_key
  access_mode  = "ReadWrite"
}

# ACR: grant pull to the UAMI (covers both apps)
resource "azurerm_role_assignment" "acr_pull_uami" {
  scope                = data.azurerm_container_registry.acr.id
  role_definition_name = "AcrPull"
  principal_id         = azurerm_user_assigned_identity.uami.principal_id
}

# -------- Optional: basic diagnostic metrics to Log Analytics --------
# (Using only metrics = safest cross-resource option)
resource "azurerm_monitor_diagnostic_setting" "sb_diag" {
  name                       = "${local.sb_ns_name}-diag"
  target_resource_id         = azurerm_servicebus_namespace.sb.id
  log_analytics_workspace_id = data.azurerm_log_analytics_workspace.la.id

  enabled_metric {
    category = "AllMetrics"
  }
}

resource "azurerm_monitor_diagnostic_setting" "aca_env_diag" {
  name                       = "${local.env_name}-diag"
  target_resource_id         = azurerm_container_app_environment.env.id
  log_analytics_workspace_id = data.azurerm_log_analytics_workspace.la.id

  enabled_metric {
    category = "AllMetrics"
  }
}

resource "azurerm_monitor_diagnostic_setting" "results_sa_table_diag" {
  name                       = "${local.results_sa}-table-diag"
  target_resource_id         = "${azurerm_storage_account.results.id}/tableServices/default"
  log_analytics_workspace_id = data.azurerm_log_analytics_workspace.la.id

  enabled_log {
    category = "StorageRead"
  }

  enabled_log {
    category = "StorageWrite"
  }

  enabled_log {
    category = "StorageDelete"
  }

  enabled_metric {
    category = "Capacity"
  }

  enabled_metric {
    category = "Transaction"
  }
}

resource "azurerm_monitor_diagnostic_setting" "results_sa_queue_diag" {
  name                       = "${local.results_sa}-queue-diag"
  target_resource_id         = "${azurerm_storage_account.results.id}/queueServices/default"
  log_analytics_workspace_id = data.azurerm_log_analytics_workspace.la.id

  enabled_log {
    category = "StorageRead"
  }

  enabled_log {
    category = "StorageWrite"
  }

  enabled_log {
    category = "StorageDelete"
  }

  enabled_metric {
    category = "Capacity"
  }

  enabled_metric {
    category = "Transaction"
  }
}
