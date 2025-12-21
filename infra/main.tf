terraform {
  required_version = ">= 1.6"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.116"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

provider "azurerm" {
  features {}
  # provider registrations are already handled out-of-band
  skip_provider_registration = true
}

locals {
  acr_name      = "${var.prefix}acr"
  kv_name       = "${var.prefix}-kv"
  sb_ns_name    = "${var.prefix}-sbns"
  la_name       = "${var.prefix}-la"
  ai_name       = "${var.prefix}-appi"
  env_name      = "${var.prefix}-acaenv"
  api_name      = "${var.prefix}-api"
  worker_name   = "${var.prefix}-worker"
  clamav_name   = "${var.prefix}-clamav"
  uami_name     = "${var.prefix}-uami"
  results_sa    = "${var.prefix}scan"
  results_table = var.results_table_name
}

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
  tags                = var.tags
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

# Storage for scan results (Table)
resource "azurerm_storage_account" "results" {
  name                            = local.results_sa
  resource_group_name             = data.azurerm_resource_group.rg.name
  location                        = data.azurerm_resource_group.rg.location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  min_tls_version                 = "TLS1_2"
  allow_nested_items_to_be_public = false
  tags                            = var.tags
}

resource "azurerm_storage_table" "results" {
  name                 = local.results_table
  storage_account_name = azurerm_storage_account.results.name
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

# ---------- Key Vault access & secrets ----------
# CI principal can manage secrets (used to create/update secrets & allow destroy)
resource "azurerm_key_vault_access_policy" "kv_ci" {
  key_vault_id       = data.azurerm_key_vault.kv.id
  tenant_id          = data.azurerm_client_config.current.tenant_id
  object_id          = data.azurerm_client_config.current.object_id
  secret_permissions = ["Get", "Set", "List", "Delete", "Purge"]
}

# Ensure the principal running Terraform can use Key Vault when RBAC is enabled
resource "azurerm_role_assignment" "kv_tf" {
  scope                = data.azurerm_key_vault.kv.id
  role_definition_name = "Key Vault Secrets Officer"
  principal_id         = data.azurerm_client_config.current.object_id
}

# Generate and store an API key for the public API (KV-backed)
resource "random_password" "api_key" {
  length  = 32
  special = false
}

resource "azurerm_key_vault_secret" "api_key" {
  name            = "ApiKey"
  value           = random_password.api_key.result
  key_vault_id    = data.azurerm_key_vault.kv.id
  content_type    = "api-key"
  expiration_date = timeadd(timestamp(), "8760h")
  depends_on      = [azurerm_key_vault_access_policy.kv_ci, azurerm_role_assignment.kv_tf]
}

# Store distinct SB connection strings in KV
resource "azurerm_key_vault_secret" "sb_send" {
  name            = "ServiceBusSend"
  value           = azurerm_servicebus_queue_authorization_rule.q_send.primary_connection_string
  key_vault_id    = data.azurerm_key_vault.kv.id
  content_type    = "servicebus-send"
  expiration_date = timeadd(timestamp(), "8760h") # ~1 year
  depends_on      = [azurerm_key_vault_access_policy.kv_ci, azurerm_role_assignment.kv_tf]
}

resource "azurerm_key_vault_secret" "sb_listen" {
  name            = "ServiceBusListen"
  value           = azurerm_servicebus_queue_authorization_rule.q_listen.primary_connection_string
  key_vault_id    = data.azurerm_key_vault.kv.id
  content_type    = "servicebus-listen"
  expiration_date = timeadd(timestamp(), "8760h")
  depends_on      = [azurerm_key_vault_access_policy.kv_ci, azurerm_role_assignment.kv_tf]
}

resource "azurerm_key_vault_secret" "sb_manage" {
  name            = "ServiceBusManage"
  value           = azurerm_servicebus_queue_authorization_rule.q_manage.primary_connection_string
  key_vault_id    = data.azurerm_key_vault.kv.id
  content_type    = "servicebus-manage"
  expiration_date = timeadd(timestamp(), "8760h")
  depends_on      = [azurerm_key_vault_access_policy.kv_ci, azurerm_role_assignment.kv_tf]
}

resource "azurerm_key_vault_secret" "results_conn" {
  name         = "ScanResultsConn"
  value        = azurerm_storage_account.results.primary_connection_string
  key_vault_id = data.azurerm_key_vault.kv.id
  content_type = "table-connection-string"
  depends_on   = [azurerm_key_vault_access_policy.kv_ci, azurerm_role_assignment.kv_tf]
}

# Give the UAMI read on KV so apps can resolve secrets at creation time
resource "azurerm_key_vault_access_policy" "kv_uami" {
  key_vault_id       = data.azurerm_key_vault.kv.id
  tenant_id          = data.azurerm_client_config.current.tenant_id
  object_id          = azurerm_user_assigned_identity.uami.principal_id
  secret_permissions = ["Get", "List"]
}

# RBAC (preferred for KV): allow UAMI to read secrets
resource "azurerm_role_assignment" "kv_secrets_uami" {
  scope                = data.azurerm_key_vault.kv.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.uami.principal_id
}

# Container Apps Environment
resource "azurerm_container_app_environment" "env" {
  name                       = local.env_name
  location                   = data.azurerm_resource_group.rg.location
  resource_group_name        = data.azurerm_resource_group.rg.name
  log_analytics_workspace_id = data.azurerm_log_analytics_workspace.la.id
  tags                       = var.tags
}

# --- ClamAV (internal TCP microservice) ---
resource "azurerm_container_app" "clamav" {
  count                        = var.create_apps ? 1 : 0
  name                         = local.clamav_name
  resource_group_name          = data.azurerm_resource_group.rg.name
  container_app_environment_id = azurerm_container_app_environment.env.id
  revision_mode                = "Single"
  tags                         = var.tags

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.uami.id]
  }

  ingress {
    external_enabled = false
    target_port      = 3310
    transport        = "tcp"
    traffic_weight {
      percentage      = 100
      latest_revision = true
    }
  }

  registry {
    server   = data.azurerm_container_registry.acr.login_server
    identity = azurerm_user_assigned_identity.uami.id
  }

  template {
    container {
      name   = "clamav"
      image  = "${data.azurerm_container_registry.acr.login_server}/${local.clamav_name}:${var.image_tag}"
      cpu    = 0.5
      memory = "1Gi"
    }

    min_replicas = 1
    max_replicas = 1
  }

  depends_on = [
    azurerm_role_assignment.acr_pull_uami,
  ]
}

# --- API app ---
resource "azurerm_container_app" "api" {
  count                        = var.create_apps ? 1 : 0
  name                         = local.api_name
  resource_group_name          = data.azurerm_resource_group.rg.name
  container_app_environment_id = azurerm_container_app_environment.env.id
  revision_mode                = "Single"
  tags                         = var.tags

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.uami.id]
  }

  ingress {
    external_enabled = true
    target_port      = 8000
    transport        = "auto"
    traffic_weight {
      percentage      = 100
      latest_revision = true
    }
  }

  registry {
    server   = data.azurerm_container_registry.acr.login_server
    identity = azurerm_user_assigned_identity.uami.id
  }

  # Secrets from Key Vault (and App Insights connection string)
  secret {
    name                = "sb-send"
    key_vault_secret_id = azurerm_key_vault_secret.sb_send.id
    identity            = azurerm_user_assigned_identity.uami.id
  }

  secret {
    name  = "appi-conn"
    value = azurerm_application_insights.appi.connection_string
  }

  secret {
    name                = "results-conn"
    key_vault_secret_id = azurerm_key_vault_secret.results_conn.id
    identity            = azurerm_user_assigned_identity.uami.id
  }

  secret {
    name                = "api-key"
    key_vault_secret_id = azurerm_key_vault_secret.api_key.id
    identity            = azurerm_user_assigned_identity.uami.id
  }

  template {
    container {
      name   = "api"
      image  = "${data.azurerm_container_registry.acr.login_server}/${local.api_name}:${var.image_tag}"
      cpu    = 0.25
      memory = "0.5Gi"

      env {
        name        = "SERVICEBUS_CONN"
        secret_name = "sb-send"
      }
      env {
        name  = "QUEUE_NAME"
        value = var.queue_name
      }
      env {
        name        = "APPINSIGHTS_CONN"
        secret_name = "appi-conn"
      }
      env {
        name        = "RESULT_STORE_CONN"
        secret_name = "results-conn"
      }
      env {
        name  = "RESULT_TABLE"
        value = local.results_table
      }
      env {
        name        = "API_KEY"
        secret_name = "api-key"
      }
      env {
        name  = "REQUIRE_API_KEY"
        value = "true"
      }
      env {
        name  = "RATE_LIMIT_RPM"
        value = tostring(var.api_rate_limit_rpm)
      }
      env {
        name  = "BLOCK_PRIVATE_NETWORKS"
        value = "true"
      }
    }

    min_replicas = var.api_min_replicas
    max_replicas = var.api_max_replicas
  }

  depends_on = [
    azurerm_key_vault_access_policy.kv_uami,
    azurerm_role_assignment.kv_secrets_uami,
    azurerm_role_assignment.acr_pull_uami,
  ]
}

# --- Worker app ---
resource "azurerm_container_app" "worker" {
  count                        = var.create_apps ? 1 : 0
  name                         = local.worker_name
  resource_group_name          = data.azurerm_resource_group.rg.name
  container_app_environment_id = azurerm_container_app_environment.env.id
  revision_mode                = "Single"
  tags                         = var.tags

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.uami.id]
  }

  registry {
    server   = data.azurerm_container_registry.acr.login_server
    identity = azurerm_user_assigned_identity.uami.id
  }

  # KV-backed secrets for runtime and scaling
  secret {
    name                = "sb-listen"
    key_vault_secret_id = azurerm_key_vault_secret.sb_listen.id
    identity            = azurerm_user_assigned_identity.uami.id
  }

  secret {
    name                = "sb-manage"
    key_vault_secret_id = azurerm_key_vault_secret.sb_manage.id
    identity            = azurerm_user_assigned_identity.uami.id
  }

  secret {
    name  = "appi-conn"
    value = azurerm_application_insights.appi.connection_string
  }

  secret {
    name                = "results-conn"
    key_vault_secret_id = azurerm_key_vault_secret.results_conn.id
    identity            = azurerm_user_assigned_identity.uami.id
  }

  template {
    container {
      name   = "worker"
      image  = "${data.azurerm_container_registry.acr.login_server}/${local.worker_name}:${var.image_tag}"
      cpu    = 0.25
      memory = "0.5Gi"

      env {
        name        = "SERVICEBUS_CONN"
        secret_name = "sb-listen"
      }
      env {
        name  = "QUEUE_NAME"
        value = var.queue_name
      }
      env {
        name        = "APPINSIGHTS_CONN"
        secret_name = "appi-conn"
      }
      env {
        name        = "RESULT_STORE_CONN"
        secret_name = "results-conn"
      }
      env {
        name  = "RESULT_TABLE"
        value = local.results_table
      }
      env {
        name  = "BLOCK_PRIVATE_NETWORKS"
        value = "true"
      }
      env {
        name  = "MAX_REDIRECTS"
        value = "5"
      }
      env {
        name  = "CLAMAV_HOST"
        value = try(azurerm_container_app.clamav[0].ingress[0].fqdn, "")
      }
      env {
        name  = "CLAMAV_PORT"
        value = "3310"
      }
      env {
        name  = "SCAN_ENGINE"
        value = "clamav"
      }
    }

    min_replicas = 0
    max_replicas = 5

    custom_scale_rule {
      name             = "sb-scaler"
      custom_rule_type = "azure-servicebus"
      metadata = {
        queueName    = azurerm_servicebus_queue.q.name
        messageCount = "20"
      }
      authentication {
        secret_name       = "sb-manage"
        trigger_parameter = "connection"
      }
    }
  }

  depends_on = [
    azurerm_key_vault_access_policy.kv_uami,
    azurerm_role_assignment.kv_secrets_uami,
    azurerm_role_assignment.acr_pull_uami,
  ]
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

  metric {
    category = "AllMetrics"
    enabled  = true
  }
}

resource "azurerm_monitor_diagnostic_setting" "aca_env_diag" {
  name                       = "${local.env_name}-diag"
  target_resource_id         = azurerm_container_app_environment.env.id
  log_analytics_workspace_id = data.azurerm_log_analytics_workspace.la.id

  metric {
    category = "AllMetrics"
    enabled  = true
  }
}
