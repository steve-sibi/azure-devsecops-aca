terraform {
  required_version = ">= 1.6"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.116"
    }
  }
}

provider "azurerm" {
  features {}
  # We register providers once manually; CI should not attempt it.
  skip_provider_registration = true
}

locals {
  rg_name     = "${var.prefix}-rg" # kept for naming only
  acr_name    = "${var.prefix}acr"
  kv_name     = "${var.prefix}-kv"
  sb_ns_name  = "${var.prefix}-sbns"
  la_name     = "${var.prefix}-la"
  ai_name     = "${var.prefix}-appi"
  env_name    = "${var.prefix}-acaenv"
  api_name    = "${var.prefix}-api"
  worker_name = "${var.prefix}-worker"
}

# Use EXISTING Resource Group
data "azurerm_resource_group" "rg" {
  name = var.resource_group_name
}

# EXISTING foundation (read-only)
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

data "azurerm_servicebus_namespace" "sb" {
  name                = local.sb_ns_name
  resource_group_name = data.azurerm_resource_group.rg.name
}

data "azurerm_client_config" "current" {}

# NEW (or imported) pieces
resource "azurerm_application_insights" "appi" {
  name                = local.ai_name
  location            = data.azurerm_resource_group.rg.location
  resource_group_name = data.azurerm_resource_group.rg.name
  application_type    = "web"
  workspace_id        = data.azurerm_log_analytics_workspace.la.id
}

resource "azurerm_servicebus_queue" "q" {
  name                  = var.queue_name
  namespace_id          = data.azurerm_servicebus_namespace.sb.id
  max_size_in_megabytes = 1024
}

resource "azurerm_servicebus_namespace_authorization_rule" "sas" {
  name         = "app-shared"
  namespace_id = data.azurerm_servicebus_namespace.sb.id
  listen       = true
  send         = true
  manage       = false
}

# CI principal needs secret perms (works when KV uses access policies)
resource "azurerm_key_vault_access_policy" "kv_ci" {
  key_vault_id       = data.azurerm_key_vault.kv.id
  tenant_id          = data.azurerm_client_config.current.tenant_id
  object_id          = data.azurerm_client_config.current.object_id
  secret_permissions = ["Get", "Set", "List", "Delete", "Purge"]
}

# Store SB connection string in Key Vault
resource "azurerm_key_vault_secret" "sb_conn" {
  name            = "ServiceBusConnection"
  value           = azurerm_servicebus_namespace_authorization_rule.sas.primary_connection_string
  key_vault_id    = data.azurerm_key_vault.kv.id
  content_type    = "servicebus-connection"
  expiration_date = timeadd(timestamp(), "8760h") # ~1 year
  depends_on      = [azurerm_key_vault_access_policy.kv_ci]
}

# Container Apps Environment (new)
resource "azurerm_container_app_environment" "env" {
  name                       = local.env_name
  location                   = data.azurerm_resource_group.rg.location
  resource_group_name        = data.azurerm_resource_group.rg.name
  log_analytics_workspace_id = data.azurerm_log_analytics_workspace.la.id
}

# --------------------------
# API app (created when create_apps = true)
# --------------------------
resource "azurerm_container_app" "api" {
  count                        = var.create_apps ? 1 : 0
  name                         = local.api_name
  resource_group_name          = data.azurerm_resource_group.rg.name
  container_app_environment_id = azurerm_container_app_environment.env.id
  revision_mode                = "Single"

  identity { type = "SystemAssigned" }

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
    identity = "System"
  }

  # IMPORTANT: identity="system" to fetch secret from Key Vault
  secret {
    name                = "sb-conn"
    key_vault_secret_id = azurerm_key_vault_secret.sb_conn.id
    identity            = "system"
  }
  secret {
    name  = "appi-conn"
    value = azurerm_application_insights.appi.connection_string
  }

  template {
    container {
      name   = "api"
      image  = "${data.azurerm_container_registry.acr.login_server}/${local.api_name}:${var.image_tag}"
      cpu    = 0.25
      memory = "0.5Gi"

      env {
        name        = "SERVICEBUS_CONN"
        secret_name = "sb-conn"
      }
      env {
        name  = "QUEUE_NAME"
        value = var.queue_name
      }
      env {
        name        = "APPINSIGHTS_CONN"
        secret_name = "appi-conn"
      }
    }
  }
}

# KV read access for API MI
resource "azurerm_key_vault_access_policy" "kv_api" {
  count              = var.create_apps ? 1 : 0
  key_vault_id       = data.azurerm_key_vault.kv.id
  tenant_id          = data.azurerm_client_config.current.tenant_id
  object_id          = azurerm_container_app.api[0].identity[0].principal_id
  secret_permissions = ["Get", "List"]
  depends_on         = [azurerm_container_app.api]
}

# --------------------------
# Worker app (created when create_apps = true)
# --------------------------
resource "azurerm_container_app" "worker" {
  count                        = var.create_apps ? 1 : 0
  name                         = local.worker_name
  resource_group_name          = data.azurerm_resource_group.rg.name
  container_app_environment_id = azurerm_container_app_environment.env.id
  revision_mode                = "Single"

  identity { type = "SystemAssigned" }

  registry {
    server   = data.azurerm_container_registry.acr.login_server
    identity = "System"
  }

  # IMPORTANT: identity="system" to fetch secret from Key Vault
  secret {
    name                = "sb-conn"
    key_vault_secret_id = azurerm_key_vault_secret.sb_conn.id
    identity            = "system"
  }
  secret {
    name  = "appi-conn"
    value = azurerm_application_insights.appi.connection_string
  }

  template {
    container {
      name   = "worker"
      image  = "${data.azurerm_container_registry.acr.login_server}/${local.worker_name}:${var.image_tag}"
      cpu    = 0.25
      memory = "0.5Gi"

      env {
        name        = "SERVICEBUS_CONN"
        secret_name = "sb-conn"
      }
      env {
        name  = "QUEUE_NAME"
        value = var.queue_name
      }
      env {
        name        = "APPINSIGHTS_CONN"
        secret_name = "appi-conn"
      }
    }

    min_replicas = 0
    max_replicas = 5

    # KEDA: Azure Service Bus queue scaler
    custom_scale_rule {
      name             = "sb-scaler"
      custom_rule_type = "azure-servicebus"
      metadata = {
        queueName    = azurerm_servicebus_queue.q.name
        messageCount = "20"
      }
      authentication {
        secret_name       = "sb-conn"
        trigger_parameter = "connection"
      }
    }
  }
}

# KV read access for WORKER MI
resource "azurerm_key_vault_access_policy" "kv_worker" {
  count              = var.create_apps ? 1 : 0
  key_vault_id       = data.azurerm_key_vault.kv.id
  tenant_id          = data.azurerm_client_config.current.tenant_id
  object_id          = azurerm_container_app.worker[0].identity[0].principal_id
  secret_permissions = ["Get", "List"]
  depends_on         = [azurerm_container_app.worker]
}

# ACR pull (needs User Access Administrator/Owner on RG)
resource "azurerm_role_assignment" "acr_pull_api" {
  count                = var.create_apps ? 1 : 0
  scope                = data.azurerm_container_registry.acr.id
  role_definition_name = "AcrPull"
  principal_id         = azurerm_container_app.api[0].identity[0].principal_id
}

resource "azurerm_role_assignment" "acr_pull_worker" {
  count                = var.create_apps ? 1 : 0
  scope                = data.azurerm_container_registry.acr.id
  role_definition_name = "AcrPull"
  principal_id         = azurerm_container_app.worker[0].identity[0].principal_id
}
