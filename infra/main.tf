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
  # stop Terraform from attempting subscription-scoped registrations
  resource_provider_registrations = "none"
}

locals {
  rg_name     = "${var.prefix}-rg"
  acr_name    = "${var.prefix}acr"
  kv_name     = "${var.prefix}-kv"
  sb_ns_name  = "${var.prefix}-sbns"
  la_name     = "${var.prefix}-la"
  ai_name     = "${var.prefix}-appi"
  env_name    = "${var.prefix}-acaenv"
  api_name    = "${var.prefix}-api"
  worker_name = "${var.prefix}-worker"
}

resource "azurerm_resource_group" "rg" {
  name     = local.rg_name
  location = var.location
}

# Log Analytics + App Insights
resource "azurerm_log_analytics_workspace" "la" {
  name                = local.la_name
  location            = var.location
  resource_group_name = azurerm_resource_group.rg.name
  sku                 = "PerGB2018"
  retention_in_days   = 30
}

resource "azurerm_application_insights" "appi" {
  name                = local.ai_name
  location            = var.location
  resource_group_name = azurerm_resource_group.rg.name
  application_type    = "web"
  workspace_id        = azurerm_log_analytics_workspace.la.id
}

# ACR
resource "azurerm_container_registry" "acr" {
  name                = local.acr_name
  resource_group_name = azurerm_resource_group.rg.name
  location            = var.location
  sku                 = "Basic"
  admin_enabled       = false
}

data "azurerm_client_config" "current" {}

# Key Vault
resource "azurerm_key_vault" "kv" {
  name                       = local.kv_name
  resource_group_name        = azurerm_resource_group.rg.name
  location                   = var.location
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "standard"
  purge_protection_enabled   = true
  soft_delete_retention_days = 7
}

# Service Bus (Standard) + queue + SAS (for simplicity)
resource "azurerm_servicebus_namespace" "sb" {
  name                = local.sb_ns_name
  resource_group_name = azurerm_resource_group.rg.name
  location            = var.location
  sku                 = "Standard"
  # zone_redundant = true  # <-- Only valid with Premium. Remove for Standard.
  minimum_tls_version = "1.2"
}

resource "azurerm_servicebus_queue" "q" {
  name                  = var.queue_name
  namespace_id          = azurerm_servicebus_namespace.sb.id
  max_size_in_megabytes = 1024
}

resource "azurerm_servicebus_namespace_authorization_rule" "sas" {
  name         = "app-shared"
  namespace_id = azurerm_servicebus_namespace.sb.id
  listen       = true
  send         = true
  manage       = false
}

# Store SB connection string in Key Vault
resource "azurerm_key_vault_secret" "sb_conn" {
  name         = "ServiceBusConnection"
  value        = azurerm_servicebus_namespace_authorization_rule.sas.primary_connection_string
  key_vault_id = azurerm_key_vault.kv.id
}

# Container Apps Environment (Consumption)
resource "azurerm_container_app_environment" "env" {
  name                       = local.env_name
  location                   = var.location
  resource_group_name        = azurerm_resource_group.rg.name
  log_analytics_workspace_id = azurerm_log_analytics_workspace.la.id
}

# API app (created only when create_apps = true)
resource "azurerm_container_app" "api" {
  count                        = var.create_apps ? 1 : 0
  name                         = local.api_name
  resource_group_name          = azurerm_resource_group.rg.name
  container_app_environment_id = azurerm_container_app_environment.env.id
  revision_mode                = "Single"

  identity {
    type = "SystemAssigned"
  }

  ingress {
    external_enabled = true
    target_port      = 8000
    transport        = "auto"

    # required: at least one traffic_weight block
    traffic_weight {
      percentage      = 100
      latest_revision = true
    }
  }

  registry {
    server   = azurerm_container_registry.acr.login_server
    identity = "system"
  }

  secret {
    name                = "sb-conn"
    key_vault_secret_id = azurerm_key_vault_secret.sb_conn.id
  }

  secret {
    name  = "appi-conn"
    value = azurerm_application_insights.appi.connection_string
  }

  template {
    container {
      name   = "api"
      image  = "${azurerm_container_registry.acr.login_server}/${local.api_name}:${var.image_tag}"
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

# Worker app (created only when create_apps = true)
resource "azurerm_container_app" "worker" {
  count                        = var.create_apps ? 1 : 0
  name                         = local.worker_name
  resource_group_name          = azurerm_resource_group.rg.name
  container_app_environment_id = azurerm_container_app_environment.env.id
  revision_mode                = "Single"

  identity {
    type = "SystemAssigned"
  }

  registry {
    server   = azurerm_container_registry.acr.login_server
    identity = "System"
  }

  secret {
    name                = "sb-conn"
    key_vault_secret_id = azurerm_key_vault_secret.sb_conn.id
  }

  secret {
    name  = "appi-conn"
    value = azurerm_application_insights.appi.connection_string
  }

  template {
    container {
      name   = "worker"
      image  = "${azurerm_container_registry.acr.login_server}/${local.worker_name}:${var.image_tag}"
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

    # <-- scaling is here (attributes, not a 'scale' block)
    min_replicas = 0
    max_replicas = 5

    # KEDA Service Bus queue scaler
    custom_scale_rule {
      name             = "sb-scaler"
      custom_rule_type = "azure-servicebus"
      # metadata values must be strings
      metadata = {
        queueName    = azurerm_servicebus_queue.q.name
        messageCount = "20" # 1 replica per 20 messages
      }
      authentication {
        secret_name       = "sb-conn" # your Container App secret that holds the SB connection string
        trigger_parameter = "connection"
      }
    }
  }

}

# RBAC for Key Vault (so the apps can read secrets)
resource "azurerm_role_assignment" "kv_reader_api" {
  count                = var.create_apps ? 1 : 0
  scope                = azurerm_key_vault.kv.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_container_app.api[0].identity[0].principal_id
}

resource "azurerm_role_assignment" "kv_reader_worker" {
  count                = var.create_apps ? 1 : 0
  scope                = azurerm_key_vault.kv.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_container_app.worker[0].identity[0].principal_id
}

# Allow API to pull images from ACR
resource "azurerm_role_assignment" "acr_pull_api" {
  count                = var.create_apps ? 1 : 0
  scope                = azurerm_container_registry.acr.id
  role_definition_name = "AcrPull"
  principal_id         = azurerm_container_app.api[0].identity[0].principal_id
}

# Allow Worker to pull images from ACR
resource "azurerm_role_assignment" "acr_pull_worker" {
  count                = var.create_apps ? 1 : 0
  scope                = azurerm_container_registry.acr.id
  role_definition_name = "AcrPull"
  principal_id         = azurerm_container_app.worker[0].identity[0].principal_id
}
