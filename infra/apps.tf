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
    exposed_port     = 3310
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
      cpu    = 1.0
      memory = "2Gi"
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
        name  = "CLAMAV_HOSTS"
        value = "${local.clamav_name},${try(azurerm_container_app.clamav[0].ingress[0].fqdn, "")}"
      }
      env {
        name  = "CLAMAV_PORT"
        value = "3310"
      }
      env {
        name  = "SCAN_ENGINE"
        value = "clamav,yara"
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

