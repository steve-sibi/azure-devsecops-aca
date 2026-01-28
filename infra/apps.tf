# Shared runtime limits/timeouts. These env vars are read by the API/Fetcher/Worker.
locals {
	  runtime_env_common = [
	    { name = "BLOCK_PRIVATE_NETWORKS", value = "true" },
	    { name = "MAX_DOWNLOAD_BYTES", value = tostring(1024 * 1024) }, # 1MB
	    { name = "MAX_REDIRECTS", value = "5" },
	    { name = "REQUEST_TIMEOUT", value = "10" },
	    { name = "WEB_MAX_HEADERS", value = "40" },
	    { name = "WEB_MAX_HEADER_VALUE_LEN", value = "600" },
	    { name = "URL_DEDUPE_TTL_SECONDS", value = tostring(var.url_dedupe_ttl_seconds) },
	    { name = "URL_DEDUPE_IN_PROGRESS_TTL_SECONDS", value = tostring(var.url_dedupe_in_progress_ttl_seconds) },
	    { name = "URL_DEDUPE_SCOPE", value = lower(var.url_dedupe_scope) },
	    { name = "URL_DEDUPE_INDEX_PARTITION", value = var.url_dedupe_index_partition },
	    { name = "URL_RESULT_VISIBILITY_DEFAULT", value = lower(var.url_result_visibility_default) },
	  ]

  consumer_tuning_env = [
    { name = "BATCH_SIZE", value = "10" },
    { name = "MAX_RETRIES", value = "5" },
    { name = "MAX_WAIT", value = "5" },
    { name = "PREFETCH", value = "20" },
  ]

  api_limits_env = [
    { name = "CLAMAV_TIMEOUT_SECONDS", value = "8" },
    { name = "FILE_SCAN_INCLUDE_VERSION", value = "true" },
    { name = "FILE_SCAN_MAX_BYTES", value = tostring(10 * 1024 * 1024) }, # 10MB
    { name = "MAX_DASHBOARD_POLL_SECONDS", value = "180" },
    { name = "RATE_LIMIT_WINDOW_SECONDS", value = "60" },
  ]

  result_store_env = [
    # Azure Table has a ~64KB per-property limit; details are compacted/truncated accordingly.
    { name = "RESULT_DETAILS_MAX_BYTES", value = "60000" },
  ]

  web_analysis_env = [
    { name = "WEB_MAX_HTML_BYTES", value = "300000" },
    { name = "WEB_MAX_INLINE_SCRIPT_CHARS", value = "80000" },
    { name = "WEB_MAX_RESOURCES", value = "25" },
    { name = "WEB_WHOIS_TIMEOUT_SECONDS", value = "3.0" },
  ]

  screenshot_env = [
    { name = "SCREENSHOT_FULL_PAGE", value = "false" },
    { name = "SCREENSHOT_JPEG_QUALITY", value = "60" },
    { name = "SCREENSHOT_SETTLE_MS", value = "750" },
    { name = "SCREENSHOT_TIMEOUT_SECONDS", value = "12" },
    { name = "SCREENSHOT_TTL_SECONDS", value = "0" },
    { name = "SCREENSHOT_VIEWPORT_HEIGHT", value = "720" },
    { name = "SCREENSHOT_VIEWPORT_WIDTH", value = "1280" },
  ]
}

# --- API app ---
resource "azurerm_container_app" "api" {
  count                        = var.create_apps ? 1 : 0
  name                         = local.api_name
  resource_group_name          = data.azurerm_resource_group.rg.name
  container_app_environment_id = azurerm_container_app_environment.env.id
  revision_mode                = "Single"
  max_inactive_revisions       = 100
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
        name        = "APPLICATIONINSIGHTS_CONNECTION_STRING"
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
        name  = "SCREENSHOT_CONTAINER"
        value = var.screenshot_container
      }
      env {
        name  = "SCREENSHOT_FORMAT"
        value = var.screenshot_format
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
      dynamic "env" {
        for_each = concat(local.runtime_env_common, local.api_limits_env, local.result_store_env)
        content {
          name  = env.value.name
          value = env.value.value
        }
      }
      env {
        name  = "CLAMAV_HOST"
        value = "127.0.0.1"
      }
      env {
        name  = "CLAMAV_PORT"
        value = "3310"
      }
    }

    # Sidecar ClamAV daemon for /file/scan.
    container {
      name   = "clamav"
      image  = "${data.azurerm_container_registry.acr.login_server}/${local.clamav_name}:${var.image_tag}"
      cpu    = 0.5
      memory = "1Gi"

      env {
        name  = "CLAMD_CONFIG_FILE"
        value = "/etc/clamav/clamd.sidecar.conf"
      }
    }

    min_replicas = var.api_min_replicas
    max_replicas = var.api_max_replicas
  }

  depends_on = [
    azurerm_role_assignment.kv_secrets_uami,
    azurerm_role_assignment.acr_pull_uami,
  ]
}

# --- Fetcher app (downloads + artifact handoff) ---
resource "azurerm_container_app" "fetcher" {
  count                        = var.create_apps ? 1 : 0
  name                         = local.fetcher_name
  resource_group_name          = data.azurerm_resource_group.rg.name
  container_app_environment_id = azurerm_container_app_environment.env.id
  revision_mode                = "Single"
  max_inactive_revisions       = 100
  tags                         = var.tags

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.uami.id]
  }

  registry {
    server   = data.azurerm_container_registry.acr.login_server
    identity = azurerm_user_assigned_identity.uami.id
  }

  secret {
    name                = "sb-listen"
    key_vault_secret_id = azurerm_key_vault_secret.sb_listen.id
    identity            = azurerm_user_assigned_identity.uami.id
  }

  secret {
    name                = "sb-scan-send"
    key_vault_secret_id = azurerm_key_vault_secret.sb_scan_send.id
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

  # KEDA scaler needs Manage to read queue metrics
  secret {
    name                = "sb-manage"
    key_vault_secret_id = azurerm_key_vault_secret.sb_manage.id
    identity            = azurerm_user_assigned_identity.uami.id
  }

  template {
    container {
      name   = "fetcher"
      image  = "${data.azurerm_container_registry.acr.login_server}/${local.worker_name}:${var.image_tag}"
      cpu    = 0.5
      memory = "1Gi"

      env {
        name  = "WORKER_MODE"
        value = "fetcher"
      }
      env {
        name        = "SERVICEBUS_CONN"
        secret_name = "sb-listen"
      }
      env {
        name        = "SERVICEBUS_SCAN_CONN"
        secret_name = "sb-scan-send"
      }
      env {
        name  = "QUEUE_NAME"
        value = var.queue_name
      }
      env {
        name  = "SCAN_QUEUE_NAME"
        value = local.scan_queue_name
      }
      env {
        name        = "APPINSIGHTS_CONN"
        secret_name = "appi-conn"
      }
      env {
        name        = "APPLICATIONINSIGHTS_CONNECTION_STRING"
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
        name  = "ARTIFACT_DIR"
        value = "/artifacts"
      }
      dynamic "env" {
        for_each = concat(local.runtime_env_common, local.consumer_tuning_env, local.result_store_env)
        content {
          name  = env.value.name
          value = env.value.value
        }
      }
      volume_mounts {
        name = "artifacts"
        path = "/artifacts"
      }
    }

    volume {
      name         = "artifacts"
      storage_name = azurerm_container_app_environment_storage.artifacts[0].name
      storage_type = "AzureFile"
    }

    min_replicas = 0
    max_replicas = 5

    custom_scale_rule {
      name             = "sb-scaler"
      custom_rule_type = "azure-servicebus"
      metadata = {
        queueName    = azurerm_servicebus_queue.q.name
        namespace    = azurerm_servicebus_namespace.sb.name
        messageCount = "20"
      }
      authentication {
        secret_name       = "sb-manage"
        trigger_parameter = "connection"
      }
    }
  }

  depends_on = [
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
  max_inactive_revisions       = 100
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
    name                = "sb-scan-listen"
    key_vault_secret_id = azurerm_key_vault_secret.sb_scan_listen.id
    identity            = azurerm_user_assigned_identity.uami.id
  }

  secret {
    name                = "sb-scan-manage"
    key_vault_secret_id = azurerm_key_vault_secret.sb_scan_manage.id
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
      cpu    = 1.0
      memory = "2Gi"

      env {
        name        = "SERVICEBUS_CONN"
        secret_name = "sb-scan-listen"
      }
      env {
        name  = "QUEUE_NAME"
        value = local.scan_queue_name
      }
      env {
        name        = "APPINSIGHTS_CONN"
        secret_name = "appi-conn"
      }
      env {
        name        = "APPLICATIONINSIGHTS_CONNECTION_STRING"
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
        name  = "WORKER_MODE"
        value = "analyzer"
      }
      env {
        name  = "ARTIFACT_DIR"
        value = "/artifacts"
      }
      env {
        name  = "ARTIFACT_DELETE_ON_SUCCESS"
        value = "false"
      }
      dynamic "env" {
        for_each = concat(local.runtime_env_common, local.consumer_tuning_env, local.result_store_env, local.web_analysis_env, local.screenshot_env)
        content {
          name  = env.value.name
          value = env.value.value
        }
      }
      env {
        name  = "CAPTURE_SCREENSHOTS"
        value = tostring(var.capture_screenshots)
      }
      env {
        name  = "SCREENSHOT_CONTAINER"
        value = var.screenshot_container
      }
      env {
        name  = "SCREENSHOT_FORMAT"
        value = var.screenshot_format
      }
      volume_mounts {
        name = "artifacts"
        path = "/artifacts"
      }
    }

    volume {
      name         = "artifacts"
      storage_name = azurerm_container_app_environment_storage.artifacts[0].name
      storage_type = "AzureFile"
    }

    min_replicas = 0
    max_replicas = 5

    custom_scale_rule {
      name             = "sb-scaler"
      custom_rule_type = "azure-servicebus"
      metadata = {
        queueName    = azurerm_servicebus_queue.q_scan.name
        namespace    = azurerm_servicebus_namespace.sb.name
        messageCount = "20"
      }
      authentication {
        secret_name       = "sb-scan-manage"
        trigger_parameter = "connection"
      }
    }
  }

  depends_on = [
    azurerm_role_assignment.kv_secrets_uami,
    azurerm_role_assignment.acr_pull_uami,
  ]
}
