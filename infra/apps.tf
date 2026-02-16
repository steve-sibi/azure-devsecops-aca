# Shared runtime limits/timeouts. These env vars are read by the API/Fetcher/Worker.
locals {
  runtime_env_common = [
    { name = "BLOCK_PRIVATE_NETWORKS", value = "true" },
    { name = "MAX_DOWNLOAD_BYTES", value = tostring(1024 * 1024) }, # 1MB
    { name = "MAX_REDIRECTS", value = "5" },
    { name = "REQUEST_TIMEOUT", value = "10" },
    { name = "OTEL_ENABLED", value = tostring(var.otel_enabled) },
    { name = "OTEL_TRACES_SAMPLER_RATIO", value = tostring(var.otel_traces_sampler_ratio) },
    { name = "OTEL_SERVICE_NAMESPACE", value = var.otel_service_namespace },
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
    { name = "WEB_WHOIS_TIMEOUT_SECONDS", value = tostring(var.web_whois_timeout_seconds) },
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

  shared_secret_defs = [
    {
      name  = "appi-conn"
      value = azurerm_application_insights.appi.connection_string
    },
    {
      name                = "results-conn"
      key_vault_secret_id = azurerm_key_vault_secret.runtime["results_conn"].id
      identity            = azurerm_user_assigned_identity.uami.id
    },
    {
      name                = "webpubsub-conn"
      key_vault_secret_id = azurerm_key_vault_secret.runtime["webpubsub_conn"].id
      identity            = azurerm_user_assigned_identity.uami.id
    },
  ]

  shared_env_defs = [
    { name = "APPINSIGHTS_CONN", secret_name = "appi-conn" },
    { name = "APPLICATIONINSIGHTS_CONNECTION_STRING", secret_name = "appi-conn" },
    { name = "RESULT_STORE_CONN", secret_name = "results-conn" },
    { name = "WEBPUBSUB_CONNECTION_STRING", secret_name = "webpubsub-conn" },
    { name = "WEBPUBSUB_HUB", value = var.webpubsub_hub_name },
    { name = "RESULT_TABLE", value = local.results_table },
  ]

  api_secret_defs = [
    for secret in concat(
      local.shared_secret_defs,
      [
        {
          name                = "sb-send"
          key_vault_secret_id = azurerm_key_vault_secret.runtime["sb_send"].id
          identity            = azurerm_user_assigned_identity.uami.id
        },
        {
          name                = "api-key"
          key_vault_secret_id = azurerm_key_vault_secret.api_key.id
          identity            = azurerm_user_assigned_identity.uami.id
        },
      ],
      ) : merge(
      {
        value               = null
        key_vault_secret_id = null
        identity            = null
      },
      secret,
    )
  ]

  fetcher_secret_defs = [
    for secret in concat(
      local.shared_secret_defs,
      [
        {
          name                = "sb-listen"
          key_vault_secret_id = azurerm_key_vault_secret.runtime["sb_listen"].id
          identity            = azurerm_user_assigned_identity.uami.id
        },
        {
          name                = "sb-scan-send"
          key_vault_secret_id = azurerm_key_vault_secret.runtime["sb_scan_send"].id
          identity            = azurerm_user_assigned_identity.uami.id
        },
        {
          name                = "sb-manage"
          key_vault_secret_id = azurerm_key_vault_secret.runtime["sb_manage"].id
          identity            = azurerm_user_assigned_identity.uami.id
        },
      ],
      ) : merge(
      {
        value               = null
        key_vault_secret_id = null
        identity            = null
      },
      secret,
    )
  ]

  worker_secret_defs = [
    for secret in concat(
      local.shared_secret_defs,
      [
        {
          name                = "sb-scan-listen"
          key_vault_secret_id = azurerm_key_vault_secret.runtime["sb_scan_listen"].id
          identity            = azurerm_user_assigned_identity.uami.id
        },
        {
          name                = "sb-scan-manage"
          key_vault_secret_id = azurerm_key_vault_secret.runtime["sb_scan_manage"].id
          identity            = azurerm_user_assigned_identity.uami.id
        },
      ],
      ) : merge(
      {
        value               = null
        key_vault_secret_id = null
        identity            = null
      },
      secret,
    )
  ]

  api_env_defs = [
    for env in concat(
      [
        { name = "SERVICEBUS_CONN", secret_name = "sb-send" },
        { name = "QUEUE_NAME", value = var.queue_name },
      ],
      local.shared_env_defs,
      [
        { name = "SCREENSHOT_CONTAINER", value = var.screenshot_container },
        { name = "SCREENSHOT_FORMAT", value = var.screenshot_format },
        { name = "API_KEY", secret_name = "api-key" },
        { name = "REQUIRE_API_KEY", value = "true" },
        { name = "RATE_LIMIT_RPM", value = tostring(var.api_rate_limit_rpm) },
      ],
      local.runtime_env_common,
      local.api_limits_env,
      local.result_store_env,
      [
        { name = "CLAMAV_HOST", value = "127.0.0.1" },
        { name = "CLAMAV_PORT", value = "3310" },
      ],
      ) : merge(
      {
        value       = null
        secret_name = null
      },
      env,
    )
  ]

  fetcher_env_defs = [
    for env in concat(
      [
        { name = "WORKER_MODE", value = "fetcher" },
        { name = "SERVICEBUS_CONN", secret_name = "sb-listen" },
        { name = "SERVICEBUS_SCAN_CONN", secret_name = "sb-scan-send" },
        { name = "QUEUE_NAME", value = var.queue_name },
        { name = "SCAN_QUEUE_NAME", value = local.scan_queue_name },
        { name = "ARTIFACT_DIR", value = "/artifacts" },
      ],
      local.shared_env_defs,
      local.runtime_env_common,
      local.consumer_tuning_env,
      local.result_store_env,
      ) : merge(
      {
        value       = null
        secret_name = null
      },
      env,
    )
  ]

  worker_env_defs = [
    for env in concat(
      [
        { name = "SERVICEBUS_CONN", secret_name = "sb-scan-listen" },
        { name = "QUEUE_NAME", value = local.scan_queue_name },
        { name = "WORKER_MODE", value = "analyzer" },
        { name = "ARTIFACT_DIR", value = "/artifacts" },
        { name = "ARTIFACT_DELETE_ON_SUCCESS", value = "false" },
      ],
      local.shared_env_defs,
      local.runtime_env_common,
      local.consumer_tuning_env,
      local.result_store_env,
      local.web_analysis_env,
      local.screenshot_env,
      [
        { name = "CAPTURE_SCREENSHOTS", value = tostring(var.capture_screenshots) },
        { name = "SCREENSHOT_CONTAINER", value = var.screenshot_container },
        { name = "SCREENSHOT_FORMAT", value = var.screenshot_format },
      ],
      ) : merge(
      {
        value       = null
        secret_name = null
      },
      env,
    )
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

  dynamic "secret" {
    for_each = local.api_secret_defs
    content {
      name                = secret.value.name
      value               = secret.value.value
      key_vault_secret_id = secret.value.key_vault_secret_id
      identity            = secret.value.identity
    }
  }

  template {
    container {
      name   = "api"
      image  = "${data.azurerm_container_registry.acr.login_server}/${local.api_name}:${var.image_tag}"
      cpu    = 0.25
      memory = "0.5Gi"

      dynamic "env" {
        for_each = local.api_env_defs
        content {
          name        = env.value.name
          value       = env.value.value
          secret_name = env.value.secret_name
        }
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

  lifecycle {
    ignore_changes = [
      template[0].container[0].image,
      template[0].container[1].image,
    ]
  }

  depends_on = [
    time_sleep.kv_secrets_uami_propagation,
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

  dynamic "secret" {
    for_each = local.fetcher_secret_defs
    content {
      name                = secret.value.name
      value               = secret.value.value
      key_vault_secret_id = secret.value.key_vault_secret_id
      identity            = secret.value.identity
    }
  }

  template {
    container {
      name   = "fetcher"
      image  = "${data.azurerm_container_registry.acr.login_server}/${local.worker_name}:${var.image_tag}"
      cpu    = 0.5
      memory = "1Gi"

      dynamic "env" {
        for_each = local.fetcher_env_defs
        content {
          name        = env.value.name
          value       = env.value.value
          secret_name = env.value.secret_name
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

  lifecycle {
    ignore_changes = [
      template[0].container[0].image,
    ]
  }

  depends_on = [
    time_sleep.kv_secrets_uami_propagation,
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

  dynamic "secret" {
    for_each = local.worker_secret_defs
    content {
      name                = secret.value.name
      value               = secret.value.value
      key_vault_secret_id = secret.value.key_vault_secret_id
      identity            = secret.value.identity
    }
  }

  template {
    container {
      name   = "worker"
      image  = "${data.azurerm_container_registry.acr.login_server}/${local.worker_name}:${var.image_tag}"
      cpu    = 1.0
      memory = "2Gi"

      dynamic "env" {
        for_each = local.worker_env_defs
        content {
          name        = env.value.name
          value       = env.value.value
          secret_name = env.value.secret_name
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

  lifecycle {
    ignore_changes = [
      template[0].container[0].image,
    ]
  }

  depends_on = [
    time_sleep.kv_secrets_uami_propagation,
    azurerm_role_assignment.acr_pull_uami,
  ]
}
