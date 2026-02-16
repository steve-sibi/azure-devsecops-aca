# ---------- Key Vault access & secrets ----------
# This project standardizes on Key Vault *data-plane* authorization via Azure RBAC.
# The vault is created/updated in scripts/gha/deploy_infra_bootstrap.sh to enable RBAC.

locals {
  kv_runtime_secrets = {
    sb_send = {
      name         = "ServiceBusSend"
      value        = azurerm_servicebus_queue_authorization_rule.queue_rule["q_send"].primary_connection_string
      content_type = "servicebus-send"
    }
    sb_listen = {
      name         = "ServiceBusListen"
      value        = azurerm_servicebus_queue_authorization_rule.queue_rule["q_listen"].primary_connection_string
      content_type = "servicebus-listen"
    }
    sb_manage = {
      name         = "ServiceBusManage"
      value        = azurerm_servicebus_queue_authorization_rule.queue_rule["q_manage"].primary_connection_string
      content_type = "servicebus-manage"
    }
    sb_scan_send = {
      name         = "ServiceBusScanSend"
      value        = azurerm_servicebus_queue_authorization_rule.queue_rule["q_scan_send"].primary_connection_string
      content_type = "servicebus-send"
    }
    sb_scan_listen = {
      name         = "ServiceBusScanListen"
      value        = azurerm_servicebus_queue_authorization_rule.queue_rule["q_scan_listen"].primary_connection_string
      content_type = "servicebus-listen"
    }
    sb_scan_manage = {
      name         = "ServiceBusScanManage"
      value        = azurerm_servicebus_queue_authorization_rule.queue_rule["q_scan_manage"].primary_connection_string
      content_type = "servicebus-manage"
    }
    results_conn = {
      name         = "ScanResultsConn"
      value        = azurerm_storage_account.results.primary_connection_string
      content_type = "table-connection-string"
    }
    webpubsub_conn = {
      name         = "WebPubSubConn"
      value        = azurerm_web_pubsub.wps.primary_connection_string
      content_type = "webpubsub-connection-string"
    }
  }
}

# Ensure the principal running Terraform can manage Key Vault secrets.
resource "azurerm_role_assignment" "kv_tf" {
  scope                = data.azurerm_key_vault.kv.id
  role_definition_name = "Key Vault Secrets Officer"
  principal_id         = coalesce(var.terraform_principal_object_id, data.azurerm_client_config.current.object_id)
}

resource "time_sleep" "kv_tf_role_propagation" {
  depends_on      = [azurerm_role_assignment.kv_tf]
  create_duration = var.kv_rbac_propagation_wait_duration
  triggers = {
    role_assignment_id = azurerm_role_assignment.kv_tf.id
  }
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

  lifecycle {
    ignore_changes = [expiration_date]
  }

  depends_on = [time_sleep.kv_tf_role_propagation]
}

resource "azurerm_key_vault_secret" "runtime" {
  for_each = local.kv_runtime_secrets

  name            = each.value.name
  value           = each.value.value
  key_vault_id    = data.azurerm_key_vault.kv.id
  content_type    = each.value.content_type
  expiration_date = timeadd(timestamp(), "8760h")

  lifecycle {
    ignore_changes = [expiration_date]
  }

  depends_on = [time_sleep.kv_tf_role_propagation]
}

# RBAC (preferred for KV): allow UAMI to read secrets
resource "azurerm_role_assignment" "kv_secrets_uami" {
  scope                = data.azurerm_key_vault.kv.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.uami.principal_id
}

resource "time_sleep" "kv_secrets_uami_propagation" {
  depends_on      = [azurerm_role_assignment.kv_secrets_uami]
  create_duration = var.kv_rbac_propagation_wait_duration
  triggers = {
    role_assignment_id = azurerm_role_assignment.kv_secrets_uami.id
  }
}

# RBAC: grant additional human/automation principals read access to KV secrets.
resource "azurerm_role_assignment" "kv_secrets_readers" {
  for_each             = var.kv_secret_reader_object_ids
  scope                = data.azurerm_key_vault.kv.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = each.value
}

resource "time_sleep" "kv_secrets_readers_propagation" {
  for_each = azurerm_role_assignment.kv_secrets_readers

  create_duration = var.kv_rbac_propagation_wait_duration
  triggers = {
    role_assignment_id = each.value.id
  }
}
