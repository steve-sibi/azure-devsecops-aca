# ---------- Key Vault access & secrets ----------
# This project standardizes on Key Vault *data-plane* authorization via Azure RBAC.
# The vault is created/updated in scripts/gha/deploy_infra_bootstrap.sh to enable RBAC.
#
# Ensure the principal running Terraform can manage Key Vault secrets.
resource "azurerm_role_assignment" "kv_tf" {
  scope                = data.azurerm_key_vault.kv.id
  role_definition_name = "Key Vault Secrets Officer"
  principal_id         = coalesce(var.terraform_principal_object_id, data.azurerm_client_config.current.object_id)

  # RBAC propagation can lag just long enough to cause flaky 403s when Terraform
  # immediately performs data-plane secret operations. A short delay here makes
  # applies more reliable without requiring extra providers.
  provisioner "local-exec" {
    command = "sleep 30"
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

  depends_on = [azurerm_role_assignment.kv_tf]
}

# Store distinct SB connection strings in KV
resource "azurerm_key_vault_secret" "sb_send" {
  name            = "ServiceBusSend"
  value           = azurerm_servicebus_queue_authorization_rule.q_send.primary_connection_string
  key_vault_id    = data.azurerm_key_vault.kv.id
  content_type    = "servicebus-send"
  expiration_date = timeadd(timestamp(), "8760h") # ~1 year

  lifecycle {
    ignore_changes = [expiration_date]
  }

  depends_on = [azurerm_role_assignment.kv_tf]
}

resource "azurerm_key_vault_secret" "sb_listen" {
  name            = "ServiceBusListen"
  value           = azurerm_servicebus_queue_authorization_rule.q_listen.primary_connection_string
  key_vault_id    = data.azurerm_key_vault.kv.id
  content_type    = "servicebus-listen"
  expiration_date = timeadd(timestamp(), "8760h")

  lifecycle {
    ignore_changes = [expiration_date]
  }

  depends_on = [azurerm_role_assignment.kv_tf]
}

resource "azurerm_key_vault_secret" "sb_manage" {
  name            = "ServiceBusManage"
  value           = azurerm_servicebus_queue_authorization_rule.q_manage.primary_connection_string
  key_vault_id    = data.azurerm_key_vault.kv.id
  content_type    = "servicebus-manage"
  expiration_date = timeadd(timestamp(), "8760h")

  lifecycle {
    ignore_changes = [expiration_date]
  }

  depends_on = [azurerm_role_assignment.kv_tf]
}

resource "azurerm_key_vault_secret" "sb_scan_send" {
  name            = "ServiceBusScanSend"
  value           = azurerm_servicebus_queue_authorization_rule.q_scan_send.primary_connection_string
  key_vault_id    = data.azurerm_key_vault.kv.id
  content_type    = "servicebus-send"
  expiration_date = timeadd(timestamp(), "8760h")

  lifecycle {
    ignore_changes = [expiration_date]
  }

  depends_on = [azurerm_role_assignment.kv_tf]
}

resource "azurerm_key_vault_secret" "sb_scan_listen" {
  name            = "ServiceBusScanListen"
  value           = azurerm_servicebus_queue_authorization_rule.q_scan_listen.primary_connection_string
  key_vault_id    = data.azurerm_key_vault.kv.id
  content_type    = "servicebus-listen"
  expiration_date = timeadd(timestamp(), "8760h")

  lifecycle {
    ignore_changes = [expiration_date]
  }

  depends_on = [azurerm_role_assignment.kv_tf]
}

resource "azurerm_key_vault_secret" "sb_scan_manage" {
  name            = "ServiceBusScanManage"
  value           = azurerm_servicebus_queue_authorization_rule.q_scan_manage.primary_connection_string
  key_vault_id    = data.azurerm_key_vault.kv.id
  content_type    = "servicebus-manage"
  expiration_date = timeadd(timestamp(), "8760h")

  lifecycle {
    ignore_changes = [expiration_date]
  }

  depends_on = [azurerm_role_assignment.kv_tf]
}

resource "azurerm_key_vault_secret" "results_conn" {
  name            = "ScanResultsConn"
  value           = azurerm_storage_account.results.primary_connection_string
  key_vault_id    = data.azurerm_key_vault.kv.id
  content_type    = "table-connection-string"
  expiration_date = timeadd(timestamp(), "8760h")

  lifecycle {
    ignore_changes = [expiration_date]
  }

  depends_on = [azurerm_role_assignment.kv_tf]
}

resource "azurerm_key_vault_secret" "webpubsub_conn" {
  name            = "WebPubSubConn"
  value           = azurerm_web_pubsub.wps.primary_connection_string
  key_vault_id    = data.azurerm_key_vault.kv.id
  content_type    = "webpubsub-connection-string"
  expiration_date = timeadd(timestamp(), "8760h")

  lifecycle {
    ignore_changes = [expiration_date]
  }

  depends_on = [azurerm_role_assignment.kv_tf]
}

# RBAC (preferred for KV): allow UAMI to read secrets
resource "azurerm_role_assignment" "kv_secrets_uami" {
  scope                = data.azurerm_key_vault.kv.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.uami.principal_id

  provisioner "local-exec" {
    command = "sleep 30"
  }
}
