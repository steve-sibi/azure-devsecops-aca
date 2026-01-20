# ---------- Key Vault access & secrets ----------
# CI principal can manage secrets (used to create/update secrets & allow destroy)
resource "azurerm_key_vault_access_policy" "kv_ci" {
  key_vault_id       = data.azurerm_key_vault.kv.id
  tenant_id          = data.azurerm_client_config.current.tenant_id
  object_id          = coalesce(var.terraform_principal_object_id, data.azurerm_client_config.current.object_id)
  secret_permissions = ["Get", "Set", "List", "Delete", "Purge"]
}

# Ensure the principal running Terraform can use Key Vault when RBAC is enabled
resource "azurerm_role_assignment" "kv_tf" {
  scope                = data.azurerm_key_vault.kv.id
  role_definition_name = "Key Vault Secrets Officer"
  principal_id         = coalesce(var.terraform_principal_object_id, data.azurerm_client_config.current.object_id)
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

  depends_on = [azurerm_key_vault_access_policy.kv_ci, azurerm_role_assignment.kv_tf]
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

  depends_on = [azurerm_key_vault_access_policy.kv_ci, azurerm_role_assignment.kv_tf]
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

  depends_on = [azurerm_key_vault_access_policy.kv_ci, azurerm_role_assignment.kv_tf]
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

  depends_on = [azurerm_key_vault_access_policy.kv_ci, azurerm_role_assignment.kv_tf]
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

  depends_on = [azurerm_key_vault_access_policy.kv_ci, azurerm_role_assignment.kv_tf]
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

  depends_on = [azurerm_key_vault_access_policy.kv_ci, azurerm_role_assignment.kv_tf]
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

  depends_on = [azurerm_key_vault_access_policy.kv_ci, azurerm_role_assignment.kv_tf]
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

  depends_on = [azurerm_key_vault_access_policy.kv_ci, azurerm_role_assignment.kv_tf]
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
