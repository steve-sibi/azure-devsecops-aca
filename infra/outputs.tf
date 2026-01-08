output "fastapi_url" {
  value       = try("https://${azurerm_container_app.api[0].ingress[0].fqdn}", null)
  description = "FastAPI public URL (HTTPS)"
}

output "key_vault_name" {
  value       = data.azurerm_key_vault.kv.name
  description = "Key Vault name (stores runtime secrets)"
}

output "api_key_secret_name" {
  value       = azurerm_key_vault_secret.api_key.name
  description = "Key Vault secret name for the API key (use `az keyvault secret show` to retrieve)"
}

output "sb_queue_id" {
  value       = azurerm_servicebus_queue.q.id
  description = "Service Bus fetch queue resource ID"
}

output "sb_scan_queue_id" {
  value       = azurerm_servicebus_queue.q_scan.id
  description = "Service Bus scan queue resource ID"
}
