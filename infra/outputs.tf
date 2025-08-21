output "fastapi_url" {
  value       = try(azurerm_container_app.api[0].ingress[0].fqdn, null)
  description = "FastAPI public FQDN"
}

output "sb_queue_id" {
  value       = azurerm_servicebus_queue.q.id
  description = "Service Bus queue resource ID"
}
