output "fastapi_url" {
  value       = try("https://${azurerm_container_app.api[0].ingress[0].fqdn}", null)
  description = "FastAPI public URL (HTTPS)"
}

output "sb_queue_id" {
  value       = azurerm_servicebus_queue.q.id
  description = "Service Bus queue resource ID"
}
