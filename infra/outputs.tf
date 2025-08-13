output "fastapi_url" {
  value       = try(azurerm_container_app.api[0].ingress[0].fqdn, null)
  description = "FastAPI public FQDN"
}
