# Web PubSub for real-time scan updates
resource "azurerm_web_pubsub" "wps" {
  name                = local.webpubsub_name
  location            = data.azurerm_resource_group.rg.location
  resource_group_name = data.azurerm_resource_group.rg.name
  sku                 = var.webpubsub_sku
  capacity            = var.webpubsub_capacity
  tags                = var.tags
}
