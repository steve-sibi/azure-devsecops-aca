# Web PubSub for real-time scan updates
resource "azurerm_web_pubsub" "wps" {
  #checkov:skip=CKV_AZURE_175: Using Free_F1 to minimize cost for now (non-prod); upgrade to Standard/Premium when SLA is required.
  name                = local.webpubsub_name
  location            = data.azurerm_resource_group.rg.location
  resource_group_name = data.azurerm_resource_group.rg.name
  sku                 = var.webpubsub_sku
  capacity            = var.webpubsub_capacity
  tags                = var.tags

  # CKV_AZURE_176: enable a managed identity so Web PubSub can authenticate to other Azure resources without keys.
  identity {
    type = "SystemAssigned"
  }
}
