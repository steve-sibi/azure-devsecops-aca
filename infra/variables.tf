variable "prefix" {
  type        = string
  default     = "devsecopsaca"
  description = "Lowercase base name for resources."
}

variable "location" {
  type        = string
  default     = "eastus"
  description = "Azure region."
}

variable "resource_group_name" {
  type        = string
  default     = "rg-devsecops-aca"
  description = "Existing resource group to deploy into."
}

variable "create_apps" {
  type        = bool
  default     = false
  description = "If true, creates API/Worker Container Apps."
}

variable "image_tag" {
  type        = string
  default     = "dev"
  description = "Tag for images to deploy (CI sets to commit SHA)."
}

variable "queue_name" {
  type        = string
  default     = "tasks"
  description = "Service Bus queue name."
}

variable "tags" {
  type = map(string)
  default = {
    env = "dev"
    app = "devsecopsaca"
  }
  description = "Common tags applied to tagged resources."
}

variable "servicebus_sku" {
  type        = string
  default     = "Basic" # or "Standard"
  description = "SKU for the Service Bus namespace."
}

variable "results_table_name" {
  type        = string
  default     = "scanresults"
  description = "Table name for storing scan results."
}
