variable "prefix" {
  type        = string
  description = "Lowercase base name for resources (e.g., devsecopsaca)."
  validation {
    condition     = can(regex("^[a-z0-9-]{3,}$", var.prefix))
    error_message = "prefix must be lowercase letters/numbers/hyphens, min 3 chars."
  }
}

variable "location" {
  type        = string
  default     = "eastus"
  description = "Azure region."
}

variable "create_apps" {
  type        = bool
  default     = false
  description = "If true, creates API/Worker Container Apps (set true after images are pushed)."
}

variable "image_tag" {
  type        = string
  default     = "dev"
  description = "Container image tag (CI sets to the commit SHA)."
}

variable "queue_name" {
  type        = string
  default     = "tasks"
  description = "Azure Service Bus queue name."
  validation {
    condition     = can(regex("^[A-Za-z0-9._-]{1,260}$", var.queue_name))
    error_message = "queue_name can include letters, numbers, ., _, -, up to 260 chars."
  }
}

variable "resource_group_name" {
  type        = string
  default     = "rg-devsecops-aca"
  description = "Name of an existing resource group to deploy into."
}
