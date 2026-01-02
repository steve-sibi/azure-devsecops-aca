variable "prefix" {
  type        = string
  default     = "devsecopsaca"
  description = "Lowercase base name for resources."
}

variable "resource_group_name" {
  type        = string
  default     = "rg-devsecops-aca"
  description = "Existing resource group to deploy into."
}

variable "create_apps" {
  type        = bool
  default     = false
  description = "If true, creates API/Worker/ClamAV Container Apps."
}

variable "image_tag" {
  type        = string
  default     = "dev"
  description = "Tag for images to deploy (CI sets to commit SHA)."
}

variable "api_min_replicas" {
  type        = number
  default     = 1
  description = "Minimum replicas for the API Container App."
}

variable "api_max_replicas" {
  type        = number
  default     = 3
  description = "Maximum replicas for the API Container App."
}

variable "api_rate_limit_rpm" {
  type        = number
  default     = 60
  description = "API rate limit (requests per minute) per API key."
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

variable "clamav_db_share_quota_gb" {
  type        = number
  default     = 2
  description = "Azure Files share quota (GB) for persisting the ClamAV signature database."
}
