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

variable "subscription_id" {
  type        = string
  default     = null
  description = "Azure Subscription ID for the AzureRM provider (can also be set via ARM_SUBSCRIPTION_ID)."
}

variable "terraform_principal_object_id" {
  type        = string
  default     = null
  description = "Object ID of the principal that should be granted Key Vault secret management permissions (defaults to the currently-authenticated principal)."
}

variable "create_apps" {
  type        = bool
  default     = false
  description = "If true, creates API/Fetcher/Worker Container Apps."
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

variable "scan_queue_name" {
  type        = string
  default     = ""
  description = "Optional Service Bus scan queue name (defaults to <queue_name>-scan)."
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

variable "artifacts_share_quota_gb" {
  type        = number
  default     = 2
  description = "Azure Files share quota (GB) for persisting fetched artifacts between fetcher and worker."
}

variable "capture_screenshots" {
  type        = bool
  default     = true
  description = "If true, the worker captures website screenshots via Playwright (served by the API at /scan/{job_id}/screenshot)."
}

variable "screenshot_container" {
  type        = string
  default     = "screenshots"
  description = "Blob container name used to store screenshots when RESULT_BACKEND=table."
}

variable "screenshot_format" {
  type        = string
  default     = "jpeg"
  description = "Screenshot format ('jpeg' or 'png'). Must match between worker and API."

  validation {
    condition     = contains(["jpeg", "png"], lower(var.screenshot_format))
    error_message = "screenshot_format must be 'jpeg' or 'png'."
  }
}
