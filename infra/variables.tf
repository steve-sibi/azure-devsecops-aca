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

variable "scan_engine" {
  type        = string
  default     = "reputation,content"
  description = "Comma-separated scan engines for the fetcher/worker (e.g. reputation,urlscan,content)."
}

variable "urlscan_api_key" {
  type        = string
  default     = ""
  description = "Optional urlscan.io API key for the urlscan engine (leave empty to disable external scans)."
  sensitive   = true
}

variable "urlscan_visibility" {
  type        = string
  default     = "public"
  description = "urlscan.io submission visibility (free tier is typically public)."
}

variable "artifacts_share_quota_gb" {
  type        = number
  default     = 2
  description = "Azure Files share quota (GB) for persisting fetched artifacts between fetcher and worker."
}
