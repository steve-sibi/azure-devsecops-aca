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

variable "kv_secret_reader_object_ids" {
  type        = set(string)
  default     = []
  description = "Additional Entra object IDs (users/service principals/managed identities) that should be granted Key Vault Secrets User on the vault. Keep empty by default and set via Deploy workflow variables/inputs."
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

variable "otel_enabled" {
  type        = bool
  default     = true
  description = "Enable OpenTelemetry trace export in API/Fetcher/Worker."
}

variable "otel_traces_sampler_ratio" {
  type        = number
  default     = 0.10
  description = "Trace sampling ratio for OpenTelemetry (0.0 to 1.0)."

  validation {
    condition     = var.otel_traces_sampler_ratio >= 0 && var.otel_traces_sampler_ratio <= 1
    error_message = "otel_traces_sampler_ratio must be between 0 and 1."
  }
}

variable "otel_service_namespace" {
  type        = string
  default     = "aca-urlscanner"
  description = "OpenTelemetry service.namespace value."
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

variable "webpubsub_sku" {
  type        = string
  default     = "Free_F1"
  description = "SKU for the Web PubSub service (e.g., Free_F1 or Standard_S1)."
}

variable "webpubsub_capacity" {
  type        = number
  default     = 1
  description = "Capacity units for Web PubSub (1 for Free_F1)."
}

variable "webpubsub_hub_name" {
  type        = string
  default     = "scans"
  description = "Hub name used for scan status updates."
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

variable "url_dedupe_ttl_seconds" {
  type        = number
  default     = 3600
  description = "If >0, cache window for reusing completed/error URL scans (seconds)."
}

variable "url_dedupe_in_progress_ttl_seconds" {
  type        = number
  default     = 900
  description = "If >0, reuse in-progress URL scans to avoid duplicate work (seconds)."
}

variable "url_dedupe_scope" {
  type        = string
  default     = "global"
  description = "URL dedupe scope ('global' or 'apikey'). Set to 'global' to reuse URL scans across API keys (recommended)."

  validation {
    condition     = contains(["global", "apikey"], lower(var.url_dedupe_scope))
    error_message = "url_dedupe_scope must be 'global' or 'apikey'."
  }
}

variable "url_dedupe_index_partition" {
  type        = string
  default     = "urlidx"
  description = "Table Storage partition key used for the URL->job index."
}

variable "url_result_visibility_default" {
  type        = string
  default     = "shared"
  description = "Default visibility for URL scan results ('shared' or 'private')."

  validation {
    condition     = contains(["shared", "private"], lower(var.url_result_visibility_default))
    error_message = "url_result_visibility_default must be 'shared' or 'private'."
  }
}

variable "web_whois_timeout_seconds" {
  type        = number
  default     = 6
  description = "Timeout for WHOIS/RDAP lookups (seconds)."

  validation {
    condition     = var.web_whois_timeout_seconds >= 0.1
    error_message = "web_whois_timeout_seconds must be >= 0.1."
  }
}

variable "monitor_alerts_enabled" {
  type        = bool
  default     = true
  description = "If true, deploy Azure Monitor scheduled query alerts."
}

variable "monitor_action_group_email_receivers" {
  type        = list(string)
  default     = []
  description = "Email receivers for the observability action group."
}

variable "monitor_workbook_enabled" {
  type        = bool
  default     = true
  description = "If true, deploy the observability workbook."
}

variable "monitor_api_5xx_threshold" {
  type        = number
  default     = 5
  description = "Alert threshold for API 5xx errors per evaluation window."
}

variable "monitor_pipeline_error_threshold" {
  type        = number
  default     = 5
  description = "Alert threshold for blocked/error/retrying pipeline events per window."
}

variable "monitor_queue_backlog_threshold" {
  type        = number
  default     = 50
  description = "Alert threshold for sustained queue backlog."
}

variable "monitor_deadletter_threshold" {
  type        = number
  default     = 1
  description = "Alert threshold for DLQ growth in Service Bus queues."
}
