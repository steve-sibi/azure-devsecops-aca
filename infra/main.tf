terraform {
  required_version = ">= 1.6"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
    time = {
      source  = "hashicorp/time"
      version = "~> 0.11"
    }
  }
}

provider "azurerm" {
  features {}
  subscription_id = var.subscription_id
  # provider registrations are already handled out-of-band
  resource_provider_registrations = "none"
}

locals {
  acr_name          = "${var.prefix}acr"
  kv_name           = "${var.prefix}-kv"
  sb_ns_name        = "${var.prefix}-sbns"
  la_name           = "${var.prefix}-la"
  ai_name           = "${var.prefix}-appi"
  env_name          = "${var.prefix}-acaenv"
  api_name          = "${var.prefix}-api"
  clamav_name       = "${var.prefix}-clamav"
  fetcher_name      = "${var.prefix}-fetcher"
  worker_name       = "${var.prefix}-worker"
  webpubsub_name    = "${var.prefix}-wps"
  artifacts_share   = "${var.prefix}-artifacts"
  artifacts_storage = "artifacts"
  uami_name         = "${var.prefix}-uami"
  results_sa        = "${var.prefix}scan"
  results_table     = var.results_table_name

  scan_queue_name = (
    trimspace(var.scan_queue_name) != ""
    ? var.scan_queue_name
    : "${var.queue_name}-scan"
  )
}

# Split by concern for readability:
# - core.tf: data sources + core infra
# - keyvault.tf: Key Vault access + secrets
# - apps.tf: Container Apps (create_apps=true)
