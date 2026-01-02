terraform {
  required_version = ">= 1.6"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.116"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

provider "azurerm" {
  features {}
  # provider registrations are already handled out-of-band
  skip_provider_registration = true
}

locals {
  acr_name            = "${var.prefix}acr"
  kv_name             = "${var.prefix}-kv"
  sb_ns_name          = "${var.prefix}-sbns"
  la_name             = "${var.prefix}-la"
  ai_name             = "${var.prefix}-appi"
  env_name            = "${var.prefix}-acaenv"
  api_name            = "${var.prefix}-api"
  worker_name         = "${var.prefix}-worker"
  clamav_name         = "${var.prefix}-clamav"
  clamav_updater_name = "${var.prefix}-clamav-updater"
  clamav_db_share     = "${var.prefix}-clamav-db"
  clamav_db_storage   = "clamavdb"
  uami_name           = "${var.prefix}-uami"
  results_sa          = "${var.prefix}scan"
  results_table       = var.results_table_name
}

# Split by concern for readability:
# - core.tf: data sources + core infra
# - keyvault.tf: Key Vault access + secrets
# - apps.tf: Container Apps (create_apps=true)
