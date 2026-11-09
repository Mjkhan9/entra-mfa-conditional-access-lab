# Microsoft Entra MFA Incident Simulator - Main Configuration
# Terraform configuration for incident simulation and detection pipeline

terraform {
  required_version = ">= 1.5"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 3.0"
    }
  }
}

provider "azurerm" {
  features {}
}

provider "azuread" {}

# Data sources
data "azurerm_client_config" "current" {}

# Short random suffix for globally unique names (storage, function app, Cosmos DB)
resource "random_string" "suffix" {
  length  = 5
  upper   = false
  special = false
}

# Local values
locals {
  name_prefix     = "${var.project_name}-${var.environment}"
  subscription_id = data.azurerm_client_config.current.subscription_id
  tenant_id       = data.azurerm_client_config.current.tenant_id

  tags = {
    Project     = "mfa-incident-simulator"
    Environment = var.environment
    ManagedBy   = "terraform"
    Owner       = "mjkhan9"
  }
}

resource "azurerm_resource_group" "main" {
  name     = "rg-${local.name_prefix}"
  location = var.location
  tags     = local.tags
}

# Log Analytics workspace: Application Insights backend and the destination for Entra SigninLogs (KQL)
resource "azurerm_log_analytics_workspace" "main" {
  name                = "law-${local.name_prefix}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  sku                 = "PerGB2018"
  retention_in_days   = var.log_retention_days
  daily_quota_gb      = var.log_daily_cap_gb # hard stop below the free monthly allowance
  tags                = local.tags
}

resource "azurerm_application_insights" "main" {
  name                = "appi-${local.name_prefix}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  workspace_id        = azurerm_log_analytics_workspace.main.id
  application_type    = "web"
  tags                = local.tags
}
