# Variables for MFA Incident Simulator

variable "location" {
  description = "Azure region for deployment"
  type        = string
  default     = "southcentralus"
}

variable "project_name" {
  description = "Project name used for resource naming"
  type        = string
  default     = "mfa-incident-simulator"
}

variable "environment" {
  description = "Environment (dev, staging, prod)"
  type        = string
  default     = "dev"
}

variable "alert_email" {
  description = "Email address for incident alerts (action group receiver)"
  type        = string
  default     = ""
}

variable "log_retention_days" {
  description = "Log Analytics retention in days (minimum 30)"
  type        = number
  default     = 30
}

variable "incident_retention_days" {
  description = "Cosmos DB incident TTL in days"
  type        = number
  default     = 7
}

variable "responder_schedule" {
  description = "NCRONTAB schedule for the responder timer trigger"
  type        = string
  default     = "0 */5 * * * *"
}

variable "enable_entra_log_export" {
  description = "Create the tenant-level diagnostic setting that streams Entra SignInLogs to the event hub and workspace (needs Entra ID P1 and Security Administrator)"
  type        = bool
  default     = false
}
