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

variable "log_daily_cap_gb" {
  description = "Log Analytics daily ingestion cap in GB. 0.15 GB/day keeps a month under the 5 GB free allowance"
  type        = number
  default     = 0.15
}

variable "grant_graph_read" {
  description = "Grant the managed identity Microsoft Graph Policy.Read.All (read-only, for the posture check)"
  type        = bool
  default     = true
}

variable "break_glass_upns" {
  description = "Emergency access account UPNs: any sign-in raises a CRITICAL break_glass_sign_in incident"
  type        = list(string)
  default     = []
}

variable "break_glass_object_ids" {
  description = "Emergency access account object IDs: the posture check verifies every policy excludes them"
  type        = list(string)
  default     = []
}

variable "privileged_upns" {
  description = "Admin account UPNs: a password-only sign-in by one of these raises privileged_single_factor"
  type        = list(string)
  default     = []
}

variable "enable_entra_log_export" {
  description = "Create the tenant-level diagnostic setting that sends Entra SignInLogs to the workspace (needs Entra ID P1 and Security Administrator)"
  type        = bool
  default     = false
}
