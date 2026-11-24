variable "subscription_id" {
  type        = string
  description = "Explicit Azure subscription ID."

  validation {
    condition     = can(regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", var.subscription_id))
    error_message = "subscription_id must be a UUID."
  }
}

variable "location" {
  type        = string
  description = "Azure region for the ephemeral builder."
  default     = "westeurope"

  validation {
    condition     = can(regex("^[a-z0-9-]+$", var.location))
    error_message = "location must be a canonical Azure region name."
  }
}

variable "run_id" {
  type        = string
  description = "Unique run identifier used in resource names and tags."

  validation {
    condition     = length(var.run_id) > 0 && length(var.run_id) <= 64 && can(regex("^[A-Za-z0-9-]+$", var.run_id))
    error_message = "run_id must be 1-64 alphanumeric or hyphen characters."
  }
}

variable "resource_group_name" {
  type        = string
  description = "Fresh run-owned builder resource-group name."

  validation {
    condition     = can(regex("^hbx-demo-[0-9a-f]{16}-builder-rg$", var.resource_group_name))
    error_message = "resource_group_name must be this run's builder group."
  }
}

variable "ssh_public_key" {
  type        = string
  description = "Owner-selected SSH public key for the builder operator."

  validation {
    condition     = can(regex("^(ssh-ed25519|ssh-rsa) [A-Za-z0-9+/=]+$", trimspace(var.ssh_public_key)))
    error_message = "ssh_public_key must be one Ed25519 or RSA public key."
  }
}

variable "ssh_source_cidr" {
  type        = string
  description = "Restricted operator IPv4 /32, or explicit public-key-only SSH source 0.0.0.0/0."

  validation {
    condition     = var.ssh_source_cidr == "0.0.0.0/0" || (can(cidrhost(var.ssh_source_cidr, 0)) && can(regex("^[0-9.]+/32$", var.ssh_source_cidr)))
    error_message = "ssh_source_cidr must be one IPv4 /32 or explicit 0.0.0.0/0 key-only mode."
  }
}

variable "vm_size" {
  type        = string
  description = "x86_64 Azure VM size for the builder."
  default     = "Standard_D32ds_v5"

  validation {
    condition     = can(regex("^Standard_[A-Za-z0-9_]+$", var.vm_size))
    error_message = "vm_size must be an Azure Standard VM size."
  }
}

variable "source_image_version" {
  type        = string
  description = "Exact Ubuntu image version; 'latest' is intentionally rejected."

  validation {
    condition     = var.source_image_version != "latest" && can(regex("^[0-9]+([.][0-9]+)+$", var.source_image_version))
    error_message = "An exact source image version is required."
  }
}
