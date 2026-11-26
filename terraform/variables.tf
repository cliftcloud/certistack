# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 Clift Cloud LLC

variable "pve_api_endpoint" {
  type        = string
  description = "Proxmox VE API URL (e.g. https://pve-node-01.example.com:8006)"
}

variable "pve_api_token" {
  type        = string
  description = "Bootstrap API token for Terraform (format: USER@REALM!TOKENID=SECRET)"
  sensitive   = true
}

variable "pve_node_name" {
  type        = string
  description = "Proxmox VE node that runs CertiStack's temporary worker and sandbox VMs (e.g. pve-node-01)"
}

variable "overlay_storage" {
  type        = string
  description = "PVE storage (file-based, images content) for the sandbox overlays: the plan's storage.overlay_storage or --overlay-storage"

  validation {
    condition     = can(regex("^[A-Za-z][A-Za-z0-9._-]*$", var.overlay_storage))
    error_message = "overlay_storage must be a PVE storage ID such as certistack-scratch."
  }
}

variable "sandbox_sdn_zones" {
  type        = list(string)
  default     = []
  description = "Pre-provisioned sandbox SDN zones (network.lifecycle: preprovisioned). Empty grants what an ephemeral sandbox needs instead: SDN.Allocate on /sdn and every zone"

  validation {
    condition     = alltrue([for zone in var.sandbox_sdn_zones : can(regex("^[A-Za-z][A-Za-z0-9]{1,7}$", zone))])
    error_message = "Each sandbox_sdn_zones entry must be a PVE SDN zone ID: a letter, then 1 to 7 letters or digits."
  }
}

variable "pve_tls_insecure" {
  type        = bool
  default     = false
  description = "Allow self-signed TLS certificates for Proxmox VE API (defaults to false for security)"
}

variable "pbs_host" {
  type        = string
  description = "IP address or FQDN of Proxmox Backup Server (e.g. 192.0.2.50)"
}

variable "pbs_port" {
  type        = number
  default     = 8007
  description = "PBS API port (default: 8007)"
}

variable "pbs_datastore" {
  type        = string
  description = "PBS Datastore name storing VM backups (e.g. backup-store)"
}

variable "pbs_fingerprint" {
  type        = string
  description = "SHA-256 TLS fingerprint of Proxmox Backup Server (from PBS GUI Dashboard)"
}

variable "pbs_user" {
  type        = string
  description = "PBS user or API-token identity (user@realm!token) holding only Datastore.Audit and Datastore.Read; never root@pam"

  validation {
    condition     = trimspace(var.pbs_user) != "" && !startswith(var.pbs_user, "root@")
    error_message = "pbs_user must be a dedicated read-only PBS identity, not root."
  }
}

variable "reference_template_vmid" {
  type        = number
  default     = null
  description = "Optional prepared template (installed OS, cloud-init, enabled qemu-guest-agent, a listening service) to full-clone as the reference VM. Unset creates no VM"
}

variable "reference_vmid" {
  type        = number
  default     = 9000
  description = "VM ID of the reference VM, a full clone of reference_template_vmid"
}

variable "reference_datastore" {
  type        = string
  default     = "local-lvm"
  description = "PVE storage for the reference VM's cloned disks and cloud-init drive (e.g. local-zfs on a ZFS install)"
}

variable "pve_bridge" {
  type        = string
  default     = null
  description = "Isolated, non-production Proxmox bridge for the reference VM; required with reference_template_vmid"

  validation {
    condition     = var.pve_bridge == null ? true : trimspace(var.pve_bridge) != "" && var.pve_bridge != "vmbr0"
    error_message = "pve_bridge must name a dedicated isolated bridge; vmbr0 and an empty value are forbidden."
  }
}

variable "guest_password" {
  type        = string
  default     = null
  description = "Initial password for the reference VM's cloud-init user; required with reference_template_vmid"
  sensitive   = true
}
