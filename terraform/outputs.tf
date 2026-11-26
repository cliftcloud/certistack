# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 Clift Cloud LLC

output "pve_token_id" {
  description = "CertiStack Proxmox VE API Token ID"
  value       = local.certistack_token_id
}

output "pve_token_secret" {
  description = "CertiStack Proxmox VE API token secret: the value for PVE_TOKEN_SECRET. The provider's own value is the whole USER@REALM!TOKENID=SECRET string (a controller given that gets HTTP 401), so the token ID and '=' are taken off."
  value       = trimprefix(proxmox_user_token.certistack_token.value, "${local.certistack_token_id}=")
  sensitive   = true
}

output "pbs_repository" {
  description = "Target PBS repository connection string"
  value       = "${var.pbs_user}@${var.pbs_host}:${var.pbs_port}:${var.pbs_datastore}"
}

output "certistack_acl_paths" {
  description = "PVE paths granted CertiStackRole for both the service user and its token (path => propagate)"
  value       = local.acl_paths
}

output "reference_vm_id" {
  description = "VM ID of the reference VM, or null when none was requested"
  value       = one(proxmox_virtual_environment_vm.reference_golden_vm[*].vm_id)
}

output "controller_connection" {
  description = "Non-secret values for the controller's environment file"
  value = {
    pve_url         = var.pve_api_endpoint
    pve_node        = var.pve_node_name
    pve_token_id    = local.certistack_token_id
    pbs_repository  = "${var.pbs_user}@${var.pbs_host}:${var.pbs_port}:${var.pbs_datastore}"
    pbs_fingerprint = var.pbs_fingerprint
    overlay_storage = var.overlay_storage
  }
}
