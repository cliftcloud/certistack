# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 Clift Cloud LLC

terraform {
  # 1.8 is the first release whose `moved` blocks can change a resource's
  # type (moved.tf); OpenTofu can from 1.10.
  required_version = ">= 1.8.0"
  required_providers {
    proxmox = {
      source  = "bpg/proxmox"
      version = "~> 0.123.1"
    }
  }
}

provider "proxmox" {
  endpoint  = var.pve_api_endpoint
  api_token = var.pve_api_token
  insecure  = var.pve_tls_insecure

  ssh {
    agent = true
  }
}

# 1. Least-privilege role
resource "proxmox_virtual_environment_role" "certistack_role" {
  role_id = "CertiStackRole"

  privileges = [
    "VM.Allocate",
    "VM.Audit",
    "VM.PowerMgmt",
    "VM.Console",
    "VM.Config.Disk",
    "VM.Config.CPU",
    "VM.Config.Memory",
    "VM.Config.Network",
    "VM.Config.Options",
    "VM.Config.HWType",
    "VM.Config.CDROM",
    "SDN.Allocate",
    "SDN.Audit",
    "SDN.Use",
    "Sys.Audit",
    "Datastore.AllocateSpace",
    "Datastore.Audit"
  ]
}

# 2. Service account
resource "proxmox_virtual_environment_user" "certistack_user" {
  user_id = "certistack-svc@pve"
  comment = "CertiStack restore tests"

  # The provider reads a user's ACL entries back into this resource's `acl`
  # blocks. The entries are managed by proxmox_acl.certistack_user below;
  # without ignore_changes every apply after the first would see them as
  # unwanted and remove them from PVE, leaving the privilege-separated token
  # (which holds only what its user also holds) with nothing, and
  # `terraform plan` would never be clean.
  lifecycle {
    ignore_changes = [acl]
  }

  # Deleting the user also removes the ACL entries it still holds, and those
  # name the role. Without this dependency Terraform destroys the role and the
  # user in parallel; when the role goes first, the user's deletion fails with
  # "the requested resource does not exist" and leaves the user behind.
  # Depending on the role destroys the user first.
  depends_on = [proxmox_virtual_environment_role.certistack_role]
}

# 3. API token
resource "proxmox_user_token" "certistack_token" {
  user_id               = proxmox_virtual_environment_user.certistack_user.user_id
  token_name            = "automation"
  comment               = "CertiStack restore tests"
  privileges_separation = true
}

# 4. Resource-scoped ACLs
#
# The token is privilege-separated: PVE gives it only the privileges that
# both it and its user hold on a path. Each path below therefore carries the
# role twice, once for the user and once for the token. The paths are the
# ones a run's privilege check reads (pkg/pve RunPrivileges), mapped to the
# propagation that covers them:
#   /vms          sandbox VMs. They are created outside any pool, and PVE
#                 deletes a VM's own /vms/<vmid> ACL when the VM is
#                 destroyed, so no narrower grant survives a teardown.
#   /sdn          this path only: take PVE's SDN lock and apply (reload)
#                 the ephemeral sandbox's SDN changes.
#   /sdn/zones    create and remove the ephemeral sandbox zone and VNet.
#                 With sandbox_sdn_zones, only those pre-provisioned zones
#                 and their VNets instead, and no /sdn grant.
#   /storage/<overlay_storage>  the overlays and firmware copies.
#   /nodes/<node> this path only: the node's status and QEMU versions.
locals {
  certistack_token_id = "${proxmox_virtual_environment_user.certistack_user.user_id}!${proxmox_user_token.certistack_token.token_name}"

  sdn_acl_paths = length(var.sandbox_sdn_zones) == 0 ? tomap({
    "/sdn"       = false
    "/sdn/zones" = true
  }) : tomap({ for zone in var.sandbox_sdn_zones : "/sdn/zones/${zone}" => true })

  acl_paths = merge(local.sdn_acl_paths, {
    "/vms"                            = true
    "/storage/${var.overlay_storage}" = true
    "/nodes/${var.pve_node_name}"     = false
  })
}

resource "proxmox_acl" "certistack_user" {
  for_each = local.acl_paths

  user_id   = proxmox_virtual_environment_user.certistack_user.user_id
  role_id   = proxmox_virtual_environment_role.certistack_role.role_id
  path      = each.key
  propagate = each.value
}

resource "proxmox_acl" "certistack_token" {
  for_each = local.acl_paths

  token_id  = local.certistack_token_id
  role_id   = proxmox_virtual_environment_role.certistack_role.role_id
  path      = each.key
  propagate = each.value
}

# 5. Optional reference VM, a guest to back up to PBS and restore in tests
#
# Created only when reference_template_vmid names a prepared template: a full
# clone of it, so it boots the template's installed OS. Terraform cannot
# install an OS or the guest agent on an isolated bridge; the template must
# already have cloud-init, an enabled qemu-guest-agent, and the service a
# probe will check. Back the VM up to PBS afterwards, as you would any VM.
resource "proxmox_virtual_environment_vm" "reference_golden_vm" {
  count = var.reference_template_vmid == null ? 0 : 1

  node_name   = var.pve_node_name
  vm_id       = var.reference_vmid
  name        = "certistack-golden-test-vm"
  description = "Reference guest used to seed initial backup snapshots to PBS for CertiStack testing"

  clone {
    vm_id        = var.reference_template_vmid
    full         = true
    datastore_id = var.reference_datastore
  }

  cpu {
    cores = 1
    type  = "host"
  }

  memory {
    dedicated = 1024
  }

  # The template's agent must start on boot: the provider waits for it.
  agent {
    enabled = true
    timeout = "15m"
  }

  # Stop rather than wait for a guest shutdown that may never come.
  stop_on_destroy = true

  operating_system {
    type = "l26"
  }

  initialization {
    datastore_id = var.reference_datastore
    ip_config {
      ipv4 {
        address = "dhcp"
      }
    }
    user_account {
      username = "debian"
      password = var.guest_password
    }
  }

  network_device {
    bridge = var.pve_bridge
  }

  lifecycle {
    precondition {
      condition     = var.pve_bridge != null && var.guest_password != null
      error_message = "A reference VM needs pve_bridge (a dedicated isolated bridge) and guest_password."
    }
  }
}
