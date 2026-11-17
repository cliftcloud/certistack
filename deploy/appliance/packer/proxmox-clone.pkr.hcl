# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 Clift Cloud LLC
// Builds a controller *VM template* from an approved Debian/Ubuntu cloud-init
// template already present in PVE. It never runs on, replaces, or modifies a
// production hypervisor root filesystem beyond standard PVE VM management.
packer {
  # The recipe is written against, and checked with, this Packer range and this
  # exact plugin. `packer init` installs the pinned plugin and nothing newer;
  # moving either is a reviewed change to this file (see the README's "What is
  # pinned" section).
  required_version = ">= 1.14.2, < 2.0.0"
  required_plugins {
    proxmox = {
      source  = "github.com/hashicorp/proxmox"
      version = "= 1.2.4"
    }
  }
}

variable "proxmox_url" {
  type        = string
  description = "PVE API endpoint, for example https://pve.example:8006/api2/json"
}

variable "proxmox_token_id" {
  type        = string
  description = "Packer-only API token ID, for example packer@pve!template"
}

variable "proxmox_token_secret" {
  type        = string
  sensitive   = true
  description = "Packer-only API token secret. Supply it from a variable file outside this repository (-var-file), never with -var: a -var value is part of the process's argument list"
}

variable "proxmox_node" {
  type        = string
  description = "PVE node that owns the trusted cloud-init source template"
}

variable "source_template" {
  type        = string
  description = "Existing patched Debian/Ubuntu cloud-init VM template name or ID. It must have cloud-init and a running qemu-guest-agent"
}

variable "template_name" {
  type    = string
  default = "certistack-controller"
}

variable "template_vmid" {
  type    = number
  default = 9800
}

variable "pool" {
  type        = string
  default     = ""
  description = "Optional PVE resource pool to create the template in. When set, the Packer token needs VM.Allocate on /pool/<pool> instead of on the template's VMID"
}

variable "task_timeout" {
  type        = string
  default     = "10m"
  description = "How long Packer waits for one PVE task such as the full clone. The plugin's own default is one minute, which a full clone of a large template on slow storage exceeds"
  validation {
    condition     = can(regex("^([0-9]+[smh])+$", var.task_timeout))
    error_message = "The task timeout must be a duration such as 10m or 1h30m."
  }
}

variable "memory" {
  type        = number
  default     = 2048
  description = "Template memory in MiB. The plugin would otherwise overwrite the source template's sizing with its own 512 MiB default"
  validation {
    condition     = var.memory >= 2048
    error_message = "The controller appliance needs at least 2048 MiB of memory (see the README's sizing table)."
  }
}

variable "cores" {
  type        = number
  default     = 2
  description = "Template cores per socket"
  validation {
    condition     = var.cores >= 2
    error_message = "The controller appliance needs at least 2 vCPUs (see the README's sizing table)."
  }
}

variable "sockets" {
  type        = number
  default     = 1
  description = "Template CPU sockets"
  validation {
    condition     = var.sockets >= 1
    error_message = "The socket count must be at least 1."
  }
}

variable "cpu_type" {
  type        = string
  default     = "x86-64-v2-AES"
  description = "PVE CPU model. The default is a baseline model that live-migrates across a mixed-generation cluster; use host only for a single node"
}

variable "os" {
  type        = string
  default     = "l26"
  description = "PVE guest OS type (l26 is a current Linux kernel)"
}

variable "ssh_username" {
  type    = string
  default = "root"
}

variable "ssh_private_key_file" {
  type        = string
  sensitive   = true
  description = "SSH key for the disposable Packer build guest. Use a key pair made for this build alone"
}

variable "ssh_build_public_key_file" {
  type        = string
  description = "Public half of ssh_private_key_file. The last provisioner removes exactly this key from every authorized_keys file in the guest and fails the build if any copy remains"
}

variable "controller_image" {
  type        = string
  description = "Immutable controller OCI reference, pinned by sha256 digest"
  validation {
    # This value is interpolated into a shell provisioner below, so it is
    # limited to the canonical form: a registry host (a dotted name, a name
    # with a port, or localhost, all lowercase, never a scheme), one or more
    # lowercase repository components, and @sha256: followed by 64 lowercase
    # hex digits. A character-class check would pass an uppercase repository,
    # https://, a doubled slash and a dir: transport path, none of which name
    # a registry manifest, and would fail only at the late podman pull.
    condition     = can(regex("^(([a-z0-9]([a-z0-9-]*[a-z0-9])?\\.)+[a-z0-9]([a-z0-9-]*[a-z0-9])?(:[0-9]{1,5})?|[a-z0-9]([a-z0-9-]*[a-z0-9])?:[0-9]{1,5}|localhost)(/[a-z0-9]+(([._]|__|-+)[a-z0-9]+)*)+@sha256:[a-f0-9]{64}$", var.controller_image))
    error_message = "Controller image must be registry-host/repository@sha256:<64 lowercase hex digits>: lowercase, no scheme or transport prefix, no tag, no doubled slash."
  }
}

variable "insecure_skip_tls_verify" {
  type        = bool
  default     = false
  description = "Only permit for an isolated build lab with an explicit exception"
}

source "proxmox-clone" "controller" {
  proxmox_url              = var.proxmox_url
  username                 = var.proxmox_token_id
  token                    = var.proxmox_token_secret
  node                     = var.proxmox_node
  clone_vm                 = var.source_template
  vm_id                    = var.template_vmid
  vm_name                  = var.template_name
  template_name            = var.template_name
  pool                     = var.pool
  full_clone               = true
  task_timeout             = var.task_timeout
  memory                   = var.memory
  cores                    = var.cores
  sockets                  = var.sockets
  cpu_type                 = var.cpu_type
  os                       = var.os
  qemu_agent               = true
  insecure_skip_tls_verify = var.insecure_skip_tls_verify
  ssh_username             = var.ssh_username
  ssh_private_key_file     = var.ssh_private_key_file
  # Packer removes only a key it generated itself, so this does nothing for
  # the static key above; the finalize provisioner below is the control that
  # matters. It stays on as a second, cheap line of defence.
  ssh_clear_authorized_keys = true
}

build {
  name    = "certistack-controller-template"
  sources = ["source.proxmox-clone.controller"]

  provisioner "file" {
    source      = "../files/certistack-controller"
    destination = "/tmp/certistack-controller"
  }

  provisioner "file" {
    source      = "../files/controller.env.example"
    destination = "/tmp/controller.env.example"
  }

  provisioner "file" {
    source      = "../files/finalize-template.sh"
    destination = "/tmp/certistack-finalize-template.sh"
  }

  provisioner "shell" {
    inline = [
      "export DEBIAN_FRONTEND=noninteractive",
      "apt-get update",
      "apt-get install -y --no-install-recommends ca-certificates openssh-client podman tini",
      "install -d -m 0700 -o 65532 -g 65532 /etc/certistack/secrets /var/lib/certistack",
      "install -m 0755 /tmp/certistack-controller /usr/local/bin/certistack-controller",
      "install -m 0600 /tmp/controller.env.example /etc/certistack/secrets/controller.env.example",
      "podman pull '${var.controller_image}'",
      "rm -f /tmp/certistack-controller /tmp/controller.env.example",
      "apt-get clean",
      "rm -rf /var/lib/apt/lists/*"
    ]
  }

  # Last: checks the pulled image, records the controller image reference and
  # a build manifest, resets the machine ID and cloud-init state, removes the
  # build key, and then asserts every one of those postconditions. Any failure
  # fails the build, so no template is produced from a half-cleaned guest.
  provisioner "shell" {
    environment_vars = [
      "CERTISTACK_CONTROLLER_IMAGE=${var.controller_image}",
      "CERTISTACK_BUILD_KEY_BLOB=${split(" ", trimspace(file(var.ssh_build_public_key_file)))[1]}",
      "CERTISTACK_PACKER_VERSION=${packer.version}",
    ]
    inline = ["sh /tmp/certistack-finalize-template.sh"]
  }
}
