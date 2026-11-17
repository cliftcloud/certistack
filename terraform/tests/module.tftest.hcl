# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 Clift Cloud LLC
#
# Offline checks of the module's plan: `terraform -chdir=terraform test`.
# The provider is mocked, so nothing contacts a PVE API.
#
# The two "grants:" tables below are also read by
# pkg/pve/terraform_module_test.go, which checks that they cover every path a
# run's privilege check (RunPrivileges) reads, for the same node, storage and
# zone as the variables here, and grant nothing a run does not need.

mock_provider "proxmox" {}

variables {
  pve_api_endpoint = "https://pve-node-01.example.com:8006"
  pve_api_token    = "bootstrap@pve!terraform=00000000-0000-0000-0000-000000000000"
  pve_node_name    = "pve1"
  overlay_storage  = "certistack-scratch"
  pbs_host         = "192.0.2.50"
  pbs_datastore    = "backup-anchor"
  pbs_user         = "certistack-ro@pbs!ro"
  pbs_fingerprint  = "SHA256:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff"
}

# The privilege-separated token gets its own ACL on every path an
# ephemeral-sandbox run needs, and its user the same ones.
run "ephemeral_sandbox_grants" {
  command = plan

  assert {
    condition = tomap({ for path, acl in proxmox_virtual_environment_acl.certistack_token : path => acl.propagate }) == tomap({
      # grants: ephemeral
      "/vms"                        = true
      "/sdn"                        = false
      "/sdn/zones"                  = true
      "/storage/certistack-scratch" = true
      "/nodes/pve1"                 = false
    })
    error_message = "The token's ACL paths are not the ones an ephemeral-sandbox run needs."
  }

  assert {
    condition     = tomap({ for path, acl in proxmox_virtual_environment_acl.certistack_user : path => acl.propagate }) == tomap({ for path, acl in proxmox_virtual_environment_acl.certistack_token : path => acl.propagate })
    error_message = "The service user and its separated token must hold the role on the same paths: PVE gives the token only what both hold."
  }

  assert {
    condition     = alltrue([for acl in proxmox_virtual_environment_acl.certistack_token : acl.token_id == "certistack-svc@pve!automation" && acl.user_id == null && acl.role_id == "CertiStackRole"])
    error_message = "Every token ACL must name the CertiStack token and CertiStackRole."
  }

  assert {
    condition     = alltrue([for acl in proxmox_virtual_environment_acl.certistack_user : acl.user_id == "certistack-svc@pve" && acl.token_id == null && acl.role_id == "CertiStackRole"])
    error_message = "Every user ACL must name the CertiStack service user and CertiStackRole."
  }

  assert {
    condition     = proxmox_virtual_environment_user_token.certistack_token.privileges_separation == true
    error_message = "The CertiStack token must stay privilege-separated."
  }

  assert {
    condition     = output.pve_token_id == "certistack-svc@pve!automation"
    error_message = "The token ID handed to the controller must be the token the ACLs name."
  }

  # The PBS inputs are only echoed for the controller (the module does not
  # configure PBS); a required input that nothing used would be a trap.
  assert {
    condition     = output.controller_connection.pbs_fingerprint == var.pbs_fingerprint
    error_message = "controller_connection must carry the PBS fingerprint the operator supplied."
  }

  # No reference VM unless a template to clone is named.
  assert {
    condition     = length(proxmox_virtual_environment_vm.reference_golden_vm) == 0
    error_message = "The module must not create a reference VM without a template to clone."
  }
}

# The provider reports the token's value as USER@REALM!TOKENID=SECRET, which a
# controller given it as PVE_TOKEN_SECRET rejects with HTTP 401. The secret
# output must be the secret alone. This run applies against the mocked provider
# (nothing is created anywhere): the provider's value is only known once the
# token exists, and `override_during = plan` needs Terraform 1.11 while the
# module supports 1.7. It must stay the only run that applies: runs in one file
# share state, so a second one would see this token and not its own override.
run "secret_output_is_the_secret_alone" {
  command = apply

  override_resource {
    target = proxmox_virtual_environment_user_token.certistack_token
    values = {
      value = "certistack-svc@pve!automation=11111111-2222-3333-4444-555555555555"
    }
  }

  assert {
    condition     = output.pve_token_secret == "11111111-2222-3333-4444-555555555555"
    error_message = "pve_token_secret must be the token's secret alone, without the token ID and '='."
  }
}

# A pre-provisioned sandbox needs its zone, not SDN.Allocate on /sdn.
run "preprovisioned_sandbox_grants" {
  command = plan

  variables {
    sandbox_sdn_zones = ["csSb01"]
  }

  assert {
    condition = tomap({ for path, acl in proxmox_virtual_environment_acl.certistack_token : path => acl.propagate }) == tomap({
      # grants: preprovisioned
      "/vms"                        = true
      "/sdn/zones/csSb01"           = true
      "/storage/certistack-scratch" = true
      "/nodes/pve1"                 = false
    })
    error_message = "The token's ACL paths are not the ones a pre-provisioned-sandbox run needs."
  }

  assert {
    condition     = tomap({ for path, acl in proxmox_virtual_environment_acl.certistack_user : path => acl.propagate }) == tomap({ for path, acl in proxmox_virtual_environment_acl.certistack_token : path => acl.propagate })
    error_message = "The service user and its separated token must hold the role on the same paths."
  }
}

# The reference VM is a full clone of a prepared template, so it has
# a disk and an installed OS to boot.
run "reference_vm_clones_the_template" {
  command = plan

  variables {
    reference_template_vmid = 9100
    pve_bridge              = "vmbr9"
    guest_password          = "test-only-password"
  }

  assert {
    condition     = length(proxmox_virtual_environment_vm.reference_golden_vm) == 1
    error_message = "A named template must produce one reference VM."
  }

  assert {
    condition     = proxmox_virtual_environment_vm.reference_golden_vm[0].clone[0].vm_id == 9100 && proxmox_virtual_environment_vm.reference_golden_vm[0].clone[0].full == true
    error_message = "The reference VM must be a full clone of the named template."
  }

  assert {
    condition     = proxmox_virtual_environment_vm.reference_golden_vm[0].network_device[0].bridge == "vmbr9"
    error_message = "The reference VM must sit on the isolated bridge."
  }
}

run "reference_vm_needs_bridge_and_password" {
  command = plan

  variables {
    reference_template_vmid = 9100
  }

  expect_failures = [proxmox_virtual_environment_vm.reference_golden_vm]
}

run "rejects_production_bridge" {
  command = plan

  variables {
    reference_template_vmid = 9100
    pve_bridge              = "vmbr0"
    guest_password          = "test-only-password"
  }

  expect_failures = [var.pve_bridge]
}

run "rejects_missing_overlay_storage" {
  command = plan

  variables {
    overlay_storage = ""
  }

  expect_failures = [var.overlay_storage]
}

run "rejects_invalid_sandbox_zone" {
  command = plan

  variables {
    sandbox_sdn_zones = ["cs-sandbox"]
  }

  expect_failures = [var.sandbox_sdn_zones]
}
