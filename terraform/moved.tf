# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 Clift Cloud LLC

# Moves state that holds the ACLs and the token under the provider's
# deprecated type names (proxmox_virtual_environment_*) to the current ones.
# The provider converts each object in place; nothing in PVE is replaced. The
# first plan after the move also shows the token as updated in place, with no
# attribute changed: the move drops the sensitive mark of its value, and the
# update only sets the same comment and privilege separation again.

moved {
  from = proxmox_virtual_environment_user_token.certistack_token
  to   = proxmox_user_token.certistack_token
}

moved {
  from = proxmox_virtual_environment_acl.certistack_user
  to   = proxmox_acl.certistack_user
}

moved {
  from = proxmox_virtual_environment_acl.certistack_token
  to   = proxmox_acl.certistack_token
}
