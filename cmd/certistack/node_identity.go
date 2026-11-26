// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"fmt"

	"github.com/cliftcloud/certistack/internal/nodeidentity"
)

// verifyNodeIdentity is nil when the node name a command was given
// (CERTISTACK_NODE or --node) is the PVE name of the host the command runs on,
// compared exactly, and says how to fix it when it is not. Every command that
// runs on a node does it first, before it calls PVE or PBS, writes a journal
// or changes anything: a worker that runs on one node and addresses another
// would otherwise fail late and cryptically, or act on the wrong node. It is a
// variable so that a test, which runs on no PVE node, can name its own host.
var verifyNodeIdentity = nodeidentity.Verify

// hostIsPVENode is false only when this host is evidently not a PVE node (no
// /etc/pve, neither pveversion nor qm). It is a variable so that a test, which
// runs on no PVE node, can say what the host is.
var hostIsPVENode = nodeidentity.OnPVENode

// requirePVENodeWithoutSSHHost is what plan and init, which work from the
// controller through an SSH host and otherwise on the PVE node itself, call
// when no SSH host is set: it is nil on a PVE node, where working on the node
// is the legitimate use, and on any other host stops the command before it
// calls PVE or PBS. envFile is the --env-file the command was given, "" for
// none.
func requirePVENodeWithoutSSHHost(envFile string) error {
	if hostIsPVENode() {
		return nil
	}
	const notANode = "this host is not a PVE node (it has no /etc/pve, and neither pveversion nor qm)"
	if envFile == "" {
		return fmt.Errorf("%s, and no SSH host is set: pass --env-file FILE to work from the controller; without it this command runs on the PVE node itself and must be run there", notANode)
	}
	return fmt.Errorf("%s, and no SSH host is set (CERTISTACK_SSH_HOST is not in %s, and there is no --ssh-host): set CERTISTACK_SSH_HOST there to work from the controller; without an SSH host this command runs on the PVE node itself and must be run there", notANode, envFile)
}
