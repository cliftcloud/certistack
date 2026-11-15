// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/spf13/cobra"

	"github.com/cliftcloud/certistack/internal/preflight"
)

// addSSHClientFlag gives a node-side command the hidden --ssh-client flag: the
// address the controller's SSH session reaches this node from, which the
// controller reads in its own session (a worker started under sudo or as a
// transient service has no SSH_CONNECTION of its own). The sandbox check refuses
// a range that holds it, since the node would send that session's replies into
// the sandbox.
func addSSHClientFlag(cmd *cobra.Command, value *string) {
	cmd.Flags().StringVar(value, "ssh-client", "", "the address the controller's SSH session reaches this node from (given by the controller; the sandbox range must not hold it)")
	_ = cmd.Flags().MarkHidden("ssh-client")
}

// requireNodeName refuses an empty --node of a worker command. The flag is
// required, and "" satisfies that, but the identity check treats an empty name
// as a name left out (whose default is the host's own) and the runner would
// then call the node "localhost". The controller always sends the name; an empty
// one means the command was typed by hand (review R2-12).
func requireNodeName(command, nodeName string) error {
	if nodeName != "" {
		return nil
	}
	return fmt.Errorf("%s: --node is empty: give the short name of the PVE node this worker runs on (the controller sends it; this command is not meant to be typed by hand, use certistack run or plan with --ssh-host instead)", command)
}

// recordSSHClient hands the flag's value to the sandbox check. An empty value
// leaves the address to this process's own SSH_CONNECTION; anything that is not
// an IP address is refused.
func recordSSHClient(value string) error {
	value = strings.TrimSpace(value)
	if value != "" {
		if _, err := netip.ParseAddr(value); err != nil {
			return fmt.Errorf("--ssh-client %q is not an IP address", value)
		}
	}
	preflight.SetSSHClient(value)
	return nil
}
