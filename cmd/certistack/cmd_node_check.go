// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/cliftcloud/certistack/internal/nodecheck"
)

// nodeCheckProbes are what node-check asks of this node. A test replaces them.
var nodeCheckProbes = nodecheck.DefaultProbes()

// nodeCheckCmd is the temporary worker's side of the controller's check: it
// tries, on this node, the layers only the node can answer and prints the
// report as JSON. It exits zero whenever it produced one, a failed layer
// included, since the report is the result.
func nodeCheckCmd() *cobra.Command {
	var envFile, through, nodeName, sandboxRange, sandboxProbe, sandboxVNet, sandboxLifecycle, sandboxMode, sandboxPeers, sshClient string
	var noWireProbes bool
	cmd := &cobra.Command{
		Use:    "node-check",
		Short:  "Check on this node what a run needs, for a controller",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			// The node the controller addresses must be this one: the layers
			// below call PVE with that name. An old controller names none.
			if err := verifyNodeIdentity(nodeName); err != nil {
				return err
			}
			if err := recordSSHClient(sshClient); err != nil {
				return err
			}
			restoreEnvironment, err := useCommandEnvironment(envFile, true)
			if err != nil {
				return err
			}
			defer restoreEnvironment()
			settings := nodecheck.SettingsFromEnvironment(envBool("PVE_TLS_INSECURE"))
			settings.NoWireProbes = noWireProbes
			// The plan's sandbox network, when the controller has one to judge.
			if sandboxRange != "" || sandboxProbe != "" || sandboxVNet != "" || sandboxLifecycle != "" || sandboxMode != "" || sandboxPeers != "" {
				if sandboxRange == "" || sandboxProbe == "" {
					return fmt.Errorf("--sandbox-range and --sandbox-probe (the plan's network.ip_range and network.probe_ip) go together")
				}
				settings.Sandbox = &nodecheck.Sandbox{IPRange: sandboxRange, ProbeIP: sandboxProbe, VNetID: sandboxVNet, Lifecycle: sandboxLifecycle, Mode: sandboxMode, Peers: sandboxPeers}
			}
			report := nodecheck.RunThrough(cmd.Context(), settings, nodeCheckProbes, through)
			if err := json.NewEncoder(cmd.OutOrStdout()).Encode(report); err != nil {
				return fmt.Errorf("write the node check report: %w", err)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&envFile, "env-file", "", "protected node-local controller environment file")
	cmd.Flags().StringVar(&nodeName, "node", "", "PVE node name the controller addresses; refused when it is not this host's (default: not checked)")
	cmd.Flags().StringVar(&through, "through", "", "stop after this layer (node_tools, pve_api) when it passes; default: every layer")
	cmd.Flags().StringVar(&sandboxRange, "sandbox-range", "", "the plan's network.ip_range: judge it against this node (a last layer)")
	cmd.Flags().StringVar(&sandboxProbe, "sandbox-probe", "", "the plan's network.probe_ip")
	cmd.Flags().StringVar(&sandboxVNet, "sandbox-vnet", "", "the plan's network.vnet_id")
	cmd.Flags().StringVar(&sandboxLifecycle, "sandbox-lifecycle", "", "the plan's network.lifecycle")
	cmd.Flags().StringVar(&sandboxMode, "sandbox-mode", "", "the plan's network.mode (vxlan: its peers are judged against the range)")
	cmd.Flags().StringVar(&sandboxPeers, "sandbox-peers", "", "the plan's network.peers, for a vxlan network")
	addSSHClientFlag(cmd, &sshClient)
	cmd.Flags().BoolVar(&noWireProbes, "no-wire-probes", false, "the plan has no wire probe, so nft is not required of this node")
	_ = cmd.MarkFlagRequired("env-file")
	return cmd
}
