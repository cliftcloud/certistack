// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/cliftcloud/certistack/internal/nodesetup"
)

func setupRBACCmd() *cobra.Command {
	var (
		node, overlayStorage, zone, datastore, namespace, part string
		zones                                                  []string
	)
	cmd := &cobra.Command{
		Use:   "rbac --node NAME --overlay-storage ID [--zone ZONE | --sandbox-zones a,b] [--pbs-datastore DS] [--pbs-namespace NS] [--part pve|pbs]",
		Short: "Print the script that creates the PVE role, user, token and ACLs and the read-only PBS user",
		Long: `Prints a shell script for you to read and run; it executes nothing and
changes nothing. The script holds the commands of the manual recipe
(https://certistack.dev/docs/manual-setup/#set-up-by-hand), filled in for your
node; certistack setup runs the same script itself, part by part:

  PART 1, as root on a Proxmox VE node (pveum):
    the role CertiStackRole (the privileges in terraform/main.tf), the user
    certistack-svc@pve, the privilege-separated token certistack-svc@pve!automation,
    and the ACLs for the user AND the token on each path of the permission table
    at https://certistack.dev/docs/manual-setup/, with the propagation the table
    gives and never on "/".
  PART 2, as root on the Proxmox Backup Server (proxmox-backup-manager), only
    with --pbs-datastore: a read-only user and token, each holding DatastoreReader
    on the datastore (or only on one namespace of it, with --pbs-namespace).

The sandbox is ephemeral by default (the /sdn and /sdn/zones paths). For
pre-provisioned sandbox zones name them with --zone or --sandbox-zones, and each
zone is granted instead.

To send one part to its own host without copying the file, print it alone with
--part pve or --part pbs; each is a complete script that checks its host and
stops with the step's name, for example:

  certistack setup rbac ... --pbs-datastore DS --part pve | ssh root@NODE sh -s
  certistack setup rbac ... --pbs-datastore DS --part pbs | ssh root@PBS-HOST sh -s

Run the whole file on a PVE node and PART 2 says that part 1 is done and that
part 2 belongs on the Proxmox Backup Server; it does not fail.

Each token's secret is printed once, by the command in the script that creates
it, on the terminal where you run the script. This tool never sees it: copy it
into your 0600 environment file (PVE_TOKEN_SECRET, PBS_PASSWORD).

The script can be run again, after an error or with a newer CertiStack: it sets
an existing role to the current privileges, leaves an existing user alone, and
for an existing token says that its secret cannot be shown again and how to
replace it, then goes on with the ACLs. A failing step stops it with the step's
name.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if zone != "" {
				zones = []string{zone}
			}
			params := nodesetup.RBACParams{
				Node:           node,
				OverlayStorage: overlayStorage,
				Zones:          zones,
				PBSDatastore:   datastore,
				PBSNamespace:   namespace,
				Part:           part,
			}
			command := []string{"certistack setup rbac --node " + node, "--overlay-storage " + overlayStorage}
			switch {
			case zone != "":
				command = append(command, "--zone "+zone)
			case len(zones) > 0:
				command = append(command, "--sandbox-zones "+strings.Join(zones, ","))
			}
			if datastore != "" {
				command = append(command, "--pbs-datastore "+datastore)
			}
			if namespace != "" {
				command = append(command, "--pbs-namespace "+namespace)
			}
			if part != "" {
				command = append(command, "--part "+part)
			}
			params.Command = strings.Join(command, " ")
			script, err := nodesetup.RBACScript(params)
			if err != nil {
				return err
			}
			out := newCheckedOutput(cmd.OutOrStdout())
			fmt.Fprint(out, script)
			return out.deliver(nil)
		},
	}
	cmd.Flags().StringVar(&node, "node", "", "the PVE node that hosts the sandbox, as PVE names it (granted on /nodes/<node>)")
	cmd.Flags().StringVar(&overlayStorage, "overlay-storage", "", "the PVE storage ID for the overlays, the plan's storage.overlay_storage (granted on /storage/<id>)")
	cmd.Flags().StringVar(&zone, "zone", "", "a pre-provisioned sandbox zone to grant instead of the ephemeral sandbox's SDN paths")
	cmd.Flags().StringSliceVar(&zones, "sandbox-zones", nil, "several pre-provisioned sandbox zones, comma-separated, as the Terraform module's sandbox_sdn_zones")
	cmd.Flags().StringVar(&datastore, "pbs-datastore", "", "the PBS datastore: adds PART 2, the read-only PBS user and token")
	cmd.Flags().StringVar(&namespace, "pbs-namespace", "", "limit the PBS grant to this namespace of the datastore")
	cmd.Flags().StringVar(&part, "part", "", "print only one part, as a complete script for its host: pve (the Proxmox VE part) or pbs (the Proxmox Backup Server part, needs --pbs-datastore); default: both")
	_ = cmd.MarkFlagRequired("node")
	_ = cmd.MarkFlagRequired("overlay-storage")
	cmd.MarkFlagsMutuallyExclusive("zone", "sandbox-zones")
	return cmd
}
