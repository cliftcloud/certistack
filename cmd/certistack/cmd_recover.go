// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/cliftcloud/certistack/internal/recoverhint"
	"github.com/cliftcloud/certistack/internal/recovery"
	"github.com/spf13/cobra"
)

// recoverState is the recovery the command runs; tests replace it, since the
// real one takes the node's host-wide lock. ctx is the command's context, which
// the first interrupt cancels, and abandon the cleanup context, which the second
// cancels (see recovery.RecoverLockedContext for what each ends).
var recoverState = recoveryFromPackage

// recoveryFromPackage is the real recovery.
func recoveryFromPackage(ctx, abandon context.Context, stateDir string) error {
	return recovery.RecoverContext(ctx, abandon, stateDir)
}

func recoverCmd() *cobra.Command {
	return recoverCmdWithCleanupContext(nil)
}

// recoverCmdWithCleanupContext is recover; cleanupContext, when set, is
// cancelled by the second interrupt, which the root handler offers.
func recoverCmdWithCleanupContext(cleanupContext context.Context) *cobra.Command {
	var (
		stateDir string
		envFile  string
	)

	cmd := &cobra.Command{
		Use:   "recover",
		Short: "Reconcile exact node-worker resources after a crash",
		Long: `Safely recovers an interrupted or crashed CertiStack test run.
Inspects the state journal in the state directory, confirms process identities
via kernel start ticks to avoid PID reuse, verifies CertiStack ownership before
destroying recorded PVE VMs and SDN objects, safely terminates hanging runners,
and detaches only recorded loop devices. Run this on the PVE node with the
same PVE credentials used by the temporary worker.

recover takes no arguments: name the directory with --state-dir. A path given
as an argument would otherwise be ignored while recovery ran on the default
directory.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if envFile != "" {
				restoreEnvironment, err := useCommandEnvironment(envFile, true)
				if err != nil {
					return err
				}
				defer restoreEnvironment()
			}
			if stateDir == "" {
				stateDir = "/var/lib/certistack"
			}

			// Recovery changes the node; a report of it that could not be
			// written is a failure to say what was done, not a success.
			out := newCheckedOutput(cmd.OutOrStdout())
			fmt.Fprintf(out, "Initiating crash recovery on state directory: %s\n", stateDir)
			ctx, abandon := cmd.Context(), cleanupContext
			if ctx == nil {
				ctx = context.Background()
			}
			if abandon == nil {
				abandon = context.Background()
			}
			if err := recoverState(ctx, abandon, stateDir); err != nil {
				if errors.Is(err, context.Canceled) {
					// Said as what it is: an interrupted recovery is not a
					// failed one, and its journal is still to be finished.
					fmt.Fprintf(out, "✗ Crash recovery was interrupted: %v\n  The journal keeps what recovery had not finished; "+recoverhint.Again+".\n", err)
					return out.deliver(err)
				}
				fmt.Fprintf(out, "✗ Crash recovery failed: %v\n", err)
				return out.deliver(err)
			}

			fmt.Fprintln(out, "✓ Crash recovery completed successfully. State reconciled.")
			return out.deliver(nil, "crash recovery ran and completed")
		},
	}

	cmd.Flags().StringVar(&stateDir, "state-dir", "/var/lib/certistack", "runner state directory containing active.json")
	cmd.Flags().StringVar(&envFile, "env-file", "", "allowlisted worker environment file; values are parsed literally, never shell-sourced")

	return cmd
}
