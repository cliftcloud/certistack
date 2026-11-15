// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strconv"
	"time"

	"github.com/cliftcloud/certistack/internal/recovery"
	"github.com/cliftcloud/certistack/pkg/probe/qga"
	"github.com/cliftcloud/certistack/pkg/probe/qmp"
	"github.com/spf13/cobra"
)

// pveVMIDPattern is Proxmox VE's own VMID format (pve-vmid): a whole number
// from 100 to 999999999, without sign, spaces or leading zeros.
var pveVMIDPattern = regexp.MustCompile(`^[1-9][0-9]{2,8}$`)

func parseInspectVMID(arg string) (int, error) {
	if !pveVMIDPattern.MatchString(arg) {
		return 0, fmt.Errorf("invalid VMID %q: a Proxmox VE VMID is a whole number from 100 to 999999999", arg)
	}
	return strconv.Atoi(arg)
}

func inspectCmd() *cobra.Command {
	var (
		qmpPath  string
		qgaPath  string
		stateDir string
	)

	cmd := &cobra.Command{
		Use:   "inspect [vmid]",
		Short: "Inspect running VM sockets or active runner state journal",
		Long: `If a VMID is provided, inspects the QMP and QGA sockets of the running VM, and
fails if neither answers. If no VMID is provided, prints the active journal
record from --state-dir. With both a VMID and an explicit --state-dir, prints
that journal record as well as the VM's sockets.`,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) > 1 {
				return fmt.Errorf("inspect takes at most one VMID, but got %d arguments", len(args))
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			// What could not be written was not inspected as far as the
			// operator can tell, so the command fails.
			out := newCheckedOutput(cmd.OutOrStdout())
			if stateDir == "" {
				stateDir = "/var/lib/certistack"
			}
			if len(args) == 0 {
				record, err := recovery.Inspect(stateDir)
				if err != nil {
					return fmt.Errorf("failed to inspect state journal at %s: %w", stateDir, err)
				}
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return out.deliver(enc.Encode(record))
			}

			vmid, err := parseInspectVMID(args[0])
			if err != nil {
				return err
			}

			// An explicit --state-dir is honoured with a VMID too: the journal
			// is shown before the sockets, and a journal that cannot be read
			// fails the command even if the VM answers.
			var journalErr error
			if cmd.Flags().Changed("state-dir") {
				journalErr = printJournalSection(out, stateDir)
			}
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			return out.deliver(errors.Join(journalErr, inspectVMSockets(ctx, out, vmid, qmpPath, qgaPath)))
		},
	}

	cmd.Flags().StringVar(&qmpPath, "qmp", "", "custom QMP socket path")
	cmd.Flags().StringVar(&qgaPath, "qga", "", "custom QGA socket path")
	cmd.Flags().StringVar(&stateDir, "state-dir", "/var/lib/certistack", "runner state directory to inspect active.json")

	return cmd
}

// printJournalSection prints the active journal in stateDir as one section
// of a VM inspection.
func printJournalSection(out io.Writer, stateDir string) error {
	path := filepath.Join(stateDir, "active.json")
	fmt.Fprintf(out, "State Journal: %s ... ", path)
	record, err := recovery.Inspect(stateDir)
	if err != nil {
		fmt.Fprintf(out, "FAILED (%v)\n", err)
		return fmt.Errorf("failed to inspect state journal at %s: %w", stateDir, err)
	}
	fmt.Fprintln(out, "READ")
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return fmt.Errorf("encode state journal at %s: %w", stateDir, err)
	}
	fmt.Fprintf(out, "%s\n", data)
	return nil
}

// inspectVMSockets reports the VM's QMP status and guest-agent reachability.
// A missing guest agent alone is an ordinary condition, so the inspection
// succeeds if either QMP answered query-status or the agent completed its
// handshake, and fails only when it learned nothing about the VM.
//
// ctx is the command's context: an interrupt ends the wait on either socket at
// once, and what was inspected is then not reported as a result. An inspection
// whose context ended is an interrupted one (the root exits 130) even when both
// sockets had answered by then, never a late success.
func inspectVMSockets(ctx context.Context, out io.Writer, vmid int, qmpPath, qgaPath string) error {
	interrupted := func() error {
		if err := ctx.Err(); err != nil {
			fmt.Fprintf(out, "  Inspection interrupted.\n")
			return fmt.Errorf("inspection of VM %d was interrupted: %w", vmid, err)
		}
		return nil
	}
	if qmpPath == "" {
		qmpPath = qmp.DefaultSocketPath(vmid)
	}
	if qgaPath == "" {
		qgaPath = qga.DefaultSocketPath(vmid)
	}

	fmt.Fprintf(out, "Inspecting VM %d...\n", vmid)

	// 1. QMP Inspection
	qmpAnswered := false
	fmt.Fprintf(out, "  QMP Socket: %s ... ", qmpPath)
	client, err := qmp.DialContext(ctx, qmpPath, 3*time.Second)
	if err != nil {
		fmt.Fprintf(out, "FAILED (%v)\n", err)
	} else {
		defer client.Close()
		status, err := client.QueryStatusContext(ctx)
		if err != nil {
			fmt.Fprintf(out, "CONNECTED, query-status failed: %v\n", err)
		} else {
			qmpAnswered = true
			fmt.Fprintf(out, "CONNECTED (Status: %s, Running: %v)\n", status.Status, status.Running)
		}
	}

	if err := interrupted(); err != nil {
		return err
	}

	// 2. QGA Inspection
	qgaAnswered := false
	fmt.Fprintf(out, "  QGA Socket: %s ... ", qgaPath)
	qgaClient, err := qga.DialContext(ctx, qgaPath, 3*time.Second)
	if err != nil {
		fmt.Fprintf(out, "UNAVAILABLE (%v)\n", err)
	} else {
		defer qgaClient.Close()
		qgaAnswered = true
		fmt.Fprintf(out, "CONNECTED (Agent active)\n")
	}

	if err := interrupted(); err != nil {
		return err
	}
	if !qmpAnswered && !qgaAnswered {
		return fmt.Errorf("could not inspect VM %d: neither its QMP socket nor its guest agent answered; check that the VM is running on this node and that the socket paths are right", vmid)
	}
	return nil
}
