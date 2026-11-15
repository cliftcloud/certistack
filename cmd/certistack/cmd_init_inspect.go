// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"github.com/cliftcloud/certistack/internal/guestinspect"
	"github.com/cliftcloud/certistack/internal/guestnet"
	"github.com/cliftcloud/certistack/internal/journal"
	"github.com/cliftcloud/certistack/internal/recoverhint"
	"github.com/cliftcloud/certistack/pkg/controller"
	"github.com/cliftcloud/certistack/pkg/initplan"
	"github.com/cliftcloud/certistack/pkg/runner"
)

// nodeInspect inspects backups on this node: what node-inspect does for a
// controller, and init --inspect without --ssh-host. A variable so that a
// test can stand in for the node.
var nodeInspect = inspectOnThisNode

// remoteInspect has a worker the controller stages on a node inspect there;
// a variable for the same reason.
var remoteInspect = func(ctx context.Context, opts controller.RunOptions, req initplan.InspectRequest) ([]byte, error) {
	return controller.NewExecutor().Inspect(ctx, opts, req)
}

// checkGuestfish is guestnet's check that guestfish runs, a variable so a
// test needs no libguestfs.
var checkGuestfish = guestnet.CheckDependency

// inspectOnThisNode takes the node's host lock, so that no run, recovery or
// other inspection works on the node meanwhile, checks that guestfish runs,
// and inspects (runner.InspectLocked). A lock that is held, or guestfish
// missing, is a refusal in the answer: init still writes its plan.
func inspectOnThisNode(ctx context.Context, req initplan.InspectRequest, opts runner.InspectOptions) initplan.Inspection {
	lock, err := acquireHostLock()
	if err != nil {
		if strings.Contains(err.Error(), journal.LockHeldMessage) {
			return initplan.Inspection{Refused: "another CertiStack operation holds the node's host lock, so nothing was mapped; run init --inspect again once it has finished"}
		}
		return initplan.Inspection{Refused: "the node's host lock could not be taken: " + runner.SafeFailureReason(err)}
	}
	defer lock.Close()
	if err := checkGuestfish(ctx); err != nil {
		return initplan.Inspection{Refused: "guestfish (libguestfs) does not run on the node: " + runner.SafeFailureReason(err)}
	}
	return runner.InspectLocked(ctx, req, opts, readGuest)
}

// readGuest finds a guest's services on its mapped disks, read-only.
func readGuest(ctx context.Context, devices []string) (initplan.GuestFindings, error) {
	reader, err := guestnet.NewImageReader(devices)
	if err != nil {
		return initplan.GuestFindings{}, err
	}
	return guestinspect.Detect(ctx, reader)
}

// nodeInspectCmd is the temporary worker's side of init --inspect: it prints
// what it found as JSON.
func nodeInspectCmd() *cobra.Command {
	var (
		envFile   string
		scratch   string
		stateDir  string
		runID     string
		nodeName  string
		namespace string
		targets   []string
	)
	cmd := &cobra.Command{
		Use:    "node-inspect",
		Short:  "Look inside VM backups on this node for init --inspect",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := verifyNodeIdentity(nodeName); err != nil {
				return err
			}
			restoreEnvironment, err := useCommandEnvironment(envFile, true)
			if err != nil {
				return err
			}
			defer restoreEnvironment()
			req := initplan.InspectRequest{Node: nodeName, Namespace: namespace}
			for _, target := range targets {
				vmid, snapshot, ok := strings.Cut(target, "=")
				id, err := strconv.Atoi(vmid)
				if !ok || err != nil {
					return fmt.Errorf("invalid --target %q: want VMID=SNAPSHOT", target)
				}
				req.Targets = append(req.Targets, initplan.InspectTarget{SourceVMID: id, Snapshot: snapshot})
			}
			if err := initplan.ValidateInspectRequest(req); err != nil {
				return err
			}
			result := initplan.Inspection{}
			if err := ensureWorkerDirectories(stateDir, scratch); err != nil {
				result.Refused = fmt.Sprintf("prepare node worker directories: %v", err)
			} else {
				result = nodeInspect(cmd.Context(), req, runner.InspectOptions{NodeName: nodeName, ScratchDir: scratch, StateDir: stateDir, RunID: runID})
			}
			if err := json.NewEncoder(cmd.OutOrStdout()).Encode(result); err != nil {
				return fmt.Errorf("write node worker result: %w", err)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&nodeName, "node", "", "PVE node name")
	cmd.Flags().StringVar(&namespace, "namespace", "", "PBS namespace")
	cmd.Flags().StringArrayVar(&targets, "target", nil, "VMID=SNAPSHOT of a backup to inspect (repeat)")
	cmd.Flags().StringVar(&scratch, "scratch", "/var/lib/certistack/scratch", "node-local scratch directory")
	cmd.Flags().StringVar(&stateDir, "state-dir", "/var/lib/certistack", "node-local recovery journal directory")
	cmd.Flags().StringVar(&runID, "run-id", "", "run ID for the recovery journal, chosen by the controller")
	cmd.Flags().StringVar(&envFile, "env-file", "", "protected node-local controller environment file")
	for _, name := range []string{"node", "env-file"} {
		_ = cmd.MarkFlagRequired(name)
	}
	return cmd
}

// inspection is what init --inspect learned, and what it must say after the
// plan is written: cleanup that could not be verified fails the command
// (status 2) once the plan is on disk.
type inspection struct {
	result       *initplan.Inspection
	cleanupError error
}

// inspectForInit runs init's inspection, on the node through a worker when
// remote is set, else here, and never fails init for what went wrong in it:
// that is in the answer, and the plan keeps SSH probes for the VMs it could
// not inspect. An interruption is the error, after the inspection has
// released what it mapped.
func inspectForInit(ctx context.Context, stderr io.Writer, req initplan.InspectRequest, remote *controller.RunOptions, local runner.InspectOptions) (inspection, error) {
	fmt.Fprintf(stderr, "Inspecting the newest backup of %d Linux VM(s), one at a time and read-only; each takes about as long as the first part of a run on that VM.\n", len(req.Targets))
	var result initplan.Inspection
	if remote != nil {
		// A journaled worker from here on: an interrupt says what a run's does.
		remoteInspectionStaged.Store(true)
		out, err := remoteInspect(ctx, *remote, req)
		switch {
		case ctx.Err() != nil && errors.Is(err, controller.ErrInspectionCleanupUnverified):
			return inspection{}, err
		case ctx.Err() != nil || len(out) == 0 && errors.Is(err, context.Canceled):
			return inspection{}, withExitCode(errors.Join(err, ctx.Err()), exitCodeInterrupted)
		case len(out) == 0 && errors.Is(err, controller.ErrInspectionCleanupUnverified):
			return inspection{result: &initplan.Inspection{Refused: "the inspection ended without an answer"}, cleanupError: err}, nil
		case len(out) == 0:
			fmt.Fprintf(stderr, "Warning: the inspection did not run, so the plan checks Linux VMs on SSH: %v\n", err)
			return inspection{result: &initplan.Inspection{Refused: "the inspection did not run: " + runner.SafeFailureReason(err)}}, nil
		}
		if err := json.Unmarshal(out, &result); err != nil {
			fmt.Fprintf(stderr, "Warning: the node's inspection answer cannot be read, so the plan checks Linux VMs on SSH: %v\n", err)
			return inspection{result: &initplan.Inspection{Refused: "the node's answer could not be read"}}, nil
		}
		found := inspection{result: &result}
		if errors.Is(err, controller.ErrInspectionCleanupUnverified) {
			found.cleanupError = err
		} else if err != nil {
			fmt.Fprintf(stderr, "Warning: %v\n", err)
		}
		if err := initplan.CheckInspection(req, found.result); err != nil {
			fmt.Fprintf(stderr, "Warning: the node's inspection answer is not usable, so the plan checks Linux VMs on SSH: %v\n", err)
			found.result = &initplan.Inspection{Refused: "the node's answer did not match the request"}
		}
		return found, nil
	}
	localInspection.Store(true)
	if local.RunID == "" {
		local.RunID = "run-" + uuid.NewString()
	}
	result = nodeInspect(ctx, req, local)
	found := inspection{result: &result}
	if result.Journaled && !result.CleanupVerified {
		found.cleanupError = fmt.Errorf("%w: %s; on this node, run this program's recover command, or let the node's next run recover ("+recoverhint.Guide+")", controller.ErrInspectionCleanupUnverified, strings.Join(result.CleanupErrors, "; "))
	}
	switch {
	case ctx.Err() != nil && found.cleanupError != nil:
		return inspection{}, found.cleanupError
	case ctx.Err() != nil:
		return inspection{}, withExitCode(ctx.Err(), exitCodeInterrupted)
	}
	if err := initplan.CheckInspection(req, found.result); err != nil {
		found.result = &initplan.Inspection{Refused: "the inspection's answer did not match the request: " + err.Error()}
	}
	return found, nil
}
