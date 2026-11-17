// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/initplan"
)

// Plan has a temporary worker, staged on the node exactly as Run stages it,
// work out what a run of the plan would do there, without changing
// anything (node-plan). It returns the worker's plan as JSON. The workspace
// is always removed afterwards: planning creates nothing a recovery could
// need, so none is kept.
func (e *Executor) Plan(ctx context.Context, opts RunOptions) ([]byte, error) {
	if e == nil || e.runner == nil {
		return nil, errors.New("controller executor is not initialized")
	}
	if err := validateTarget(&opts); err != nil {
		return nil, err
	}
	plan, err := config.LoadFromFile(opts.PlanPath)
	if err != nil {
		return nil, fmt.Errorf("load validation plan: %w", err)
	}
	if err := resolveScratchDir(&opts, plan); err != nil {
		return nil, err
	}
	opts.sshClient = e.nodeSSHClient(ctx, opts.SSH)
	return e.readOnNode(ctx, opts, plan, "plan", func(workspace string) []string {
		return buildNodePlanCommand(workspace, opts)
	})
}

// Discover has a temporary worker, staged on the node as Run stages it,
// read what init needs to write a first plan (node-discover): the VMs with
// backups, what their backups say, and the node's storages and free IDs. It
// returns the worker's discovery as JSON and removes the workspace.
func (e *Executor) Discover(ctx context.Context, opts RunOptions, req initplan.Request) ([]byte, error) {
	if e == nil || e.runner == nil {
		return nil, errors.New("controller executor is not initialized")
	}
	if err := validateNode(&opts); err != nil {
		return nil, err
	}
	if err := resolveScratchDir(&opts, nil); err != nil {
		return nil, err
	}
	command, err := buildNodeDiscoverCommand(req, opts.ScratchDir)
	if err != nil {
		return nil, err
	}
	return e.readOnNode(ctx, opts, nil, "discover", func(workspace string) []string {
		return append([]string{path.Join(workspace, "certistack-node")}, append(command, "--env-file", path.Join(workspace, "runtime.env"))...)
	})
}

// readOnNode stages a temporary worker workspace (with plan, when there is
// one), runs command in it, and removes it. Nothing it runs may change the
// node: no workspace is kept for a recovery. When the command fails there is
// no output; a cleanup error comes back with the output.
func (e *Executor) readOnNode(ctx context.Context, opts RunOptions, plan *config.Plan, what string, command func(workspace string) []string) (output []byte, retErr error) {
	if ctx == nil {
		ctx = context.Background()
	}
	localStage, err := os.MkdirTemp("", "certistack-controller-")
	if err != nil {
		return nil, fmt.Errorf("create controller staging directory in %s: %w", os.TempDir(), err)
	}
	defer os.RemoveAll(localStage)
	if err := os.Chmod(localStage, 0o700); err != nil {
		return nil, fmt.Errorf("secure controller staging directory: %w", err)
	}
	if err := e.checkNodeArchitecture(ctx, opts.SSH); err != nil {
		return nil, err
	}
	// A plan is what a run of it would do, and a run on a node whose clock its
	// report cannot survive would end with the evidence refused: plan says so
	// as run does. A read for another purpose (init's discovery,
	// which has no plan) signs nothing and has no report to refuse.
	if plan != nil {
		writer := opts.Writer
		if writer == nil {
			writer = io.Discard
		}
		progress := newProgressReporter(writer)
		err := e.checkNodeClock(ctx, opts.SSH, opts.NodeName, progress)
		_ = progress.close()
		if err != nil {
			return nil, err
		}
	}
	workspaceRoot, err := workerWorkspaceRoot(opts.StateDir)
	if err != nil {
		return nil, err
	}
	workspace := path.Join(workspaceRoot, uuid.NewString())
	staging := path.Join("/tmp", "certistack-controller-"+path.Base(workspace))
	// The removal is bounded, and an operator's second interrupt (the cleanup
	// context the caller gives, cancelled only then) abandons it, as it does a
	// run's cleanup.
	cleanupParent := opts.CleanupContext
	if cleanupParent == nil {
		cleanupParent = context.Background()
	}
	// watched is set once the node's lease watch removes the workspace by
	// itself, which is what an abandoned removal falls back on.
	watched := false
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(cleanupParent, 30*time.Second)
		defer cancel()
		var errs []error
		if err := e.removeWorkspace(cleanupCtx, opts.SSH, workspaceRoot, workspace); err != nil {
			errs = append(errs, fmt.Errorf("remove temporary node workspace %s: %w", workspace, err))
		}
		if err := e.removeStaging(cleanupCtx, opts.SSH, staging); err != nil {
			errs = append(errs, fmt.Errorf("remove temporary SSH staging directory: %w", err))
		}
		if len(errs) > 0 && cleanupParent.Err() != nil {
			// A read keeps no journal and nothing a recovery could need. Its
			// workspace holds the read's credentials, and the lease watch on
			// the node removes it once the lease is no longer renewed (this
			// controller stopped renewing it with the read); before the watch
			// runs, nothing does.
			if watched {
				errs = append(errs, fmt.Errorf("cleanup was abandoned; the node removes the temporary workspace %s itself about %d seconds after this controller stops renewing its lease, and there is nothing to recover manually", workspace, workerLeaseDurationSeconds))
			} else {
				errs = append(errs, fmt.Errorf("cleanup was abandoned before the node's lease watch of the temporary workspace was running, so nothing on the node removes it: delete the directory %s and the SSH staging directory %s on node %s", workspace, staging, opts.NodeName))
			}
		}
		if len(errs) > 0 {
			retErr = errors.Join(append([]error{retErr}, errs...)...)
		}
	}()
	if err := e.stageWorkspace(ctx, opts, plan, localStage, workspaceRoot, workspace, staging); err != nil {
		return nil, err
	}
	// The workspace holds the read's credentials, as a run's does, and gets
	// the same lease: the controller renews it for as long as the read lasts,
	// so another run on the node sees a live workspace and not an idle one,
	// and a watch on the node removes the workspace once the lease is no
	// longer renewed, whether or not this controller lives to do it.
	leasePath := path.Join(workspace, "controller.lease")
	if err := e.createWorkerLease(ctx, opts.SSH, workspaceRoot, workspace, leasePath); err != nil {
		return nil, err
	}
	if err := e.startReadLeaseWatch(ctx, opts.SSH, opts.StateDir, workspaceRoot, workspace, leasePath); err != nil {
		return nil, err
	}
	watched = true
	leaseWriter := opts.Writer
	if leaseWriter == nil {
		leaseWriter = io.Discard
	}
	leaseProgress := newProgressReporter(leaseWriter)
	defer func() { _ = leaseProgress.close() }()
	stopLease := e.startWorkerLease(ctx, opts.SSH, workspaceRoot, workspace, leasePath, leaseProgress.warning)
	defer stopLease()
	output, err = e.remoteCommand(ctx, opts.SSH, append(e.privilegePrefix(opts.SSH), command(workspace)...))
	if err != nil {
		return nil, fmt.Errorf("%s on node %s: %w", what, opts.NodeName, err)
	}
	return output, nil
}

// buildNodePlanCommand is node-plan's command line in workspace.
func buildNodePlanCommand(workspace string, opts RunOptions) []string {
	command := []string{
		path.Join(workspace, "certistack-node"), "node-plan",
		"--plan", path.Join(workspace, "plan.yaml"),
		"--node", opts.NodeName,
		"--scratch", opts.ScratchDir,
		"--state-dir", opts.StateDir,
		"--env-file", path.Join(workspace, "runtime.env"),
	}
	if opts.OverlayStorage != "" {
		command = append(command, "--overlay-storage", opts.OverlayStorage)
	}
	if opts.sshClient != "" {
		command = append(command, "--ssh-client", opts.sshClient)
	}
	return command
}

// buildNodeDiscoverCommand is node-discover's arguments for req, after the
// worker binary and before --env-file. Every value is checked here, on the
// controller, before it reaches the node. scratch, the node directory the
// backups' configurations are restored into, goes with them, so the worker
// does not restore into a temporary directory of its own.
func buildNodeDiscoverCommand(req initplan.Request, scratch string) ([]string, error) {
	if err := initplan.ValidateRequest(req); err != nil {
		return nil, err
	}
	command := []string{"node-discover", "--node", req.Node}
	if scratch != "" {
		command = append(command, "--scratch", scratch)
	}
	if req.Namespace != "" {
		command = append(command, "--namespace", req.Namespace)
	}
	if req.All {
		command = append(command, "--all")
	}
	if len(req.VMIDs) > 0 {
		command = append(command, "--vm", joinInts(req.VMIDs))
	}
	if req.FirstVMID > 0 {
		command = append(command, "--first-vmid", strconv.Itoa(req.FirstVMID))
	}
	if len(req.AvoidVMIDs) > 0 {
		command = append(command, "--avoid-vmid", joinInts(req.AvoidVMIDs))
	}
	if len(req.AvoidSDNIDs) > 0 {
		command = append(command, "--avoid-sdn", strings.Join(req.AvoidSDNIDs, ","))
	}
	return command, nil
}

func joinInts(ids []int) string {
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = strconv.Itoa(id)
	}
	return strings.Join(parts, ",")
}
