// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/cliftcloud/certistack/pkg/initplan"
)

// ErrInspectionCleanupUnverified is what Inspect's error wraps when the
// controller could not verify that the inspection released everything it
// mapped on the node. The node's journal keeps what is left, and the workspace
// is kept for its recovery: the node recovers it by itself once this
// controller's lease lapses, and its next CertiStack run recovers it first.
var ErrInspectionCleanupUnverified = errors.New("the inspection's cleanup on the node could not be verified")

// Inspect has a temporary worker look inside the newest backup of each VM in
// req (node-inspect) and returns its answer as JSON. The worker maps backups
// on the node, so it is staged and supervised exactly as Run's is: the same
// workspace, controller lease and systemd supervisor, which stops the worker
// and recovers its journal when the controller goes away, and the same checks
// afterwards. With an answer, the node's journal is verified as a run's is
// (reconcileCompletedWorker); without one (the worker failed, the connection
// was lost, the controller was interrupted) the worker is stopped and its
// journal recovered (reconcileInterruptedWorker). The workspace is removed
// once the journal shows the inspection clean, and kept otherwise.
func (e *Executor) Inspect(ctx context.Context, opts RunOptions, req initplan.InspectRequest) (output []byte, retErr error) {
	if e == nil || e.runner == nil {
		return nil, errors.New("controller executor is not initialized")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	cleanupParent := opts.CleanupContext
	if cleanupParent == nil {
		cleanupParent = context.Background()
	}
	if err := validateNode(&opts); err != nil {
		return nil, err
	}
	if req.Node != opts.NodeName {
		return nil, fmt.Errorf("the inspection is for node %q, not %q", req.Node, opts.NodeName)
	}
	if err := initplan.ValidateInspectRequest(req); err != nil {
		return nil, err
	}
	if err := resolveScratchDir(&opts, nil); err != nil {
		return nil, err
	}
	if opts.Writer == nil {
		opts.Writer = io.Discard
	}
	progress := newProgressReporter(opts.Writer)
	defer func() {
		if problem := progress.close(); problem != nil && retErr != nil {
			retErr = errors.Join(retErr, problem)
		}
	}()
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
	workspaceRoot, err := workerWorkspaceRoot(opts.StateDir)
	if err != nil {
		return nil, err
	}
	workspace := path.Join(workspaceRoot, uuid.NewString())
	staging := path.Join("/tmp", "certistack-controller-"+path.Base(workspace))
	workspaceRemovable, keepWorkspaceForLog, nodeUnreachable := true, false, false
	defer func() {
		if nodeUnreachable {
			progress.notice("warning: node %s cannot be reached, so the controller removed nothing there. If the node still has this inspection's workspace (%s), its next CertiStack run recovers what the inspection left, then removes the workspace's credentials.", opts.NodeName, workspace)
			return
		}
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		var cleanupErrs []error
		switch {
		case workspaceRemovable && keepWorkspaceForLog:
			progress.notice("warning: retaining temporary node workspace %s: the node could not keep the recovery log, and its worker-progress.log is the log's only copy; removing only the workspace's credentials", workspace)
			if err := e.scrubWorkspaceCredentials(cleanupCtx, opts.SSH, workspaceRoot, workspace, "the node could not keep this inspection's recovery log, so its workspace, which holds the log, was kept"); err != nil {
				cleanupErrs = append(cleanupErrs, err)
			}
		case workspaceRemovable:
			if err := e.removeWorkspace(cleanupCtx, opts.SSH, workspaceRoot, workspace); err != nil {
				progress.notice("warning: could not remove temporary node workspace %s: %v", workspace, err)
				cleanupErrs = append(cleanupErrs, err)
			}
		default:
			progress.notice("warning: retaining temporary node workspace %s because the inspection's cleanup could not be verified", workspace)
			if os.Getenv("CERTISTACK_PBS_KEYFILE") != "" {
				if err := e.removeRetainedKey(cleanupCtx, opts.SSH, workspaceRoot, workspace); err != nil {
					progress.notice("warning: could not remove the PBS encryption key from the retained workspace %s: %v", workspace, err)
					cleanupErrs = append(cleanupErrs, err)
				}
			}
		}
		if err := e.removeStaging(cleanupCtx, opts.SSH, staging); err != nil {
			progress.notice("warning: could not remove temporary SSH staging directory: %v", err)
			cleanupErrs = append(cleanupErrs, err)
		}
		if len(cleanupErrs) > 0 {
			retErr = errors.Join(retErr, fmt.Errorf("%w: %w", ErrControllerMaterialCleanupUnverified, errors.Join(cleanupErrs...)))
		}
	}()

	if err := e.stageWorkspace(ctx, opts, nil, localStage, workspaceRoot, workspace, staging); err != nil {
		return nil, err
	}
	leasePath := path.Join(workspace, "controller.lease")
	if err := e.createWorkerLease(ctx, opts.SSH, workspaceRoot, workspace, leasePath); err != nil {
		return nil, err
	}
	workerUnit, err := workerUnitName(workspaceRoot, workspace)
	if err != nil {
		return nil, err
	}
	bootID := e.nodeBootID(ctx, opts.SSH)
	var workerEnded atomic.Bool
	stopLease := e.startWorkerLease(cleanupParent, opts.SSH, workspaceRoot, workspace, leasePath, func(format string, args ...interface{}) {
		if !workerEnded.Load() {
			progress.warning(format, args...)
		}
	})
	defer stopLease()
	workerCommand := e.supervisedWorkerCommand(
		opts.SSH,
		workerUnit,
		workspaceRoot,
		workspace,
		path.Join(workspace, "worker.pid"),
		leasePath,
		opts.StateDir,
		path.Join(workspace, "runtime.env"),
		path.Join(workspace, "worker-result.json"),
		path.Join(workspace, "worker-progress.log"),
		buildNodeInspectCommand(workspace, opts, req),
	)
	progress.status("Inspecting the newest backup of %d VM(s) on node %s, one at a time and read-only.", len(req.Targets), opts.NodeName)
	stopHeartbeat := progress.startHeartbeat()
	resultData, err := e.remoteCommandWithProgress(ctx, opts.SSH, workerCommand, progress)
	for _, wait := range setupRetries {
		if err == nil || ctx.Err() != nil || !workerNeverStarted(err) {
			break
		}
		progress.warning("Could not start the worker on node %s (%s); trying again in %s.", opts.NodeName, sshReason(err), roughly(wait))
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
			resultData, err = e.remoteCommandWithProgress(ctx, opts.SSH, workerCommand, progress)
		}
	}
	stopHeartbeat()
	workerEnded.Store(true)
	var inspection initplan.Inspection
	if err == nil {
		err = decodeInspection(resultData, &inspection)
	}
	if err != nil {
		contact := nodeContact{name: opts.NodeName, bootID: bootID, progress: progress}
		contact.workerStuck = remoteStatus(err) == supervisorWorkerStuckStatus
		if remoteStatus(err) == supervisorLogNotKeptStatus || strings.Contains(err.Error(), recoveryLogNotKeptMessage) {
			keepWorkspaceForLog = true
		}
		reconnected := false
		if ctx.Err() == nil && sshTransportFailed(err) && !workerNeverStarted(err) {
			if e.nodeAnswersAtOnce(ctx, opts.SSH) {
				// The node is up: its worker ended, or only the connection was cut.
				reconnected = true
				progress.failure("The ssh connection to node %s ended, but the node answers: it has not crashed or lost its network. Checking what the inspection's worker left.", opts.NodeName)
			} else {
				contact.lost = true
				progress.failure("Lost contact with node %s: %s. Its temporary maps are released as soon as it answers; waiting up to %s.", opts.NodeName, sshReason(err), roughly(interruptionCleanupTimeout))
			}
		}
		var found journalOutcome
		contact.outcome = &found
		cleanupCtx, cancel := context.WithTimeout(cleanupParent, interruptionCleanupTimeout)
		_, cleanupErr := e.reconcileInterruptedWorker(cleanupCtx, opts.SSH, workspaceRoot, workspace, opts.StateDir, contact)
		cancel()
		if cleanupErr != nil {
			workspaceRemovable = false
			var unreachable *nodeUnreachableError
			if errors.As(cleanupErr, &unreachable) {
				nodeUnreachable = true
			}
			progress.failure("The inspection's cleanup on node %s could not be verified: %s. If the node is running, it recovers the inspection's journal by itself once the worker's lease is %d s old; its next CertiStack run recovers it first; to recover it now, run on the node: %s", opts.NodeName, lastErrorLine(cleanupErr), workerLeaseDurationSeconds, strings.Join(e.recoverCommand(opts.SSH, workspace, opts.StateDir), " "))
			return nil, fmt.Errorf("%w: %w", ErrInspectionCleanupUnverified, cleanupErr)
		}
		if ctx.Err() != nil {
			progress.failure("Interrupted; the inspection's temporary resources on node %s were reconciled.", opts.NodeName)
			return nil, ctx.Err()
		}
		if reconnected {
			if message, endErr, ok := workerEnd(opts.NodeName, workerUnit, found.workerStop, "the inspection's maps were released", err); ok {
				progress.failure("%s", message)
				return nil, fmt.Errorf("inspect backups on node %s: %w", opts.NodeName, endErr)
			}
		}
		return nil, fmt.Errorf("inspect backups on node %s: %w", opts.NodeName, err)
	}
	// The worker's word that it released its maps is checked against the
	// node's journal, as a run's teardown is.
	cleanupCtx, cancel := context.WithTimeout(cleanupParent, interruptionCleanupTimeout)
	teardownErr := e.reconcileCompletedWorker(cleanupCtx, opts.SSH, workspaceRoot, workspace, opts.StateDir, journalCheck{
		runID:           workerRunID(workspace),
		noRecordIsClean: !inspection.Journaled,
		progress:        progress,
		waiting: func() {
			progress.status("Another CertiStack operation holds the node's host lock; waiting to verify the inspection's journal.")
		},
	})
	cancel()
	if teardownErr != nil {
		workspaceRemovable = false
		progress.failure("The inspection's cleanup on node %s could not be verified: %s. On the node, run: %s", opts.NodeName, lastErrorLine(teardownErr), strings.Join(e.recoverCommand(opts.SSH, workspace, opts.StateDir), " "))
		return resultData, fmt.Errorf("%w: %w", ErrInspectionCleanupUnverified, teardownErr)
	}
	if inspection.Journaled {
		progress.status("Journal verified: the inspection released every backup map it made.")
	}
	return resultData, nil
}

// decodeInspection decodes a node-inspect answer. Output that is not one is
// an *unusableResultError, after which the journal is checked as for a
// worker that gave no answer.
func decodeInspection(data []byte, inspection *initplan.Inspection) error {
	if len(bytes.TrimSpace(data)) == 0 {
		return &unusableResultError{reason: "it is empty"}
	}
	if err := json.Unmarshal(data, inspection); err != nil {
		sample := data
		if len(sample) > maxUnusableResultSample {
			sample = sample[:maxUnusableResultSample]
		}
		return &unusableResultError{reason: fmt.Sprintf("%v; it begins %q", err, sample)}
	}
	return nil
}

// buildNodeInspectCommand is node-inspect's command line in workspace. Every
// value was checked (ValidateInspectRequest, validateNode) before it reaches
// the node.
func buildNodeInspectCommand(workspace string, opts RunOptions, req initplan.InspectRequest) []string {
	command := []string{
		path.Join(workspace, "certistack-node"), "node-inspect",
		"--node", opts.NodeName,
		"--scratch", opts.ScratchDir,
		"--state-dir", opts.StateDir,
		"--env-file", path.Join(workspace, "runtime.env"),
		"--run-id", workerRunID(workspace),
	}
	if req.Namespace != "" {
		command = append(command, "--namespace", req.Namespace)
	}
	for _, target := range req.Targets {
		command = append(command, "--target", strconv.Itoa(target.SourceVMID)+"="+target.Snapshot)
	}
	return command
}
