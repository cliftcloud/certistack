// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"context"
	"errors"
	"fmt"
	"path"

	"github.com/google/uuid"
)

// readLeaseWatchTick is how often a read-only workspace's lease watch looks at
// its lease, in seconds.
const readLeaseWatchTick = 5

// ReadWorkspaceLeaseSeconds is how long a read-only workspace's lease may go
// unrenewed before the node removes the workspace itself; the command line says
// so to an operator who abandons the removal.
const ReadWorkspaceLeaseSeconds = workerLeaseDurationSeconds

// readLeaseWatchUnitName is the transient service that watches a read-only
// workspace's lease.
func readLeaseWatchUnitName(workspace string) string {
	return "certistack-read-watch-" + path.Base(workspace)
}

// readLeaseWatchScript is the watch on the node over a read-only workspace (a
// plan's or a discovery's): it ends as soon as the workspace is gone, which a
// live controller sees to, and removes the workspace when the controller's
// lease has not been renewed for leaseSeconds, measured on the boot clock like
// a run's lease. Such a workspace holds the credentials of the read and
// nothing a recovery could need (a read creates nothing and keeps no journal),
// so the whole workspace goes, and the credentials with it, without any other
// run on the node having to find it abandoned.
//
// variables are workspaceShellVariables, whose names workerShellFunctions
// (boot_now, lease_stamp) share with a run's supervisor and lease watch.
func readLeaseWatchScript(variables string, leaseSeconds, tick int) string {
	return fmt.Sprintf(`umask 077
%s
%s
lease_seconds=%d
tick=%d
%s
now=0
boot_now
renewed_at=$now
lease_stamp
last_stamp=$stamp
while [ -d "$workspace" ]; do
  boot_now
  lease_stamp
  # Any change of the lease's modification time is a renewal, whatever time it
  # names; its age is counted on the boot clock from when the change was seen.
  if [ -n "$stamp" ] && [ "$stamp" != "$last_stamp" ]; then
    last_stamp=$stamp
    renewed_at=$now
  fi
  if [ "$((now - renewed_at))" -gt "$lease_seconds" ]; then
    /usr/bin/rm -rf -- "$workspace"
    exit 0
  fi
  /bin/sleep "$tick"
done
`, launcherCanary, variables, leaseSeconds, tick, workerShellFunctions)
}

// readLeaseWatchCommand starts a read-only workspace's lease watch as a
// transient service of its own on the node, which the controller's session
// does not outlive and the watch does not wait for. It is nil for a workspace
// that is not exactly a worker workspace.
func (e *Executor) readLeaseWatchCommand(cfg SSHConfig, stateDir, workspaceRoot, workspace, leasePath string) []string {
	if !safeRemoteAbsolutePath(workspaceRoot) || !safeRemoteAbsolutePath(stateDir) || path.Dir(workspace) != workspaceRoot || uuid.Validate(path.Base(workspace)) != nil || path.Dir(leasePath) != workspace {
		return nil
	}
	variables := workspaceShellVariables(leasePath, path.Join(workspace, "certistack-node"), stateDir, path.Join(workspace, "runtime.env"), path.Join(workspace, "worker-progress.log"), workspace)
	script := readLeaseWatchScript(variables, workerLeaseDurationSeconds, readLeaseWatchTick)
	command := []string{"/usr/bin/systemd-run", "--unit", systemdWord(readLeaseWatchUnitName(workspace)), "--description=CertiStack read lease watch", "--collect", "--quiet"}
	for _, word := range []string{"/bin/sh", "-c", script} {
		command = append(command, systemdWord(word))
	}
	return append(e.privilegePrefix(cfg), command...)
}

// startReadLeaseWatch puts a read-only workspace under its lease watch. A
// workspace that cannot be watched is not read from: the credentials in it
// would have no end but the controller's.
func (e *Executor) startReadLeaseWatch(ctx context.Context, cfg SSHConfig, stateDir, workspaceRoot, workspace, leasePath string) error {
	command := e.readLeaseWatchCommand(cfg, stateDir, workspaceRoot, workspace, leasePath)
	if command == nil {
		return errors.New("refusing to watch a lease outside an exact worker workspace")
	}
	if _, err := e.remoteSetupCommand(ctx, cfg, command); err != nil {
		return fmt.Errorf("start the lease watch of the temporary node workspace: %w", err)
	}
	return nil
}
