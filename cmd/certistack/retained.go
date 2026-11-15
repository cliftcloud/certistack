// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
)

// retainedWorkspaceIdle is how long a sibling workspace's controller must
// have been silent before its credentials are removed. A live controller
// renews its lease within the 90 s it is valid, and a workspace still being
// staged, before it has a lease, is seconds old.
const retainedWorkspaceIdle = 15 * time.Minute

// retainedSecrets are the workspace files that carry credentials: the
// worker's PVE and PBS environment, the PBS encryption key, and the worker
// binary that would use them.
var retainedSecrets = []string{"runtime.env", "pbs-encryption.key", "certistack-node"}

// retainedNoteName records, in a scrubbed workspace, when and why its
// credentials were removed.
const retainedNoteName = "credentials-removed.txt"

// scrubRetainedWorkspaces removes the credentials from worker workspaces a
// controller kept because it could not verify their cleanup. The workspace
// existed so the journal could be recovered. Call it only under the host
// lock with the node's journal clean: then no other worker runs, and no
// recovery needs those credentials again. Logs, results and reports stay
// as evidence. It returns the workspaces it scrubbed.
func scrubRetainedWorkspaces(root, own, runID string, now time.Time) ([]string, error) {
	idle, err := idleRetainedWorkspaces(root, own, now)
	if err != nil {
		return nil, err
	}
	var scrubbed, failures []string
	for _, workspace := range idle {
		dir, last, name := workspace.dir, workspace.last, filepath.Base(workspace.dir)
		removed, err := removeSecrets(dir)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", name, err))
			continue
		}
		if len(removed) == 0 {
			continue
		}
		note := fmt.Sprintf("Credentials removed (%v) by node worker run %s at %s: the node's journal was clean and this workspace's controller had been silent since %s. Logs and results are kept.\n",
			removed, runID, now.UTC().Format(time.RFC3339), last.UTC().Format(time.RFC3339))
		if err := os.WriteFile(filepath.Join(dir, retainedNoteName), []byte(note), 0o600); err != nil {
			failures = append(failures, fmt.Sprintf("%s: note: %v", name, err))
		}
		scrubbed = append(scrubbed, dir)
	}
	if len(failures) > 0 {
		return scrubbed, fmt.Errorf("remove retained workspace credentials: %v", failures)
	}
	return scrubbed, nil
}

// idleWorkspace is a sibling workspace whose controller has been silent.
type idleWorkspace struct {
	dir  string
	last time.Time
}

// idleRetainedWorkspaces are root's worker workspaces, other than own, whose
// controller has been silent for retainedWorkspaceIdle and that still hold
// a credential file: those scrubRetainedWorkspaces cleans, and the plan
// command lists.
func idleRetainedWorkspaces(root, own string, now time.Time) ([]idleWorkspace, error) {
	entries, err := os.ReadDir(root)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	own = filepath.Clean(own)
	var idle []idleWorkspace
	for _, entry := range entries {
		dir := filepath.Join(root, entry.Name())
		// Only real directories named as the controller names them; never a
		// symlink, which could point anywhere.
		if !entry.IsDir() || entry.Type()&fs.ModeSymlink != 0 || uuid.Validate(entry.Name()) != nil || dir == own {
			continue
		}
		last, err := lastActivity(dir)
		if err != nil || now.Sub(last) < retainedWorkspaceIdle || !holdsSecrets(dir) {
			continue
		}
		idle = append(idle, idleWorkspace{dir: dir, last: last})
	}
	return idle, nil
}

// holdsSecrets reports whether dir still has a credential file.
func holdsSecrets(dir string) bool {
	for _, name := range retainedSecrets {
		if _, err := os.Lstat(filepath.Join(dir, name)); err == nil {
			return true
		}
	}
	return false
}

// lastActivity is the newest of a workspace's own, its lease's and its
// environment's modification times.
func lastActivity(dir string) (time.Time, error) {
	info, err := os.Lstat(dir)
	if err != nil {
		return time.Time{}, err
	}
	last := info.ModTime()
	for _, name := range []string{"controller.lease", "runtime.env"} {
		if info, err := os.Lstat(filepath.Join(dir, name)); err == nil && info.ModTime().After(last) {
			last = info.ModTime()
		}
	}
	return last, nil
}

// removeSecrets deletes dir's credential files that are regular files, and
// returns the names it deleted.
func removeSecrets(dir string) ([]string, error) {
	var removed []string
	for _, name := range retainedSecrets {
		p := filepath.Join(dir, name)
		info, err := os.Lstat(p)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return removed, err
		}
		if !info.Mode().IsRegular() {
			return removed, fmt.Errorf("%s is not a regular file", name)
		}
		if err := os.Remove(p); err != nil {
			return removed, err
		}
		removed = append(removed, name)
	}
	return removed, nil
}
