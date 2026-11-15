// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package telemetry

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Every change of the state file is a read, a decision and a write: a run
// reads whether telemetry is on and records itself, an opt-out reads the
// identity it forgets and writes the no, a reset deletes. Atomic replacement
// keeps the file from being torn but not these steps from interleaving, so a
// run that read the state before an opt-out wrote the old, enabled state back
// over it. The steps are serialized by an exclusive lock on a file beside the
// state file (flock, on the platforms that have it), held for the read and the
// write and never across the network.
var lockWait = 5 * time.Second

const lockPoll = 10 * time.Millisecond

// lockSuffix names the lock file beside the state file. It holds nothing, is
// never deleted (a lock file that goes while others hold it would split them),
// and is left by reset.
const lockSuffix = ".lock"

// lockState takes the exclusive lock beside path and returns what releases it.
// It waits up to lockWait for another process that holds it and then says so,
// so that a stuck holder costs a command a few seconds and not its answer.
// Where the lock cannot be had at all (no lock file can be made, or the file
// system or platform has no flock) it is best effort: the change goes ahead
// unserialized, because an opt-out must work on a machine that cannot lock.
func lockState(path string) (unlock func(), err error) {
	return lockStateContext(context.Background(), path)
}

// lockStateContext is lockState that also stops waiting when ctx ends, so a
// caller with a budget (the report at the end of a run) never waits past it.
func lockStateContext(ctx context.Context, path string) (unlock func(), err error) {
	noLock := func() {}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return noLock, nil
	}
	lockPath := path + lockSuffix
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return noLock, nil
	}
	deadline := time.Now().Add(lockWait)
	for {
		held, err := tryLock(f)
		if err != nil {
			_ = f.Close()
			return noLock, nil
		}
		if held {
			return func() {
				releaseLock(f)
				_ = f.Close()
			}, nil
		}
		if !time.Now().Before(deadline) || ctx.Err() != nil {
			_ = f.Close()
			return nil, fmt.Errorf("another CertiStack process is changing the telemetry state (%s is locked); try again in a moment", lockPath)
		}
		select {
		case <-ctx.Done():
		case <-time.After(lockPoll):
		}
	}
}
