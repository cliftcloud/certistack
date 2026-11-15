// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

// The controller removed the workspace of a run whose recovery log
// the node had said it could not keep, and with it worker-progress.log, the
// log's only other copy: the failed-worker branch exited with the worker's
// own status, and no status of the supervisor was read. The workspace stays,
// with only its credentials removed, whatever the worker's status.
func TestControllerNeverRemovesTheOnlyCopyOfARecoveryLogTheNodeCouldNotKeep(t *testing.T) {
	const notice = recoveryLogNotKeptMessage + " /var/lib/certistack/logs/x.log; the workspace's worker-progress.log holds the only other copy"
	for name, tc := range map[string]struct {
		status int
		detail string
	}{
		"the supervisor's own status":         {supervisorLogNotKeptStatus, notice},
		"its status alone":                    {supervisorLogNotKeptStatus, "no detail"},
		"the worker's status with the notice": {2, notice},
		"a signal death with the notice":      {137, notice},
	} {
		t.Run(name, func(t *testing.T) {
			opts := completedWorkerTeardownOptions(t)
			var progress bytes.Buffer
			opts.Writer = &progress
			fake := &fakeCommandRunner{nodeRunError: exitStatusError{tc.status, tc.detail}, workerStopResult: "gone", journalPhase: "cleaned"}
			_, err := (&Executor{runner: fake}).Run(context.Background(), opts)
			if err == nil {
				t.Fatal("the run succeeded")
			}
			if fake.workspaceRemoveCalls != 0 {
				t.Fatalf("the workspace was removed %d times: %s", fake.workspaceRemoveCalls, recordedCommands(fake.calls))
			}
			commands := recordedCommands(fake.calls)
			for _, want := range []string{"credentials-removed.txt", "runtime.env", "certistack-node"} {
				if !strings.Contains(commands, want) {
					t.Errorf("the credentials were not removed (%q missing): %s", want, commands)
				}
			}
			if strings.Contains(commands, "'/usr/bin/rm' '-rf' '/var/lib/certistack/workers/") {
				t.Error("the workspace was deleted")
			}
			for _, want := range []string{"could not keep this run's recovery log", "worker-progress.log", "removing only the workspace's credentials"} {
				if !strings.Contains(progress.String(), want) {
					t.Errorf("progress lacks %q:\n%s", want, progress.String())
				}
			}
			if errors.Is(err, ErrControllerMaterialCleanupUnverified) {
				t.Errorf("a deliberately kept, scrubbed workspace was reported as unverified material: %v", err)
			}
		})
	}
	// Without the notice the worker's own failure removes the workspace, as
	// before.
	opts := completedWorkerTeardownOptions(t)
	fake := &fakeCommandRunner{nodeRunError: exitStatusError{2, "worker failed"}, workerStopResult: "gone", journalPhase: "cleaned"}
	if _, err := (&Executor{runner: fake}).Run(context.Background(), opts); err == nil || fake.workspaceRemoveCalls != 1 {
		t.Fatalf("err = %v, removals = %d; want the workspace removed", err, fake.workspaceRemoveCalls)
	}
}

// The controller keeps the workspace after an interruption too, and when the
// scrub itself fails says the material is unverified.
func TestKeptWorkspaceScrubFailureIsUnverifiedMaterial(t *testing.T) {
	opts := completedWorkerTeardownOptions(t)
	fake := &fakeCommandRunner{nodeRunError: exitStatusError{supervisorLogNotKeptStatus, "x"}, workerStopResult: "gone", journalPhase: "cleaned"}
	fake.hook = func(name, joined string) ([]byte, error, bool) {
		if strings.Contains(joined, "for file in") {
			return nil, errors.New("rm failed"), true
		}
		return nil, nil, false
	}
	_, err := (&Executor{runner: fake}).Run(context.Background(), opts)
	if !errors.Is(err, ErrControllerMaterialCleanupUnverified) || fake.workspaceRemoveCalls != 0 {
		t.Fatalf("err = %v, removals = %d", err, fake.workspaceRemoveCalls)
	}
}
