// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/internal/journal"
	"github.com/google/uuid"
)

func fastHostLockRetry(t *testing.T) {
	t.Helper()
	initial, maximum := hostLockRetryInitial, hostLockRetryMax
	hostLockRetryInitial, hostLockRetryMax = time.Millisecond, 4*time.Millisecond
	t.Cleanup(func() { hostLockRetryInitial, hostLockRetryMax = initial, maximum })
}

// A clean run ended "cleanup unverified" (exit 2, workspace kept)
// because the controller's post-run check ran "<worker> recover", which
// needs the host lock, just as another run on the node took it.
//
// What the check accepts as proof names this run: its own journal cleaned, or
// the transition record a later run kept of it. A journal that is missing,
// names no run or names another run proves nothing, whatever its phase.
func TestCompletedWorkerCheckDoesNotNeedTheHostLock(t *testing.T) {
	fastHostLockRetry(t)
	workspaceRoot := "/var/lib/certistack/workers"
	workspace := workspaceRoot + "/" + uuid.NewString()
	ours := workerRunID(workspace)
	later := "run-" + uuid.NewString()
	lockHeld := errors.New("ssh failed: exit status 1: cannot acquire host lock for recovery: " + journal.LockHeldMessage + ": resource temporarily unavailable")
	for _, tc := range []struct {
		name         string
		fake         *fakeCommandRunner
		wantRecovers int
		wantErr      string
	}{
		{"own journal cleaned", &fakeCommandRunner{journalReads: []string{ours + " cleaned"}}, 0, ""},
		// A run replaces only a clean journal, and keeps a record of it
		// when it does.
		{"a later run's journal, with our transition", &fakeCommandRunner{journalReads: []string{later + " running"}, transitions: []string{ours}}, 0, ""},
		{"own journal recovered", &fakeCommandRunner{journalReads: []string{ours + " cleanup_failed"}}, 1, ""},
		// The lock holder recovers our journal before it starts and then
		// writes its own; the check reads the journal again after waiting.
		{"lock holder takes over", &fakeCommandRunner{
			journalReads:  []string{ours + " cleanup_failed", later + " running"},
			transitions:   []string{ours},
			recoverErrors: []error{lockHeld},
		}, 1, ""},
		{"lock released", &fakeCommandRunner{
			journalReads:  []string{ours + " cleanup_failed"},
			recoverErrors: []error{lockHeld, lockHeld, nil},
		}, 3, ""},
		{"recovery fails", &fakeCommandRunner{
			journalReads:  []string{ours + " cleanup_failed"},
			recoverErrors: []error{errors.New("ssh failed: exit status 1: destroy VM 217401: permission denied")},
		}, 1, "reconcile completed node-worker journal"},
		{"own journal, workspace gone", &fakeCommandRunner{journalReads: []string{ours + " running"}, workspaceState: "absent"}, 0, "workspace is absent"},
		// A missing journal is no proof, whatever the worker says.
		{"no journal", &fakeCommandRunner{journalState: "absent"}, 0, "the journal is missing"},
		// Neither is another run's journal, in any phase.
		{"a later run's journal, without our transition", &fakeCommandRunner{journalReads: []string{later + " running"}}, 0, "the journal names another run (" + later + ")"},
		{"another run's clean journal", &fakeCommandRunner{journalReads: []string{later + " cleaned"}}, 0, "the journal names another run"},
		{"another run's failed journal", &fakeCommandRunner{journalReads: []string{later + " cleanup_failed"}}, 0, "the journal names another run"},
		{"a clean journal that names no run", &fakeCommandRunner{journalReads: []string{" cleaned"}}, 0, "the journal names no run"},
		// Recovery that acts on a journal that is no longer ours verifies
		// nothing of ours.
		{"recovery succeeded on a journal that is not ours", &fakeCommandRunner{
			journalReads:  []string{ours + " cleanup_failed", later + " cleanup_failed"},
			recoverErrors: []error{nil},
		}, 1, "recovery reported success, but afterwards the journal names another run"},
	} {
		fake := tc.fake
		err := (&Executor{runner: fake}).reconcileCompletedWorker(context.Background(), SSHConfig{Host: "pve.example", User: "root"}, workspaceRoot, workspace, "/var/lib/certistack", journalCheck{runID: ours})
		if tc.wantErr == "" && err != nil || tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
			t.Fatalf("%s: err = %v, want %q", tc.name, err, tc.wantErr)
		}
		if fake.recoverCalls != tc.wantRecovers {
			t.Fatalf("%s: recover ran %d times, want %d", tc.name, fake.recoverCalls, tc.wantRecovers)
		}
		var unproven *journalUnprovenError
		wantUnproven := strings.Contains(tc.wantErr, "the journal") || strings.Contains(tc.wantErr, "recovery reported success")
		if errors.As(err, &unproven) != wantUnproven {
			t.Fatalf("%s: err = %v, want unproven = %v", tc.name, err, wantUnproven)
		}
	}
}

// What the node holds for a run must be that run's own record: a
// transition file that names another run, or is not one, is no proof.
func TestATransitionRecordThatIsNotOursProvesNothing(t *testing.T) {
	workspaceRoot := "/var/lib/certistack/workers"
	workspace := workspaceRoot + "/" + uuid.NewString()
	ours := workerRunID(workspace)
	for name, content := range map[string]string{
		"another run's":   `{"run_id":"run-` + uuid.NewString() + `","phase":"cleaned","superseded_by":"run-x"}`,
		"not clean":       `{"run_id":"` + ours + `","phase":"cleanup_failed","superseded_by":"run-x"}`,
		"supersedes none": `{"run_id":"` + ours + `","phase":"cleaned"}`,
		"not JSON":        `cleaned`,
		"empty":           ``,
	} {
		t.Run(name, func(t *testing.T) {
			fake := &fakeCommandRunner{journalReads: []string{"run-" + uuid.NewString() + " running"}}
			fake.hook = func(name, joined string) ([]byte, error, bool) {
				switch {
				case strings.Contains(joined, "/runs/run-") && strings.Contains(joined, "if [ -e"):
					return []byte("present\n"), nil, true
				case strings.Contains(joined, "/runs/run-") && strings.Contains(joined, "'/usr/bin/cat'"):
					return []byte(content), nil, true
				}
				return nil, nil, false
			}
			err := (&Executor{runner: fake}).reconcileCompletedWorker(context.Background(), SSHConfig{Host: "pve.example", User: "root"}, workspaceRoot, workspace, "/var/lib/certistack", journalCheck{runID: ours})
			var unproven *journalUnprovenError
			if !errors.As(err, &unproven) || !strings.Contains(err.Error(), "not a valid record that it was clean") {
				t.Fatalf("err = %v, want the record refused", err)
			}
		})
	}
}

// A run that returned no evidence, as after a lost connection or a
// refusal, has nothing that signs its cleanup: a journal with no record of
// it means it recorded no resource, and is accepted as that, and told apart.
func TestNoRecordOfARunThatReturnedNoEvidenceIsNotAFailure(t *testing.T) {
	workspaceRoot := "/var/lib/certistack/workers"
	workspace := workspaceRoot + "/" + uuid.NewString()
	for name, fake := range map[string]*fakeCommandRunner{
		"no journal":         {journalState: "absent"},
		"another run's":      {journalReads: []string{"run-" + uuid.NewString() + " running"}},
		"a record of no run": {journalReads: []string{" cleaned"}},
	} {
		var outcome journalOutcome
		err := (&Executor{runner: fake}).reconcileCompletedWorker(context.Background(), SSHConfig{Host: "pve.example", User: "root"}, workspaceRoot, workspace, "/var/lib/certistack", journalCheck{runID: workerRunID(workspace), noRecordIsClean: true, outcome: &outcome})
		if err != nil || !outcome.noRecord || outcome.ownCleaned || fake.recoverCalls != 0 {
			t.Fatalf("%s: err = %v, outcome %+v, recover ran %d times", name, err, outcome, fake.recoverCalls)
		}
	}
}

func TestCompletedWorkerCheckGivesUpWhenTheLockStaysHeld(t *testing.T) {
	fastHostLockRetry(t)
	workspace := "/var/lib/certistack/workers/" + uuid.NewString()
	fake := &fakeCommandRunner{
		journalReads:        []string{workerRunID(workspace) + " cleanup_failed"},
		workerRecoveryError: errors.New("ssh failed: exit status 1: " + journal.LockHeldMessage),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	waits := 0
	err := (&Executor{runner: fake}).reconcileCompletedWorker(ctx, SSHConfig{Host: "pve.example", User: "root"}, "/var/lib/certistack/workers", workspace, "/var/lib/certistack", journalCheck{
		runID: workerRunID(workspace), waiting: func() { waits++ },
	})
	if err == nil || !strings.Contains(err.Error(), "still holds the host lock") || fake.recoverCalls < 2 {
		t.Fatalf("err = %v after %d recover attempts, want a bounded wait that reports the lock", err, fake.recoverCalls)
	}
	if waits != 1 {
		t.Fatalf("the wait was reported %d times, want once", waits)
	}
}

// The worker records the controller's run ID, and a sudo account probes the
// root-only state directory with its privilege prefix.
func TestWorkerRunIDAndPrivilegedProbes(t *testing.T) {
	workspace := "/var/lib/certistack/workers/" + uuid.NewString()
	command := strings.Join(buildNodeRunCommand(workspace, RunOptions{NodeName: "pve1", ScratchDir: "/s", StateDir: "/var/lib/certistack"}), " ")
	if !strings.Contains(command, "--run-id run-"+strings.TrimPrefix(workspace, "/var/lib/certistack/workers/")) {
		t.Fatalf("node-run command lacks the run ID: %s", command)
	}
	fake := &fakeCommandRunner{journalReads: []string{"run-" + uuid.NewString() + " running"}, transitions: []string{workerRunID(workspace)}}
	if err := (&Executor{runner: fake}).reconcileCompletedWorker(context.Background(), SSHConfig{Host: "pve.example", User: "certistack", UseSudo: true}, "/var/lib/certistack/workers", workspace, "/var/lib/certistack", journalCheck{runID: workerRunID(workspace)}); err != nil {
		t.Fatal(err)
	}
	probed := 0
	for _, call := range fake.calls {
		joined := strings.Join(call.args, " ")
		if strings.Contains(joined, "if [ -e") || strings.Contains(joined, "'/usr/bin/cat'") {
			probed++
			if !strings.Contains(joined, "'/usr/bin/sudo' '-n'") {
				t.Fatalf("root-only state probed without sudo: %s", joined)
			}
		}
	}
	if probed < 4 {
		t.Fatalf("only %d probes of the journal and the transition record", probed)
	}
}
