// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/nodeapi"
	"github.com/google/uuid"
)

// exitStatusError is a remote command's failure, as ssh reports it.
type exitStatusError struct {
	code   int
	detail string
}

func (e exitStatusError) Error() string {
	return fmt.Sprintf("ssh failed: exit status %d: %s", e.code, e.detail)
}
func (e exitStatusError) ExitCode() int { return e.code }

// answersNodeRun makes the fake answer the worker command with output.
func answersNodeRun(fake *fakeCommandRunner, output string) {
	fake.hook = func(name, joined string) ([]byte, error, bool) {
		if name == "ssh" && strings.Contains(joined, "node-run") {
			return []byte(output), nil, true
		}
		return nil, nil, false
	}
}

// A worker command that succeeds with output the controller cannot use
// (empty, truncated, not a result) does not lose the workspace, with the
// environment recovery needs: the journal is checked and recovered first, as
// after a lost connection, and the workspace stays when that cannot be done.
func TestUnusableWorkerResultIsReconciledBeforeTheWorkspaceGoes(t *testing.T) {
	for name, output := range map[string]string{
		"empty":                     ``,
		"only white space":          " \n",
		"truncated":                 `{"report":`,
		"neither report nor error":  `{}`,
		"null":                      `null`,
		"not JSON":                  `Connection to pve closed`,
		"a result and then garbage": `{"error":"x"} trailing`,
	} {
		t.Run(name, func(t *testing.T) {
			opts := completedWorkerTeardownOptions(t)
			fake := &fakeCommandRunner{journalPhase: "cleanup_failed"}
			answersNodeRun(fake, output)
			var progress bytes.Buffer
			opts.Writer = &progress
			result, err := (&Executor{runner: fake}).Run(context.Background(), opts)
			if err == nil || !strings.Contains(err.Error(), "node worker returned an unusable result") {
				t.Fatalf("err = %v, want an unusable-result error", err)
			}
			if result != nil {
				t.Fatalf("a report was returned for an unusable result: %+v", result)
			}
			commands := recordedCommands(fake.calls)
			if !strings.Contains(commands, "active.json") || fake.recoverCalls != 1 {
				t.Fatalf("the journal was not checked and recovered (recover ran %d times): %s", fake.recoverCalls, commands)
			}
			if fake.workspaceRemoveCalls != 1 {
				t.Fatalf("workspace removals = %d, want 1 once the journal is clean", fake.workspaceRemoveCalls)
			}
			if !strings.Contains(progress.String(), "no report was written") {
				t.Fatalf("progress lacks the notice:\n%s", progress.String())
			}
		})
	}
}

// The same output with a journal that cannot be recovered keeps the
// workspace, and the error still says the output was unusable.
func TestUnusableWorkerResultKeepsTheWorkspaceWhenTheJournalCannotBeRecovered(t *testing.T) {
	opts := completedWorkerTeardownOptions(t)
	fake := &fakeCommandRunner{journalPhase: "cleanup_failed", workerRecoveryError: errors.New("PVE recovery API unavailable")}
	answersNodeRun(fake, `{"report":`)
	_, err := (&Executor{runner: fake}).Run(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "automatic cleanup could not be verified") {
		t.Fatalf("err = %v, want the failed cleanup reported", err)
	}
	if fake.workspaceRemoveCalls != 0 {
		t.Fatalf("workspace removals = %d, want none while the journal is not clean", fake.workspaceRemoveCalls)
	}
	if !strings.Contains(recordedCommands(fake.calls), "'recover'") {
		t.Fatal("recovery was not attempted")
	}
}

// The output an operator sees of an unusable result is bounded.
func TestUnusableWorkerResultShowsBoundedOutput(t *testing.T) {
	_, err := decodeNodeResult([]byte(`{"report":` + strings.Repeat("x", 100000)))
	if err == nil || len(err.Error()) > 2*maxUnusableResultSample+200 {
		t.Fatalf("error of %d bytes for a 100 kB result: %v", len(err.Error()), err)
	}
	if _, err := decodeNodeResult([]byte(`{"report":{"report_id":"x"}}`)); err != nil {
		t.Fatalf("a result with a report was refused: %v", err)
	}
}

// A worker that says it refused the run, without evidence, is not
// believed on its word: its journal is checked before the workspace goes.
func TestWorkerRefusalWithoutEvidenceIsReconciledToo(t *testing.T) {
	opts := completedWorkerTeardownOptions(t)
	fake := &fakeCommandRunner{nodeResult: nodeapi.RunResult{Error: "acquire node worker host lock: another CertiStack operation holds the host lock"}, journalPhase: "cleaned"}
	_, err := (&Executor{runner: fake}).Run(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "node worker failed before producing evidence: acquire node worker host lock") {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(recordedCommands(fake.calls), "active.json") || fake.workspaceRemoveCalls != 1 {
		t.Fatalf("journal checked = %v, workspace removals = %d; want the journal checked and the workspace removed", strings.Contains(recordedCommands(fake.calls), "active.json"), fake.workspaceRemoveCalls)
	}
}

// The supervisor's status for a result it could not read is an
// error of its run, reconciled like a lost worker, never a success.
func TestSupervisorFailureToReadTheResultIsReconciled(t *testing.T) {
	opts := completedWorkerTeardownOptions(t)
	fake := &fakeCommandRunner{
		nodeRunError: exitStatusError{supervisorResultUnreadableStatus, "CertiStack could not read the node worker result /var/lib/certistack/workers/x/worker-result.json"},
		journalPhase: "cleanup_failed",
	}
	_, err := (&Executor{runner: fake}).Run(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "could not read the node worker result") {
		t.Fatalf("err = %v", err)
	}
	if fake.recoverCalls != 1 {
		t.Fatalf("recover ran %d times, want the journal checked and recovered once", fake.recoverCalls)
	}
}

// A supervisor that reports a worker it could not kill is not
// waited for another graceful stop of fifteen minutes: the controller checks
// once more, and when the worker is still there says so and recovers
// nothing, keeping the workspace.
func TestStuckWorkerIsReportedAndNothingIsRecovered(t *testing.T) {
	opts := completedWorkerTeardownOptions(t)
	fake := &fakeCommandRunner{
		nodeRunError:     exitStatusError{supervisorWorkerStuckStatus, "The node worker (PID 4242, state D, waiting in io_schedule) is still running 30 s after SIGKILL"},
		workerStopResult: "still-running",
		journalPhase:     "running",
	}
	var progress bytes.Buffer
	opts.Writer = &progress
	_, err := (&Executor{runner: fake}).Run(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "could not be stopped") || !errors.Is(err, errWorkerStillRunning) {
		t.Fatalf("err = %v, want the stuck worker reported", err)
	}
	if fake.recoverCalls != 0 || fake.workspaceRemoveCalls != 0 {
		t.Fatalf("recover ran %d times and the workspace was removed %d times; want neither while the worker runs", fake.recoverCalls, fake.workspaceRemoveCalls)
	}
	for _, want := range []string{"still running after SIGTERM and SIGKILL", "nothing is recovered while it runs", "reboot the node"} {
		if !strings.Contains(progress.String(), want) {
			t.Errorf("progress lacks %q:\n%s", want, progress.String())
		}
	}
	// The supervisor has waited out the grace period already.
	for _, call := range fake.calls {
		if joined := strings.Join(call.args, " "); strings.Contains(joined, "kill -TERM") && strings.Contains(joined, "$pinned_proc_dir/exe") {
			if !strings.Contains(joined, "remaining=0\n") {
				t.Fatalf("the controller waited a second graceful period: %s", joined)
			}
		}
	}
}

// A worker that ended after the supervisor gave up on it is recovered as any
// other, and the run still fails.
func TestStuckWorkerThatHasEndedIsRecovered(t *testing.T) {
	opts := completedWorkerTeardownOptions(t)
	fake := &fakeCommandRunner{
		nodeRunError:     exitStatusError{supervisorWorkerStuckStatus, "still running"},
		workerStopResult: "gone",
		journalPhase:     "cleanup_failed",
	}
	_, err := (&Executor{runner: fake}).Run(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "did not end after SIGKILL") {
		t.Fatalf("err = %v", err)
	}
	if fake.recoverCalls != 1 || fake.workspaceRemoveCalls != 1 {
		t.Fatalf("recover ran %d times, workspace removed %d times; want each once", fake.recoverCalls, fake.workspaceRemoveCalls)
	}
}

// A run that returned no evidence and left no record on the node is reported as
// having recorded no resource, which is what was found, and not as a journal
// reconciled.
func TestInterruptedRunWithNoRecordSaysSoInsteadOfReconciled(t *testing.T) {
	for name, fake := range map[string]*fakeCommandRunner{
		"no journal":         {nodeRunError: errors.New("ssh session ended"), journalState: "absent"},
		"another run's":      {nodeRunError: errors.New("ssh session ended"), journalReads: []string{"run-" + uuid.NewString() + " running"}},
		"an own journal too": {nodeRunError: errors.New("ssh session ended"), journalPhase: "cleaned"},
	} {
		opts := completedWorkerTeardownOptions(t)
		var progress bytes.Buffer
		opts.Writer = &progress
		if _, err := (&Executor{runner: fake}).Run(context.Background(), opts); err == nil {
			t.Fatalf("%s: the run succeeded", name)
		}
		noRecord := strings.Contains(progress.String(), "the node's journal holds no record of this run, so it had created no temporary resources")
		if want := name != "an own journal too"; noRecord != want {
			t.Errorf("%s: says no record = %v, want %v:\n%s", name, noRecord, want, progress.String())
		}
	}
}
