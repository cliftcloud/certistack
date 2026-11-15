// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/nodeapi"
)

// A stop request in a run's first second (systemctl stop right after start)
// killed the ssh child of the step that was running, and the run ended with
// that child's error, "determine PVE node architecture: ... ssh failed: signal:
// killed": exit status 2, an SSH failure, and not the interruption it was
// (130). Every step before the worker starts on the node now ends, once the
// run's context has ended, as the interruption, whatever its child reported;
// what the step left on the node is still removed by the run's cleanup. A
// step that fails while the context is live keeps its own error.
func TestAStopBeforeTheWorkerStartsIsTheInterruption(t *testing.T) {
	killed := errors.New("SSH command on pve.example: ssh failed: signal: killed")
	steps := []struct {
		name    string
		matches func(name, joined string) bool
		staged  bool // the staging directory may exist, so the cleanup removes it
		stops   bool // the step's own failure stops the run (a clock that cannot be read is only warned about)
	}{
		{"reading the node's architecture", func(name, joined string) bool {
			return name == "ssh" && strings.Contains(joined, "'/usr/bin/uname' '-m'")
		}, false, true},
		{"reading the node's clock", func(name, joined string) bool {
			return name == "ssh" && strings.Contains(joined, "'/usr/bin/date' '-u' '+%s'")
		}, false, false},
		{"creating the staging directory", func(name, joined string) bool {
			return name == "ssh" && strings.Contains(joined, "refuse()") && strings.Contains(joined, "/tmp/certistack-controller-")
		}, true, true},
		{"copying the worker to the node", func(name, joined string) bool { return name == "scp" }, true, true},
		{"installing the workspace", func(name, joined string) bool {
			return name == "ssh" && strings.Contains(joined, "refuse()") && strings.Contains(joined, "/workers/")
		}, true, true},
		{"creating the worker's lease", func(name, joined string) bool {
			return name == "ssh" && strings.Contains(joined, "controller.lease") && strings.Contains(joined, "'/usr/bin/install'")
		}, true, true},
	}
	for _, step := range steps {
		t.Run(step.name, func(t *testing.T) {
			for _, interrupted := range []bool{true, false} {
				opts := completedWorkerTeardownOptions(t)
				fake := &fakeCommandRunner{nodeResult: nodeapi.RunResult{Report: workerReportFor(t, opts)}, journalPhase: "cleaned"}
				ctx, cancel := context.WithCancel(context.Background())
				failed := false
				fake.hook = func(name, joined string) ([]byte, error, bool) {
					if failed || !step.matches(name, joined) {
						return nil, nil, false
					}
					failed = true
					if interrupted {
						cancel() // the stop request; it kills the step's ssh child
					}
					return nil, killed, true
				}
				_, err := (&Executor{runner: fake}).Run(ctx, opts)
				cancel()
				if !failed {
					t.Fatal("the run never reached the step")
				}
				if !interrupted {
					if errors.Is(err, context.Canceled) || step.stops && (err == nil || !strings.Contains(err.Error(), "signal: killed")) {
						t.Errorf("the step failed with the run's context live: err = %v; want the step's own failure, not an interruption", err)
					}
					continue
				}
				if err != context.Canceled {
					t.Errorf("err = %v; want the interruption alone (context.Canceled), which the CLI reports as an interruption with exit status 130", err)
				}
				if command, started := startedWorker(fake); started {
					t.Errorf("the worker was started after the interruption: %s", command)
				}
				if step.staged && !removedStaging(fake) {
					t.Error("the staging directory the step may have left was not removed")
				}
			}
		})
	}
}

// startedWorker reports whether the run started its node worker.
func startedWorker(fake *fakeCommandRunner) (string, bool) {
	for _, call := range fake.calls {
		joined := call.name + " " + strings.Join(call.args, " ")
		if strings.Contains(joined, "node-run") {
			return joined, true
		}
	}
	return "", false
}

// removedStaging reports whether the run removed its SSH staging directory.
func removedStaging(fake *fakeCommandRunner) bool {
	for _, call := range fake.calls {
		joined := strings.Join(call.args, " ")
		if call.name == "ssh" && strings.Contains(joined, "'/usr/bin/rm' '-rf' '/tmp/certistack-controller-") {
			return true
		}
	}
	return false
}

// The earliest point: the stop request came before Run reached the node at
// all, so the first ssh child fails at once.
func TestAStopBeforeTheRunReachesTheNodeIsTheInterruption(t *testing.T) {
	opts := completedWorkerTeardownOptions(t)
	fake := &fakeCommandRunner{nodeResult: nodeapi.RunResult{Report: workerReportFor(t, opts)}, journalPhase: "cleaned"}
	fake.hook = func(name, joined string) ([]byte, error, bool) {
		return nil, errors.New("SSH command on pve.example: ssh failed: signal: killed"), true
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := (&Executor{runner: fake}).Run(ctx, opts)
	if err != context.Canceled {
		t.Errorf("err = %v; want the interruption alone (context.Canceled)", err)
	}
	if command, started := startedWorker(fake); started {
		t.Errorf("the worker was started after the interruption: %s", command)
	}
}
