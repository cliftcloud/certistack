// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/internal/preflight"
	accept "github.com/cliftcloud/certistack/pkg/acceptance"
	"github.com/cliftcloud/certistack/pkg/config"
)

// heldPVE is the reporter's loopback PVE: a valid version reply, privilege
// replies up to a point, and then one request held until its client gives up.
type heldPVE struct {
	*httptest.Server
	mu         sync.Mutex
	privileges int
	held       chan struct{}
	gone       chan string
	once       sync.Once
}

func newHeldPVE(t *testing.T, holdVersion bool, answerBefore int) *heldPVE {
	t.Helper()
	grant := map[string]int{"VM.Allocate": 1, "VM.Audit": 1, "VM.PowerMgmt": 1, "VM.Console": 1, "VM.Config.Disk": 1, "VM.Config.CPU": 1, "VM.Config.Memory": 1, "VM.Config.Network": 1, "VM.Config.Options": 1, "VM.Config.HWType": 1, "VM.Config.CDROM": 1, "SDN.Allocate": 1, "SDN.Audit": 1, "SDN.Use": 1, "Sys.Audit": 1, "Datastore.AllocateSpace": 1, "Datastore.Audit": 1}
	h := &heldPVE{held: make(chan struct{}), gone: make(chan string, 1)}
	hold := func(r *http.Request) {
		h.once.Do(func() { close(h.held) })
		<-r.Context().Done()
		select {
		case h.gone <- r.Context().Err().Error():
		default:
		}
	}
	h.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/version"):
			if holdVersion {
				hold(r)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"version": "8.2.0"}})
		case strings.HasSuffix(r.URL.Path, "/access/permissions"):
			h.mu.Lock()
			n := h.privileges
			h.privileges++
			h.mu.Unlock()
			if n == answerBefore {
				hold(r)
				return
			}
			path := r.URL.Query().Get("path")
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{path: grant}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(h.Close)
	return h
}

// `doctor` passed the command's context to its later checks and not to
// the PVE preflight, so after the first interrupt it printed that it was
// waiting, after the second that it was abandoning cleanup, and went on for as
// long as the PVE requests' own time limits (12.9 seconds in the original
// report). The reporter's sequence through the real signal contexts and the
// real command: a valid version reply, a privilege request held in flight,
// SIGINT, SIGINT 250 ms later. The command now ends at the first interrupt,
// with the interrupted status and no verdict; the version request and a late
// privilege request are the other places it waited.
func TestDoctorEndsAtTheFirstInterruptWhereverItWaitsOnPVE(t *testing.T) {
	for name, tc := range map[string]struct {
		holdVersion  bool
		answerBefore int
	}{
		"the version request":                {true, 0},
		"the first privilege request":        {false, 0},
		"a late privilege request (the 5th)": {false, 4},
	} {
		t.Run(name, func(t *testing.T) {
			clearControllerEnvironment(t)
			server := newHeldPVE(t, tc.holdVersion, tc.answerBefore)
			t.Setenv("PVE_URL", server.URL)
			t.Setenv("PVE_TOKEN_ID", "audit@pve!doctor")
			t.Setenv("PVE_TOKEN_SECRET", "AUDIT-ONLY-NOT-A-CREDENTIAL")
			// No program for the tool lookups to find: the reporter's
			// deterministic final state.
			t.Setenv("PATH", t.TempDir())
			root := t.TempDir()
			plan := writeValidationFixture(t, root, "plan.yaml")
			state := filepath.Join(root, "state")
			if err := os.Mkdir(state, 0o700); err != nil {
				t.Fatal(err)
			}

			signals := make(chan os.Signal, 2)
			var messages, stdout bytes.Buffer
			ctx, cleanupCtx, stop := newSignalContexts(signals, &messages)
			defer stop()
			cmd := newRootCmd(cleanupCtx)
			cmd.SetOut(&stdout)
			cmd.SetErr(io.Discard)
			cmd.SetArgs([]string{"doctor", "--plan", plan, "--scratch", filepath.Join(root, "scratch"), "--state-dir", state})
			done := make(chan error, 1)
			go func() { done <- cmd.ExecuteContext(ctx) }()

			select {
			case <-server.held:
			case err := <-done:
				t.Fatalf("doctor ended before the request it was to be interrupted in: %v\n%s", err, stdout.String())
			case <-time.After(10 * time.Second):
				t.Fatal("the PVE request that is held never arrived")
			}
			first := time.Now()
			signals <- os.Interrupt
			time.Sleep(250 * time.Millisecond)
			signals <- os.Interrupt

			var err error
			select {
			case err = <-done:
			case <-time.After(8 * time.Second):
				t.Fatal("doctor was still waiting for the PVE API 8 seconds after the first interrupt")
			}
			if elapsed := time.Since(first); elapsed > 4*time.Second {
				t.Errorf("doctor took %v to end after the first interrupt; the requests' own limits are 5 and 10 seconds", elapsed)
			}
			if exitCodeForError(err) != exitCodeInterrupted {
				t.Errorf("exit %d (err %v), want the interrupted status %d", exitCodeForError(err), err, exitCodeInterrupted)
			}
			if err == nil || !strings.Contains(err.Error(), "interrupted before it reached a verdict") {
				t.Errorf("err = %v", err)
			}
			if strings.Contains(stdout.String(), "Preflight checks") || strings.Contains(stdout.String(), "CertiStack Preflight Diagnostics") {
				t.Errorf("an interrupted doctor printed a verdict:\n%s", stdout.String())
			}
			select {
			case why := <-server.gone:
				if why != "context canceled" {
					t.Errorf("the held request ended for %q, not because the client gave up", why)
				}
			case <-time.After(2 * time.Second):
				t.Error("the PVE API never saw the request given up")
			}
		})
	}
}

// A worker stopped while it checks the host has refused nothing, and
// does not blame the host for what stopped it. The evidence says it was
// stopped, is not read as a capacity denial, and a worker that was not stopped
// still refuses for what failed.
func TestAWorkerStoppedDuringPreflightIsNotARefusal(t *testing.T) {
	plan, err := config.LoadFromFile(writeValidationFixture(t, t.TempDir(), "plan.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	failed := preflight.Result{Checks: []preflight.CheckItem{{Name: "pve_connectivity", Status: "failed", Detail: "failed to reach PVE API: context canceled"}}}

	stopped, cancel := context.WithCancel(context.Background())
	cancel()
	got := preflightRefusedResult(stopped, plan, "pve-01", failed, false)
	if !strings.Contains(got.Error, "node preflight interrupted") || got.Report == nil || got.Report.FailureReason != got.Error {
		t.Fatalf("a stopped worker: %+v", got)
	}
	if strings.HasPrefix(got.Error, accept.PreflightFailurePrefix) || strings.Contains(got.Error, "pve_connectivity") {
		t.Errorf("a stopped worker blames the host: %q", got.Error)
	}
	if got.Report.TeardownEvidence == nil || !got.Report.TeardownEvidence.AllCleaned {
		t.Errorf("the evidence does not say nothing was left behind: %+v", got.Report.TeardownEvidence)
	}

	refused := preflightRefusedResult(context.Background(), plan, "pve-01", failed, false)
	if !strings.HasPrefix(refused.Error, accept.PreflightFailurePrefix) || !strings.Contains(refused.Error, "pve_connectivity") {
		t.Errorf("a worker that was not stopped: %+v", refused)
	}
}

// As the reporter ran it: the command as a process, SIGINT delivered to
// it while its first privilege request is in flight, and a second SIGINT
// 250 ms later (the reporter's, which found the process alive a second after
// both and ended only by the request's own limit, 12.9 seconds after the
// first). The process now ends at the first, with the interrupted status.
func TestDoctorProcessEndsAtTheFirstSignal(t *testing.T) {
	server := newHeldPVE(t, false, 0)
	root := t.TempDir()
	plan := writeValidationFixture(t, root, "plan.yaml")
	state := filepath.Join(root, "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := cliProcess(t, []string{"PATH=" + t.TempDir(), "PVE_URL=" + server.URL, "PVE_TOKEN_ID=audit@pve!doctor", "PVE_TOKEN_SECRET=AUDIT-ONLY-NOT-A-CREDENTIAL"},
		"doctor", "--plan", plan, "--scratch", filepath.Join(root, "scratch"), "--state-dir", state)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t.Cleanup(func() { _ = cmd.Process.Kill() })

	select {
	case <-server.held:
	case err := <-done:
		t.Fatalf("doctor ended before the request it was to be interrupted in: %v\n%s%s", err, stdout.String(), stderr.String())
	case <-time.After(10 * time.Second):
		t.Fatal("the held PVE request never arrived")
	}
	first := time.Now()
	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	time.Sleep(250 * time.Millisecond)
	_ = cmd.Process.Signal(os.Interrupt) // the process may have ended already, which is the point

	select {
	case <-done:
	case <-time.After(8 * time.Second):
		t.Fatalf("doctor was still running 8 seconds after SIGINT:\n%s%s", stdout.String(), stderr.String())
	}
	if elapsed := time.Since(first); elapsed > 6*time.Second { // the held request's own limit is 10
		t.Errorf("doctor took %v to end after the first SIGINT", elapsed)
	}
	if code := cmd.ProcessState.ExitCode(); code != exitCodeInterrupted {
		t.Errorf("exit status %d, want %d\n%s%s", code, exitCodeInterrupted, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "Interrupt received") || !strings.Contains(stderr.String(), "interrupted before it reached a verdict") {
		t.Errorf("stderr:\n%s", stderr.String())
	}
	// Doctor only reads; it is not waiting for any cleanup.
	if strings.Contains(stderr.String(), "waiting for CertiStack cleanup") {
		t.Errorf("a read-only command said it was waiting for cleanup:\n%s", stderr.String())
	}
	if strings.Contains(stdout.String(), "Preflight checks") {
		t.Errorf("an interrupted doctor printed a verdict:\n%s", stdout.String())
	}
}
