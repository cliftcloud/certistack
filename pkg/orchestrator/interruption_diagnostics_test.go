// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/config"
)

// The diagnostics taken after a failed probe stage ask the guest agent
// and QEMU, and an interrupted run does not wait for them. Each used to take no
// context and wait its own 5 s (and the screendump 15 s).
func TestFailureDiagnosticsEndAtOnceWhenTheRunIsInterrupted(t *testing.T) {
	endsAtOnce := func(t *testing.T, run func(ctx context.Context)) {
		t.Helper()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan struct{})
		go func() { run(ctx); close(done) }()
		time.Sleep(300 * time.Millisecond)
		canceled := time.Now()
		cancel()
		select {
		case <-done:
			if took := time.Since(canceled); took > 1500*time.Millisecond {
				t.Fatalf("the diagnostic took %v to end after cancellation", took)
			}
		case <-time.After(6 * time.Second):
			t.Fatal("the diagnostic was still waiting 6 seconds after cancellation")
		}
	}

	t.Run("the guest agent never finishes its handshake", func(t *testing.T) {
		dir := shortSocketDir(t)
		fakeQGA(t, dir, 9202, nil, map[string]time.Duration{"guest-sync": 30 * time.Second})
		o := &Orchestrator{opts: Options{QGASocketDir: dir}}
		endsAtOnce(t, func(ctx context.Context) {
			if _, _, _, err := o.captureLiveNetworkDiagnostic(ctx, 9202, "", ""); err == nil {
				t.Error("an interrupted capture reported a diagnostic")
			}
		})
	})

	t.Run("the guest agent never lists its interfaces", func(t *testing.T) {
		dir := shortSocketDir(t)
		fakeQGA(t, dir, 9203, map[string]any{"guest-network-get-interfaces": map[string]any{"return": []any{}}},
			map[string]time.Duration{"guest-network-get-interfaces": 30 * time.Second})
		o := &Orchestrator{opts: Options{QGASocketDir: dir}}
		endsAtOnce(t, func(ctx context.Context) {
			if _, _, _, err := o.captureLiveNetworkDiagnostic(ctx, 9203, "", ""); err == nil {
				t.Error("an interrupted capture reported a diagnostic")
			}
		})
	})

	t.Run("QEMU never greets the forensic screendump", func(t *testing.T) {
		dir := shortSocketDir(t)
		release := make(chan struct{})
		t.Cleanup(func() { close(release) })
		serveUnixSocket(t, filepath.Join(dir, "9204.qmp"), func(conn net.Conn) { <-release })
		o := &Orchestrator{opts: Options{QMPSocketDir: dir, ScratchDir: privateScratch(t)}}
		endsAtOnce(t, func(ctx context.Context) {
			if artifact := o.captureFailureArtifact(ctx, 9204); artifact != nil {
				t.Error("an interrupted capture returned an artifact")
			}
		})
	})
}

// privateScratch is a scratch directory with the 0700 mode the screendump code
// requires.
func privateScratch(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

// The screendump probe's residual: a screendump probe whose QEMU does
// not answer the screendump command held the probe stage for the 15 s QMP
// command timeout after the run was canceled, because the capture took a
// context and never passed it on. The reporter's verifier saw runProbes return
// after 15.006 s for a cancel at 300 ms.
func TestRunProbesEndsAtOnceWhenCanceledDuringAnUnansweredScreendump(t *testing.T) {
	dir := shortSocketDir(t)
	entered := make(chan struct{})
	var once sync.Once
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	serveUnixSocket(t, filepath.Join(dir, "9205.qmp"), func(conn net.Conn) {
		reader, encoder := bufio.NewReader(conn), json.NewEncoder(conn)
		if err := encoder.Encode(map[string]any{"QMP": map[string]any{}}); err != nil {
			return
		}
		for {
			line, err := reader.ReadBytes('\n')
			if err != nil {
				return
			}
			var command map[string]any
			if err := json.Unmarshal(line, &command); err != nil {
				return
			}
			if command["execute"] == "screendump" {
				once.Do(func() { close(entered) })
				<-release // QEMU is busy; the reply never comes
				return
			}
			if err := encoder.Encode(map[string]any{"return": map[string]any{}, "id": command["id"]}); err != nil {
				return
			}
		}
	})

	o := &Orchestrator{opts: Options{QMPSocketDir: dir, ScratchDir: privateScratch(t)}}
	vm := config.VM{VMID: 9205, Probes: []config.Probe{
		{Type: "screendump", Description: "console", TimeoutSec: 60, Retries: 1},
		{Type: "tcp", TargetIP: "127.0.0.1", Port: acceptingPort(t), Description: "service port", TimeoutSec: 1},
	}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type outcome struct {
		passed bool
		err    error
		first  string
	}
	done := make(chan outcome, 1)
	go func() {
		results, passed, err := o.runProbes(ctx, vm)
		first := ""
		if len(results) > 0 {
			first = results[0].Error
			if results[0].Passed {
				first = "PASSED"
			}
		}
		done <- outcome{passed, err, first}
	}()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the screendump command never reached QEMU")
	}
	time.Sleep(300 * time.Millisecond)
	canceled := time.Now()
	cancel()
	select {
	case got := <-done:
		if got.passed || got.err == nil || got.first == "PASSED" {
			t.Fatalf("the stage passed=%v err=%v first result error=%q after the run was canceled", got.passed, got.err, got.first)
		}
		if took := time.Since(canceled); took > 2*time.Second {
			t.Fatalf("runProbes took %v to return after cancellation", took)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("runProbes was still waiting for the screendump 6 seconds after cancellation")
	}
}
