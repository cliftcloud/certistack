//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// The supervisor's tests replace systemd-run with a recorder, so the lease
// watch the supervisor embeds, quoted into its own script, is not run from
// there. Here the launcher records what it is given, the embedded script, as
// systemd reads it, is compared with leaseWatchScript, and it runs end to end:
// it leaves a fresh lease alone and cleans up once the lease has lapsed. The
// watch passes through systemd-run, as the supervisor does, so its own "$" are
// escaped for it too.
func TestTheLeaseWatchTheSupervisorEmbedsRunsEndToEnd(t *testing.T) {
	h := newSupervisorHarness(t, `printf '{"report":{}}'; exit 0`, 0)
	// The launcher records the command line it is given, one word to a file.
	// A real systemd-run hands the words to the service after systemd has read
	// them (systemdExpandCommand), and so does this test, below.
	launcher := filepath.Join(h.root, "systemd-run")
	words := filepath.Join(h.root, "launched")
	h.write(t, launcher, "#!/bin/sh\nshift 6\nn=0\nfor word in \"$@\"; do\n  n=$((n + 1))\n  printf '%s' \"$word\" > "+shellQuote(words)+".$n\ndone\nprintf '%s' \"$n\" > "+shellQuote(words)+".count\n")
	status, stdout, stderr := h.start(t, h.supervisor(t))()
	if status != 0 || stdout != `{"report":{}}` {
		t.Fatalf("status %d stdout %q stderr %q", status, stdout, stderr)
	}
	count, err := os.ReadFile(words + ".count")
	if err != nil || string(count) != "6" {
		t.Fatalf("the watch was launched with %q words (%v), want the script, its name and four arguments", count, err)
	}
	raw := make([]string, 6)
	for i := range raw {
		data, err := os.ReadFile(words + "." + strconv.Itoa(i+1))
		if err != nil {
			t.Fatal(err)
		}
		raw[i] = string(data)
	}
	launched := systemdExpandCommand(raw, systemdEnvironment)
	embedded := launched[0]
	want := h.adapt(t, leaseWatchScript(workspaceShellVariables(h.lease, h.worker, h.stateDir, h.env, h.progress, h.workspace)))
	// adapt() puts a quoted tick path inside the supervisor's single-quoted
	// watch_script, which unquotes it there: normalise that harness artifact.
	tick := filepath.Join(h.root, "tick")
	if normalised := strings.ReplaceAll(want, shellQuote(tick), tick); embedded != normalised {
		t.Fatalf("the embedded watch differs from leaseWatchScript:\n--- embedded\n%s\n--- want\n%s", embedded, normalised)
	}
	// The renewal time on the boot clock, the lease's stamp, and the worker's
	// PID and start time.
	if args := strings.Join(launched[2:], "|"); strings.Count(args, "|") != 3 || !strings.HasPrefix(args, "1000|") {
		t.Fatalf("watch arguments = %q", args)
	}
	watchOut := filepath.Join(h.root, "watch-out")
	watch := exec.Command("/bin/sh", append([]string{"-c", embedded}, launched[1:]...)...)
	out, err := os.Create(watchOut)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	watch.Stdout, watch.Stderr = out, out
	if err := watch.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = watch.Process.Kill(); _ = watch.Wait() })
	h.waitTicks(t, 2)
	if !exists(h.workspace) {
		t.Fatal("the watch removed the workspace while the lease was fresh")
	}
	h.setUptime(t, 1000+workerLeaseDurationSeconds+2)
	// A hang guard, not a measure of speed: the clean-up takes about 0.1 s, but in
	// the whole suite on a loaded machine the watch's shell can wait seconds to run.
	for deadline := time.Now().Add(60 * time.Second); exists(h.workspace); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			out, _ := os.ReadFile(watchOut)
			t.Fatalf("the watch did not clean up: %s", out)
		}
	}
	if !exists(h.recovered) {
		t.Fatal("the watch removed the workspace without recovering the journal")
	}
}

// A worker that ends at once can be reaped by the supervisor's shell before
// its start time is read. Its own exit status and output are what the
// supervisor reports, whichever happens first. Busy goroutines keep the CPUs
// loaded meanwhile, which makes the early reaping likely; the harness swaps a
// package variable, so the runs themselves are sequential.
func TestAWorkerThatEndsAtOnceGivesItsOwnStatus(t *testing.T) {
	stop := make(chan struct{})
	var spinners sync.WaitGroup
	for i := 0; i < runtime.NumCPU(); i++ {
		spinners.Add(1)
		go func() {
			defer spinners.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
			}
		}()
	}
	defer func() { close(stop); spinners.Wait() }()
	for i := 0; i < 40; i++ {
		h := newSupervisorHarness(t, `printf '{"report":{}}'; exit 0`, 0)
		status, stdout, stderr := h.start(t, h.supervisor(t))()
		if status != 0 || stdout != `{"report":{}}` || strings.Contains(stderr, "cannot be identified") {
			t.Fatalf("run %d: status %d stdout %q stderr %q", i, status, stdout, stderr)
		}
	}
}
