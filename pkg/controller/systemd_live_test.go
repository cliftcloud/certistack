//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// These tests run the controller's own commands through the real systemd-run
// of the machine they run on, which no other test of this package does: the
// rest run the script with sh -c, where that problem (systemd deleting what it
// takes for an environment variable from the script) cannot show. They need
// root on a host whose PID 1 is systemd, and create transient units of their
// own (certistack-test-*, certistack-worker-*, certistack-watch-*), so they run
// only when asked for:
//
//	sudo CERTISTACK_TEST_SYSTEMD=1 go test ./pkg/controller -run Live -v
//
// The lease watch test waits out a real 90 s lease and is skipped with -short.
// Run the same on a Proxmox node's systemd to check the version it ships.

func requireLiveSystemd(t *testing.T) {
	t.Helper()
	if os.Getenv("CERTISTACK_TEST_SYSTEMD") != "1" {
		t.Skip("set CERTISTACK_TEST_SYSTEMD=1, as root on a systemd host, to run against the real systemd-run")
	}
	if os.Geteuid() != 0 {
		t.Fatal("CERTISTACK_TEST_SYSTEMD=1 needs root: systemd-run creates system units")
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		t.Fatalf("CERTISTACK_TEST_SYSTEMD=1 needs systemd as PID 1: %v", err)
	}
	if _, err := os.Stat("/usr/bin/systemd-run"); err != nil {
		t.Fatalf("CERTISTACK_TEST_SYSTEMD=1 needs /usr/bin/systemd-run: %v", err)
	}
}

var liveUnits atomic.Int64

// liveScript prints each of its arguments and a unit separator after it.
const liveScript = `for word in "$@"; do printf '%s\037' "$word"; done`

// liveShell runs liveScript with sh -c through the real systemd-run, the
// words as arguments, and returns what the shell printed. The command is the
// controller's own (systemdRunCommand); escape says whether the words are
// escaped as well, as the controller escapes a script.
func liveShell(t *testing.T, escape bool, words ...string) string {
	t.Helper()
	command := systemdRunCommand(fmt.Sprintf("certistack-test-%d-%d", os.Getpid(), liveUnits.Add(1)), "/bin/sh", "-c", liveScript, "sh")
	for _, word := range words {
		if escape {
			word = systemdWord(word)
		}
		command = append(command, word)
	}
	var stdout, stderr bytes.Buffer
	cmd := exec.Command(command[0], command[1:]...)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("%.200q: %v: %s", command, err, stderr.String())
	}
	return stdout.String()
}

// liveWords is a corpus of words: the forms that problem was about, what a path
// may hold, and words that are long.
func liveWords() []string {
	return []string{
		`a${x##*\) }b`, `a${x#y}b`, `a${x%y}b`, `a${x%%y}b`, `a${x}b`, `a${#x}b`, `a${x-y}b`, `a${x:-y}b`, `a${x:+y}b`,
		`a$((1+2))b`, `a$(echo hi)b`, `a$xb`, `a$x b`, `a$$b`, `a$$$b`, `a$${x##y}b`,
		`a%sb`, `a%%b`, `a%hb`, `a%Hb`, `a%nb`, `a%ib`, `a%tb`, `100%`,
		`${HOME}`, `x${HOME}y`, `x${PATH}y`, `$`, `$$`, `${`, `${}`, `trailing$`,
		"tab\tand \\ backslash \\$ and 'q' \"dq\"", "two\nlines\n", "ünïcode ✓ $é ${é}",
		strings.Repeat("$", 1000), strings.Repeat("${a##b}%s", 500),
	}
}

// The property the controller relies on: a word escaped with systemdWord
// reaches the program exactly as it was, whatever systemd does with the
// forms it knows. The model is pinned to the forms it is certain of; the two
// that some versions replace by a default are allowed to differ.
func TestLiveSystemdRunMatchesTheModel(t *testing.T) {
	requireLiveSystemd(t)
	words := liveWords()
	escaped := liveShell(t, true, words...)
	if want := strings.Join(words, "\x1f") + "\x1f"; escaped != want {
		t.Errorf("escaped words did not arrive as they were:\n--- received\n%q\n--- sent\n%q", escaped, want)
	}
	raw := liveShell(t, false, words...)
	// The service's PATH is this host's; nothing else in the model is set.
	environment := map[string]string{"PATH": strings.TrimSuffix(liveShellOutput(t, `printf '%s' "$PATH"`), "\x1f")}
	for _, word := range words {
		// Unset variables and a bare "$NAME" word do not make this list: a
		// word that systemd removes leaves no record of it.
		model := systemdExpandCommand([]string{word}, environment)
		if len(model) != 1 {
			continue
		}
		if strings.Contains(word, ":-") || strings.Contains(word, ":+") {
			continue
		}
		if !strings.Contains(raw, model[0]+"\x1f") {
			t.Errorf("the model of systemd says %q becomes %q, which a real systemd-run did not hand over:\n%q", word, model[0], raw)
		}
	}
}

// liveShellOutput is what script prints when a real systemd-run runs it.
func liveShellOutput(t *testing.T, script string) string {
	t.Helper()
	command := systemdRunCommand(fmt.Sprintf("certistack-test-%d-%d", os.Getpid(), liveUnits.Add(1)), "/bin/sh", "-c", script+`; printf '\037'`)
	var stdout, stderr bytes.Buffer
	cmd := exec.Command(command[0], command[1:]...)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("%.200q: %v: %s", command, err, stderr.String())
	}
	return stdout.String()
}

type liveSupervisor struct {
	h      *supervisorHarness
	unit   string
	result string
	status int
	stderr string
}

// runLiveSupervisor runs the supervisor the controller builds through the real
// systemd-run, with the real lease watch launcher, and waits for it to end.
func runLiveSupervisor(t *testing.T, nodeRun string, recoverStatus int) *liveSupervisor {
	t.Helper()
	requireLiveSystemd(t)
	h := newSupervisorHarness(t, nodeRun, recoverStatus)
	previous := leaseWatchLauncher
	leaseWatchLauncher = "/usr/bin/systemd-run"
	t.Cleanup(func() { leaseWatchLauncher = previous })
	unit, err := workerUnitName(h.workspaceRoot, h.workspace)
	if err != nil {
		t.Fatal(err)
	}
	command := (&Executor{}).supervisedWorkerCommand(SSHConfig{}, unit, h.workspaceRoot, h.workspace, h.pidFile, h.lease, h.stateDir, h.env, h.result, h.progress, []string{h.worker, "node-run"})
	if command == nil {
		t.Fatal("no supervisor command")
	}
	watchUnit := leaseWatchUnitName(h.workspace)
	t.Cleanup(func() {
		_ = exec.Command("systemctl", "stop", unit, watchUnit).Run()
		_ = exec.Command("systemctl", "reset-failed", unit, watchUnit).Run()
	})
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, command[0], command[1:]...)
	cmd.WaitDelay = 5 * time.Second
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err = cmd.Run()
	live := &liveSupervisor{h: h, unit: unit, result: stdout.String(), stderr: stderr.String()}
	if exit, ok := err.(*exec.ExitError); ok {
		live.status = exit.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	if ctx.Err() != nil {
		progress, _ := os.ReadFile(h.progress)
		status, _ := exec.Command("systemctl", "status", unit, "--no-pager").CombinedOutput()
		t.Fatalf("the supervisor did not end within 60 s through the real systemd-run:\nprogress:\n%s\nstatus:\n%s", progress, status)
	}
	return live
}

func (l *liveSupervisor) watchActive() string {
	out, _ := exec.Command("systemctl", "is-active", leaseWatchUnitName(l.h.workspace)).Output()
	return strings.TrimSpace(string(out))
}

// On a real node: the supervisor identified nothing, stopped its worker
// with status 125 and hung on its progress tail. Through the real systemd-run
// it runs a worker, writes its PID, returns its result and leaves a lease
// watch, which ends on its own once the controller removes the workspace.
func TestLiveSupervisorRunsAWorkerThroughSystemdRun(t *testing.T) {
	l := runLiveSupervisor(t, `printf '{"report":{}}'; exit 0`, 0)
	progress, _ := os.ReadFile(l.h.progress)
	if l.status != 0 || l.result != `{"report":{}}` {
		t.Fatalf("exit %d, stdout %q, stderr %q, progress %q", l.status, l.result, l.stderr, progress)
	}
	if strings.Contains(string(progress), "cannot be identified") || !exists(l.h.pidFile) {
		t.Fatalf("the supervisor could not identify its worker (pid file %v):\n%s", exists(l.h.pidFile), progress)
	}
	if active := l.watchActive(); active != "active" {
		t.Fatalf("the lease watch is %q, want active", active)
	}
	// The controller collects the result and removes the workspace: the watch
	// ends without recovering anything.
	if err := os.RemoveAll(l.h.workspace); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(30 * time.Second); l.watchActive() == "active"; time.Sleep(time.Second) {
		if time.Now().After(deadline) {
			t.Fatal("the lease watch did not end after the workspace was removed")
		}
	}
	if exists(l.h.recovered) {
		t.Fatal("the lease watch recovered a journal the controller had collected")
	}
}

// A worker that fails is recovered by the supervisor, which then ends: the
// progress tail is ended with it (the original hang was in this step).
func TestLiveSupervisorRecoversAWorkerThatFailsThroughSystemdRun(t *testing.T) {
	for _, tc := range []struct {
		name, nodeRun string
		status        int
		message       string
	}{
		{"exit status", `printf '{"error":"x"}'; exit 3`, 3, "The node worker failed with exit status 3; recovering its journal."},
		{"signal", `kill -9 $$`, 137, "The node worker ended by signal 9 before it finished; recovering its journal."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := runLiveSupervisor(t, tc.nodeRun, 0)
			progress, _ := os.ReadFile(l.h.progress)
			if l.status != tc.status || !strings.Contains(string(progress), tc.message) || !exists(l.h.recovered) {
				t.Fatalf("exit %d, recovered %v, stderr %q, progress:\n%s", l.status, exists(l.h.recovered), l.stderr, progress)
			}
			if !strings.Contains(l.stderr, tc.message) {
				t.Fatalf("the controller's stream (the supervisor's stderr) lacks %q:\n%s", tc.message, l.stderr)
			}
		})
	}
}

// On a real node: the controller is gone, nobody renews the lease or
// collects, and the lease watch, a service of its own, recovers the journal
// and removes the workspace once the lease is 90 s old on the boot clock.
func TestLiveLeaseWatchCleansUpAfterAControllerThatIsGone(t *testing.T) {
	if testing.Short() {
		t.Skip("waits out a real 90 s lease")
	}
	l := runLiveSupervisor(t, `printf '{"report":{}}'; exit 0`, 0)
	if l.status != 0 {
		t.Fatalf("exit %d, stderr %q", l.status, l.stderr)
	}
	started := time.Now()
	for exists(l.h.workspace) {
		if time.Since(started) > 4*time.Minute {
			progress, _ := os.ReadFile(l.h.progress)
			t.Fatalf("the lease watch (%s) did not clean up within 4 min:\n%s", l.watchActive(), progress)
		}
		time.Sleep(2 * time.Second)
	}
	if !exists(l.h.recovered) {
		t.Fatal("the lease watch removed the workspace without recovering the journal")
	}
	if kept, err := os.ReadFile(filepath.Join(l.h.stateDir, "logs", filepath.Base(l.h.workspace)+".log")); err != nil || !strings.Contains(string(kept), "recovering its journal") {
		t.Fatalf("the watch kept no recovery log: %q, %v", kept, err)
	}
	t.Logf("the watch cleaned up %s after the worker ended", time.Since(started).Round(time.Second))
}
