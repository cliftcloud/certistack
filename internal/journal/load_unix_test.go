//go:build unix

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package journal

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// within runs read and fails the test if it does not return within a few
// seconds: a read that waits for a writer that never comes is a hang of
// recover, plan, inspect and every run's admission.
func within(t *testing.T, what string, read func() error) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- read() }()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatalf("%s did not return: it waits on a named pipe", what)
		return nil
	}
}

// Load and LoadTransition opened their file with a plain open, which on a
// named pipe waits for a writer: a FIFO at active.json, or at a transition
// record, hung recovery, plan, inspect and the start of every run on the node
// forever. Each is now refused at once, with the path and what it is.
func TestLoadRefusesANamedPipeAtOnce(t *testing.T) {
	stateDir := t.TempDir()
	active := filepath.Join(stateDir, "active.json")
	if err := syscall.Mkfifo(active, 0o600); err != nil {
		t.Skipf("cannot make a named pipe here: %v", err)
	}
	err := within(t, "Load", func() error { _, err := Load(active); return err })
	if err == nil || !strings.Contains(err.Error(), active) || !strings.Contains(err.Error(), "named pipe") {
		t.Fatalf("Load = %v; want a refusal that names %s as a named pipe", err, active)
	}

	runs := filepath.Join(stateDir, TransitionsDir)
	if err := os.Mkdir(runs, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(runs, "run-1.json"), 0o600); err != nil {
		t.Fatal(err)
	}
	err = within(t, "LoadTransition", func() error { _, err := LoadTransition(stateDir, "run-1"); return err })
	if err == nil || !strings.Contains(err.Error(), "named pipe") {
		t.Fatalf("LoadTransition = %v; want a refusal of the named pipe", err)
	}
}

// A journal larger than any CertiStack writes is refused with its path and the
// limit, and one that is not JSON with its path and what to do; neither is
// read as a journal.
func TestLoadSaysWhichJournalItCannotRead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "active.json")
	if err := os.WriteFile(path, []byte(`{"run_id": "run-1", "phase": "running",`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), "not valid JSON") {
		t.Fatalf("Load of a truncated journal = %v; want the path and that it is not valid JSON", err)
	}
	if !strings.Contains(err.Error(), UnreadableJournalAdvice) {
		t.Fatalf("Load of a truncated journal = %v; want the next step", err)
	}
}
