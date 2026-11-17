// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package journal

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func writeActive(t *testing.T, dir string, r Record) {
	t.Helper()
	if err := Write(filepath.Join(dir, "active.json"), r); err != nil {
		t.Fatal(err)
	}
}

// A run replaces the clean journal of the run before it, and
// keeps that run's transition record, so its controller can still verify
// its cleanup once the node-wide journal names another run.
func TestBeginKeepsTheTransitionOfTheCleanJournalItReplaces(t *testing.T) {
	dir := t.TempDir()
	writeActive(t, dir, Record{RunID: "run-earlier", Phase: "cleaned", UpdatedAt: time.Now().UTC()})
	if err := Begin(dir, Record{RunID: "run-later", Phase: "running"}); err != nil {
		t.Fatal(err)
	}
	transition, err := LoadTransition(dir, "run-earlier")
	if err != nil || transition.RunID != "run-earlier" || transition.Phase != "cleaned" || transition.SupersededBy != "run-later" || transition.At.IsZero() {
		t.Fatalf("transition = %+v, %v", transition, err)
	}
	active, err := Load(filepath.Join(dir, "active.json"))
	if err != nil || active.RunID != "run-later" || active.Phase != "running" {
		t.Fatalf("active journal = %+v, %v", active, err)
	}
	info, err := os.Stat(filepath.Join(dir, TransitionsDir))
	if err != nil || (runtime.GOOS != "windows" && info.Mode().Perm() != 0o700) {
		t.Fatalf("transitions directory = %v, %v; want private", info, err)
	}
}

// A journal that is not clean, that names no run, that is missing or that is
// the run's own leaves no transition: only a clean record of another run
// does.
func TestBeginKeepsNoTransitionForAnythingButACleanEarlierRun(t *testing.T) {
	for name, prepare := range map[string]func(dir string){
		"no journal":         func(string) {},
		"an interrupted run": func(dir string) { writeActive(t, dir, Record{RunID: "run-earlier", Phase: "running"}) },
		"a failed cleanup":   func(dir string) { writeActive(t, dir, Record{RunID: "run-earlier", Phase: "cleanup_failed"}) },
		"a clean journal that names no run": func(dir string) {
			writeActive(t, dir, Record{Phase: "cleaned"})
		},
		"the run's own record": func(dir string) { writeActive(t, dir, Record{RunID: "run-later", Phase: "cleaned"}) },
		"a journal that cannot be read": func(dir string) {
			if err := os.WriteFile(filepath.Join(dir, "active.json"), []byte("{"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			prepare(dir)
			if err := Begin(dir, Record{RunID: "run-later", Phase: "running"}); err != nil {
				t.Fatal(err)
			}
			entries, _ := os.ReadDir(filepath.Join(dir, TransitionsDir))
			if len(entries) != 0 {
				t.Fatalf("transition records kept: %v", entries)
			}
		})
	}
}

// A transition that cannot be kept does not stop the run.
func TestBeginStartsTheRunWhenItCannotKeepATransition(t *testing.T) {
	dir := t.TempDir()
	writeActive(t, dir, Record{RunID: "run-earlier", Phase: "cleaned"})
	if err := os.WriteFile(filepath.Join(dir, TransitionsDir), []byte("in the way"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Begin(dir, Record{RunID: "run-later", Phase: "running"}); err != nil {
		t.Fatalf("Begin = %v, want the run to start", err)
	}
	if active, err := Load(filepath.Join(dir, "active.json")); err != nil || active.RunID != "run-later" {
		t.Fatalf("active journal = %+v, %v", active, err)
	}
}

func TestTransitionPathRefusesARunIDThatIsNotAFileName(t *testing.T) {
	for _, id := range []string{"", "../active", "run/../../x", ".hidden", "run id", strings.Repeat("a", 129)} {
		if _, err := TransitionPath("/state", id); err == nil {
			t.Errorf("run ID %q was accepted", id)
		}
	}
	if path, err := TransitionPath("/state", "run-2f1c6d0e-5b7a-4c1e-9d3f-8a2b4c6d8e0f"); err != nil || path != filepath.Join("/state", "runs", "run-2f1c6d0e-5b7a-4c1e-9d3f-8a2b4c6d8e0f.json") {
		t.Fatalf("path = %q, %v", path, err)
	}
}

// The state directory keeps the newest transitions, and only those.
func TestTransitionsArePrunedToTheNewest(t *testing.T) {
	dir := t.TempDir()
	transitions := filepath.Join(dir, TransitionsDir)
	if err := os.MkdirAll(transitions, 0o700); err != nil {
		t.Fatal(err)
	}
	base := time.Now().Add(-time.Hour)
	for i := 0; i < maxTransitions+5; i++ {
		name := filepath.Join(transitions, fmt.Sprintf("run-old-%03d.json", i))
		if err := os.WriteFile(name, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(name, base.Add(time.Duration(i)*time.Second), base.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	other := filepath.Join(transitions, "notes.txt")
	if err := os.WriteFile(other, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	writeActive(t, dir, Record{RunID: "run-earlier", Phase: "cleaned"})
	if err := Begin(dir, Record{RunID: "run-later", Phase: "running"}); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(transitions)
	json := 0
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".json") {
			json++
		}
	}
	if json != maxTransitions {
		t.Fatalf("%d transition records kept, want %d", json, maxTransitions)
	}
	if _, err := LoadTransition(dir, "run-earlier"); err != nil {
		t.Fatalf("the newest transition was pruned: %v", err)
	}
	if _, err := os.Stat(filepath.Join(transitions, "run-old-000.json")); !os.IsNotExist(err) {
		t.Fatalf("the oldest transition was kept: %v", err)
	}
	if _, err := os.Stat(other); err != nil {
		t.Fatalf("a file that is not a transition was removed: %v", err)
	}
}

// A run refused before it allocated anything gets a clean journal
// of its own, which is what its controller verifies. It is written over a
// clean earlier journal (keeping that run's transition) or none, changes
// nothing when the journal is already the run's own, and never replaces a
// journal that is not clean.
func TestRecordRefusedRun(t *testing.T) {
	t.Run("no journal", func(t *testing.T) {
		dir := t.TempDir()
		if err := RecordRefusedRun(dir, "run-refused"); err != nil {
			t.Fatal(err)
		}
		active, err := Load(filepath.Join(dir, "active.json"))
		if err != nil || active.RunID != "run-refused" || active.Phase != "cleaned" || active.UpdatedAt.IsZero() {
			t.Fatalf("active journal = %+v, %v", active, err)
		}
	})
	t.Run("a clean earlier journal", func(t *testing.T) {
		dir := t.TempDir()
		writeActive(t, dir, Record{RunID: "run-earlier", Phase: "cleaned"})
		if err := RecordRefusedRun(dir, "run-refused"); err != nil {
			t.Fatal(err)
		}
		if active, _ := Load(filepath.Join(dir, "active.json")); active.RunID != "run-refused" || active.Phase != "cleaned" {
			t.Fatalf("active journal = %+v", active)
		}
		if _, err := LoadTransition(dir, "run-earlier"); err != nil {
			t.Fatalf("the earlier run's transition was not kept: %v", err)
		}
	})
	t.Run("the run's own journal stands", func(t *testing.T) {
		dir := t.TempDir()
		writeActive(t, dir, Record{RunID: "run-refused", Phase: "cleanup_failed", CleanupErrors: []string{"left a VM"}, VMs: []TrackedVM{{VMID: 9001}}})
		if err := RecordRefusedRun(dir, "run-refused"); err != nil {
			t.Fatal(err)
		}
		if active, _ := Load(filepath.Join(dir, "active.json")); active.Phase != "cleanup_failed" || len(active.VMs) != 1 {
			t.Fatalf("the run's own journal was replaced: %+v", active)
		}
	})
	for name, prepare := range map[string]func(dir string){
		"an interrupted run's journal": func(dir string) {
			writeActive(t, dir, Record{RunID: "run-earlier", Phase: "running", VMs: []TrackedVM{{VMID: 9001}}})
		},
		"a journal that cannot be read": func(dir string) {
			if err := os.WriteFile(filepath.Join(dir, "active.json"), []byte("{"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name+" is never replaced", func(t *testing.T) {
			dir := t.TempDir()
			prepare(dir)
			before, _ := os.ReadFile(filepath.Join(dir, "active.json"))
			if err := RecordRefusedRun(dir, "run-refused"); err == nil {
				t.Fatal("RecordRefusedRun replaced a journal that is not clean")
			}
			if after, _ := os.ReadFile(filepath.Join(dir, "active.json")); string(after) != string(before) {
				t.Fatalf("the journal changed: %q", after)
			}
		})
	}
	if err := RecordRefusedRun(t.TempDir(), ""); err == nil {
		t.Fatal("a refused run without a run ID was recorded")
	}
}
