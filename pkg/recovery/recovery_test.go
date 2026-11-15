// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package recovery

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/internal/journal"
)

// The facade has one job: hand a state directory to the engine's recovery.
// A directory with no journal is nothing to recover, and one whose journal
// says "cleaned" is finished; neither is an error and neither is touched.
func TestRecoverHandsTheStateDirectoryToTheEngine(t *testing.T) {
	if runtime.GOOS == "linux" && os.Geteuid() != 0 {
		// Linux recovery takes the host lock in /run, which only root can open:
		// the engine's own refusal shows the facade reached it.
		err := Recover(t.TempDir())
		if err == nil || !strings.Contains(err.Error(), "host lock") {
			t.Fatalf("Recover as an unprivileged user = %v, want the engine's host-lock refusal", err)
		}
		t.Skip("the rest needs root: Linux recovery holds the host lock in /run")
	}
	empty := t.TempDir()
	if err := Recover(empty); err != nil {
		t.Fatalf("no journal: %v", err)
	}

	cleaned := t.TempDir()
	path := filepath.Join(cleaned, "active.json")
	record := journal.Record{RunID: "finished", Phase: "cleaned", UpdatedAt: time.Now().UTC()}
	if err := journal.Write(path, record); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := Recover(cleaned); err != nil {
		t.Fatalf("cleaned journal: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != string(before) {
		t.Fatalf("a cleaned journal was rewritten: %v", err)
	}

	broken := t.TempDir()
	if err := os.WriteFile(filepath.Join(broken, "active.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Recover(broken); err == nil {
		t.Fatal("an unreadable journal was treated as nothing to recover")
	}
}
