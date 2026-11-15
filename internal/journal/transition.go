// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package journal

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// TransitionsDir is the directory in a state directory that holds one
// Transition per run whose journal was clean when the next run replaced it.
const TransitionsDir = "runs"

// maxTransitions bounds the transition records a state directory keeps: the
// newest ones, by modification time, stay.
const maxTransitions = 256

// runIDExpr bounds the run IDs that name a transition record's file.
var runIDExpr = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// Transition is the durable, run-bound record that the journal of run RunID
// was clean ("cleaned") when run SupersededBy replaced it as the active
// journal. active.json holds one run's journal, so once another run has
// replaced it, this record is all the node keeps of the earlier run's
// cleanup: a controller that finds another run's journal there can tell
// whether the run it checks left nothing behind (the journal itself proves
// nothing of a run it does not name).
type Transition struct {
	RunID        string    `json:"run_id"`
	Phase        string    `json:"phase"`
	SupersededBy string    `json:"superseded_by"`
	At           time.Time `json:"at"`
}

// TransitionPath is where the transition of run runID is kept in stateDir.
func TransitionPath(stateDir, runID string) (string, error) {
	if !runIDExpr.MatchString(runID) {
		return "", fmt.Errorf("journal: %q is not a usable run ID", runID)
	}
	return filepath.Join(stateDir, TransitionsDir, runID+".json"), nil
}

// LoadTransition reads the transition of run runID.
func LoadTransition(stateDir, runID string) (Transition, error) {
	var t Transition
	path, err := TransitionPath(stateDir, runID)
	if err != nil {
		return t, err
	}
	data, err := readStateFile(path, "transition record", 1<<16, "")
	if err != nil {
		return t, err
	}
	err = json.Unmarshal(data, &t)
	return t, err
}

// Begin makes next the active journal of stateDir, the way a run starts one.
// The caller holds the host lock and has checked that the journal it replaces
// is clean. Before it replaces a clean journal that names another run, Begin
// keeps that run's Transition, so the run's own controller can still verify
// its cleanup afterwards. A transition that cannot be written does not stop
// the run: the earlier run's controller then finds its cleanup unproven,
// which is the safe side.
func Begin(stateDir string, next Record) error {
	path := filepath.Join(stateDir, "active.json")
	if prev, err := Load(path); err == nil && prev.Phase == "cleaned" && prev.RunID != "" && prev.RunID != next.RunID {
		if err := noteTransition(stateDir, prev.RunID, next.RunID); err != nil {
			slog.Warn("could not record that an earlier run's journal was clean", "run_id", prev.RunID, "error", err)
		}
	}
	return Write(path, next)
}

func noteTransition(stateDir, runID, supersededBy string) error {
	path, err := TransitionPath(stateDir, runID)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(Transition{RunID: runID, Phase: "cleaned", SupersededBy: supersededBy, At: time.Now().UTC()}, "", "  ")
	if err != nil {
		return err
	}
	if err := AtomicWrite(path, append(data, '\n')); err != nil {
		return err
	}
	pruneTransitions(filepath.Dir(path))
	return nil
}

// pruneTransitions keeps the newest maxTransitions records of dir. It is
// best effort: what it cannot remove stays.
func pruneTransitions(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	type kept struct {
		name string
		at   time.Time
	}
	var records []kept
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		if info, err := entry.Info(); err == nil {
			records = append(records, kept{entry.Name(), info.ModTime()})
		}
	}
	if len(records) <= maxTransitions {
		return
	}
	sort.Slice(records, func(i, j int) bool { return records[i].at.Before(records[j].at) })
	for _, old := range records[:len(records)-maxTransitions] {
		_ = os.Remove(filepath.Join(dir, old.name))
	}
}

// RecordRefusedRun makes the journal show that run runID, which was refused
// before it allocated anything, left nothing behind: a clean journal that
// names it, so that its controller can verify the refusal as it verifies any
// run's cleanup. It changes nothing when the journal already names the run,
// and refuses to replace a journal that is not clean or cannot be read. The
// caller holds the host lock.
func RecordRefusedRun(stateDir, runID string) error {
	if runID == "" {
		return errors.New("journal: a refused run has no run ID to record")
	}
	path := filepath.Join(stateDir, "active.json")
	prev, err := Load(path)
	switch {
	case err == nil && prev.RunID == runID:
		return nil
	case err == nil && prev.Phase != "cleaned":
		return fmt.Errorf("journal: not replacing the journal of run %q, which is %q, with the record of refused run %q", prev.RunID, prev.Phase, runID)
	case err != nil && !errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("journal: not recording refused run %q: the active journal cannot be read: %w", runID, err)
	}
	return Begin(stateDir, Record{RunID: runID, Phase: "cleaned", UpdatedAt: time.Now().UTC()})
}
