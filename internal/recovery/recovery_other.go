//go:build !linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package recovery

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cliftcloud/certistack/internal/journal"
	"github.com/cliftcloud/certistack/internal/recoverhint"
)

// UnmapLeakedMaps is a no-op: PBS maps exist only on Linux nodes.
func UnmapLeakedMaps([]*journal.MapIntent, map[string]bool, func() error) error { return nil }

// MayStopMapDaemon is false: PBS maps exist only on Linux nodes.
func MayStopMapDaemon(string, journal.MapIntent) (bool, error) { return false, nil }

// StopMapDaemon stops nothing: PBS maps exist only on Linux nodes.
func StopMapDaemon(string, journal.MapIntent) (string, error) { return "", nil }

// ReusedLoopNote says nothing: PBS maps exist only on Linux nodes.
func ReusedLoopNote(string, string) (string, error) { return "", nil }

func LoopBacking(device string) (string, error) {
	return "", errors.New("loop devices are only supported on Linux")
}

func Inspect(stateDir string) (*journal.Record, error) {
	path := filepath.Join(stateDir, "active.json")
	r, err := journal.Load(path)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func Recover(stateDir string) error {
	return RecoverLocked(stateDir)
}

// RecoverContext mirrors Recover for a caller that can be interrupted. It
// starts nothing on this platform, so there is nothing to interrupt.
func RecoverContext(_, _ context.Context, stateDir string) error {
	return RecoverLocked(stateDir)
}

// RecoverLockedContext mirrors RecoverLocked for a caller that can be
// interrupted; see RecoverContext.
func RecoverLockedContext(_, _ context.Context, stateDir string) error {
	return RecoverLocked(stateDir)
}

// RecoverLocked mirrors Recover on platforms without Linux host resources.
// It is kept for the node-worker locking contract used on Linux.
func RecoverLocked(stateDir string) error {
	path := filepath.Join(stateDir, "active.json")
	r, err := journal.Load(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if r.Phase == "cleaned" {
		return nil
	}
	// This platform cannot inspect or remove the Linux/PVE resources recorded
	// in a run. Marking them cleaned would irreversibly hide unresolved state
	// from a later recovery-capable host.
	return fmt.Errorf("cannot recover active run %q in phase %q on this platform; on the Linux PVE host that owns the recorded resources, "+recoverhint.Recover, r.RunID, r.Phase)
}
