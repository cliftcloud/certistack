// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/progress"
)

// Inspection: `certistack init --inspect` reads a few files of each Linux
// VM's newest backup to choose the probes of a first plan. It maps the
// backup exactly as a run does, through mapSourceDrive, under the run's
// journal, host lock and cleanup stack, so a worker killed in the middle of
// it leaves a journal that the node's next run (or certistack recover)
// recovers like any interrupted run's. The maps are read-only, nothing is
// booted, and no overlay, VM or network object is made.

// InspectTarget is a VM whose backup an inspection reads: its snapshot, and
// the disks the backup holds, in the order the guest sees them.
type InspectTarget struct {
	SourceVMID int
	Snapshot   string
	Drives     []config.SourceDrive
}

// InspectOutcome is what InspectBackups did with one target. Skipped says
// why its backup was not mapped at all; Err why reading it failed once it
// was, or why its maps could not be shown released.
type InspectOutcome struct {
	Target  InspectTarget
	Skipped string
	Err     error
}

// InspectCleanup is what an inspection proved of its own cleanup: Verified
// once every map it made was shown released and the journal was marked
// cleaned, and otherwise what was not.
type InspectCleanup struct {
	Verified bool
	Errors   []string
}

// ErrMapsNotReleased is an inspection map that could not be shown released.
// The journal keeps it for recovery, and nothing more is mapped: the next
// map could be given its loop number.
var ErrMapsNotReleased = errors.New("a backup map could not be shown released, so the journal keeps it for recovery")

// loopSettleAttempts and loopSettleInterval bound how long a released map's
// loop device may take to leave the kernel's loop table: the libguestfs
// appliance that read it can still be closing it, and on a busy node with many
// maps released at once that takes seconds. A loop that is still there after
// this is not released, and the cleanup says so. Variables so a test can
// shorten them.
var (
	loopSettleAttempts = 30
	loopSettleInterval = time.Second
)

// InspectBackups maps each target's backup in turn, read-only, hands its
// loop devices to read, and releases the maps before it maps the next one,
// whatever read did. The journal must already name the inspection (the
// caller began it, as a run does); InspectBackups marks it running, and at
// the end cleaned, or cleanup_failed with what is left.
//
// admit, when set, is asked before each target is mapped; a refusal skips
// the target. A map that cannot be shown released stops the inspection: the
// targets after it are skipped, and the journal keeps the map for recovery.
// A signal (SIGINT, SIGHUP, SIGTERM) stops the inspection after the target it
// is reading has been released; the error then names it.
func (o *Orchestrator) InspectBackups(ctx context.Context, targets []InspectTarget, admit func(context.Context) error, read func(context.Context, InspectTarget, []string) error) ([]InspectOutcome, InspectCleanup, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, stopSignals, interruptedBy := interruptContext(ctx)
	defer stopSignals()

	o.record.Phase = "running"
	if err := o.flushJournal(); err != nil {
		return nil, InspectCleanup{Errors: []string{err.Error()}}, err
	}
	var (
		outcomes   []InspectOutcome
		unreleased []string
		stop       string
	)
	for _, target := range targets {
		if stop == "" && ctx.Err() != nil {
			stop = "the inspection was stopped before it reached this VM"
		}
		if stop != "" {
			outcomes = append(outcomes, InspectOutcome{Target: target, Skipped: stop})
			continue
		}
		if len(target.Drives) == 0 {
			outcomes = append(outcomes, InspectOutcome{Target: target, Skipped: "its backup holds no disk"})
			continue
		}
		if admit != nil {
			if err := admit(ctx); err != nil {
				outcomes = append(outcomes, InspectOutcome{Target: target, Skipped: err.Error()})
				continue
			}
		}
		readErr, releaseErr := o.inspectBackup(ctx, target, read)
		if releaseErr != nil {
			unreleased = append(unreleased, releaseErr.Error())
			stop = "a map of an earlier VM's backup could not be shown released, so nothing more was mapped"
		}
		outcomes = append(outcomes, InspectOutcome{Target: target, Err: errors.Join(readErr, releaseErr)})
	}
	cleanup := o.finishInspection(unreleased)
	if interrupted := interruptedBy(); interrupted != nil {
		return outcomes, cleanup, interrupted
	}
	return outcomes, cleanup, nil
}

// inspectBackup maps target's disks, has read read them, and releases the
// maps again. readErr is why the map or the read failed; releaseErr (an
// ErrMapsNotReleased) that a map could not be shown released.
func (o *Orchestrator) inspectBackup(ctx context.Context, target InspectTarget, read func(context.Context, InspectTarget, []string) error) (readErr, releaseErr error) {
	if o.cleanup.Len() != 0 {
		// One VM's maps at a time: nothing else may be on the stack the
		// release unwinds.
		return nil, fmt.Errorf("%w: %d cleanup step(s) of something else are still registered", ErrMapsNotReleased, o.cleanup.Len())
	}
	first := len(o.record.MapIntents)
	progress.Info("Inspect", "VM %d: mapping its backup %s read-only.", target.SourceVMID, target.Snapshot)
	devices := make([]string, 0, len(target.Drives))
	for _, drive := range target.Drives {
		device, err := o.mapSourceDrive(ctx, target.SourceVMID, target.Snapshot, drive, nil, nil)
		if err != nil {
			readErr = err
			break
		}
		devices = append(devices, device)
	}
	if readErr == nil {
		progress.Info("Inspect", "VM %d: reading its OS identity, enabled services and their listen settings from the mapped disks, read-only.", target.SourceVMID)
		readErr = read(ctx, target, devices)
	}
	return readErr, o.releaseInspectionMaps(target, first)
}

// releaseInspectionMaps unwinds the cleanup stack, which holds only target's
// maps, and shows every recorded loop gone (or another file's, with nothing
// of the map left). Then, and only then, the journal forgets the maps from
// intent first on, so that the next VM's maps, which the kernel may give the
// same loop numbers, are journaled as the new maps they are.
func (o *Orchestrator) releaseInspectionMaps(target InspectTarget, first int) error {
	var problems []error
	for _, failure := range o.cleanup.Unwind() {
		problems = append(problems, fmt.Errorf("%s: %w", failure.Step, failure.Err))
	}
	if len(problems) == 0 {
		for attempt := 1; ; attempt++ {
			all, _, errs := o.verifyTrackedLoopsUnmapped()
			if all {
				break
			}
			if attempt >= loopSettleAttempts {
				problems = append(problems, errs...)
				if len(errs) == 0 {
					problems = append(problems, errors.New("a recorded PBS loop device could not be shown unmapped"))
				}
				break
			}
			time.Sleep(loopSettleInterval)
		}
	}
	if len(problems) > 0 {
		cause := errors.Join(problems...)
		progress.Error("Inspect", "VM %d: its backup maps could not be shown released; the journal keeps them for recovery: %v", target.SourceVMID, cause)
		return fmt.Errorf("%w: %w", ErrMapsNotReleased, cause)
	}
	o.record.ForgetReleasedMaps(first)
	if err := o.flushJournal(); err != nil {
		// The maps are released, but the journal on disk still records them,
		// and the next map could be given one of their loop numbers.
		return fmt.Errorf("%w: %w", ErrMapsNotReleased, err)
	}
	progress.Info("Inspect", "VM %d: released its backup maps.", target.SourceVMID)
	return nil
}

// finishInspection proves what the inspection left: nothing registered for
// cleanup, every recorded loop gone, and no map whose release failed. The
// journal is then marked cleaned; otherwise cleanup_failed, with why, and it
// keeps every recorded map for recovery, as a run's does.
func (o *Orchestrator) finishInspection(unreleased []string) InspectCleanup {
	problems := append([]string(nil), unreleased...)
	for _, failure := range o.cleanup.Unwind() {
		problems = append(problems, fmt.Sprintf("%s: %v", failure.Step, failure.Err))
	}
	if all, _, errs := o.verifyTrackedLoopsUnmapped(); !all {
		for _, err := range errs {
			problems = append(problems, err.Error())
		}
		if len(errs) == 0 {
			problems = append(problems, "a recorded PBS loop device could not be shown unmapped")
		}
	}
	if len(problems) == 0 {
		o.record.Phase = "cleaned"
		o.record.CleanupErrors = nil
	} else {
		o.record.Phase = "cleanup_failed"
		o.record.CleanupErrors = append([]string(nil), problems...)
	}
	if err := o.flushJournal(); err != nil {
		return InspectCleanup{Errors: append(problems, err.Error())}
	}
	if len(problems) > 0 {
		progress.Error("Cleanup", "The inspection's cleanup could not be fully verified (%d issue(s)); its journal is kept for recovery.", len(problems))
		return InspectCleanup{Errors: problems}
	}
	progress.Info("Cleanup", "Inspection cleanup verified: every backup map was released.")
	return InspectCleanup{Verified: true}
}
