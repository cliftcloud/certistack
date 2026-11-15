// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"fmt"

	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/progress"
	"github.com/cliftcloud/certistack/pkg/runphase"
)

// beginPhases works out the run's phases from its plan, so each can say where
// it is of how many. The controller works them out from the same plan with the
// same function for its own phase, the last one.
func (o *Orchestrator) beginPhases() {
	o.phases = runphase.NewTracker(runphase.Steps(o.plan, runphase.Options{SkipIntegrity: o.opts.SkipIntegrity}))
}

// announcePhase says that a phase of the run begins, as one progress line
// under the stage "Phase N of M". id is the VM's ID for a phase of one VM and
// the tier's level for a phase of a tier. A phase the run's list does not have
// (a restore driven on its own, as a test does, has no list) says nothing: no
// number is made up.
func (o *Orchestrator) announcePhase(kind runphase.Kind, id int, note string) {
	announcement, ok := o.phases.Begin(kind, id)
	if !ok {
		return
	}
	if o.phaseFn != nil {
		o.phaseFn(announcement.Stage(), announcement.Message(note))
		return
	}
	progress.Info(announcement.Stage(), "%s", announcement.Message(note))
}

// scanTotal is the length of a restored disk as far as the plan can tell before
// the scan: the size the snapshot's manifest records, else the backup
// configuration's. 0 is not known.
func scanTotal(vmCfg config.VM, slot string) int64 {
	if n, ok := sourceDiskLength(vmCfg, slot); ok && n > 0 {
		return n
	}
	return 0
}

// scanSizeNote is how much the VM's integrity scan has to read, for the line
// that begins the phase: the lengths of all its disks added up, or nothing when
// the length of any of them is not known.
func scanSizeNote(vmCfg config.VM, slots []string) string {
	var total int64
	for _, slot := range slots {
		n := scanTotal(vmCfg, slot)
		if n == 0 {
			return ""
		}
		total += n
	}
	if total == 0 {
		return ""
	}
	return runphase.FormatSize(total) + " to read"
}

// scanReporter is the progress callback of the scan of one disk: it says, at each
// gibibyte, how much is verified and, as far as it can be told, of how much and
// about how long is left.
func (o *Orchestrator) scanReporter(vmCfg config.VM, slot string, withCopy bool) func(int64) {
	estimator := runphase.NewScanEstimator(scanTotal(vmCfg, slot), o.scanClock)
	return func(bytesVerified int64) {
		progress.Info("Storage", "%s", scanProgressLine(vmCfg.VMID, withCopy, bytesVerified, estimator.Observe(bytesVerified)))
	}
}

// scanProgressLine is the line a scan reports. What it said before the size and
// the time left were added is its start, word for word ("VM 9100 full
// mapped-image integrity scan: 7 GiB verified"), because the lab's tools read
// the scan's progress from it; what is known of the size and the time left is
// said after it.
func scanProgressLine(vmid int, withCopy bool, bytesVerified int64, p runphase.ScanProgress) string {
	what := "full mapped-image integrity scan"
	if withCopy {
		what += " and copy"
	}
	return fmt.Sprintf("VM %d %s: %d GiB verified%s.", vmid, what, bytesVerified>>30, p.Suffix())
}
