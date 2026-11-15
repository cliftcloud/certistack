// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// nodeClockWarning is how far the node's clock may be from the controller's
// before the controller says so, short of refusing: half of what a report's
// timestamp is allowed (reportClockSkew).
const nodeClockWarning = reportClockSkew / 2

// maxReportJudgementLag is the longest the controller can take, after the
// worker has stamped its report, to judge it: the worker ends, the controller
// reads its result and verifies the run's journal on the node, which is bounded
// by interruptionCleanupTimeout, and only then holds the report to the
// allowance (checkWorkerReport). Ten minutes are added for the SSH commands
// around those. A node's clock that is ahead is saved by this lag and no more:
// see judge.
const maxReportJudgementLag = interruptionCleanupTimeout + 10*time.Minute

// checkNodeClock reads the node's clock before anything is staged on the node
// and refuses a node whose report the check at the end of the run
// (checkWorkerReport) is sure to refuse. That check accepts a report whose
// timestamp is no earlier than the controller's start less the allowance and
// no later than the moment of the check plus the allowance, and the worker
// stamps its report as its run ends, on the node's clock. A node whose clock is
// off used to run the whole validation and then have its evidence discarded,
// unsigned, with the node's workspace. Reading the clock first finds that out
// before the run costs anything, where it can be known.
//
// What can be known depends on the side. A node AHEAD of the controller by
// more than the allowance stamps its report in the future whatever the run
// length, and only the time the controller takes between the stamp and the
// check can save it (maxReportJudgementLag): beyond both, the run is refused. A
// node BEHIND stamps its report early by its lag, and the run's own length
// brings the stamp back: its report is accepted when the run lasts longer than
// the lag less the allowance. No run has a length the controller knows in
// advance (a soak may last days, and mapping and integrity scans have no
// timeout), so a node behind is never refused here: the length of run it would
// need is said, and the check at the end decides. This check adds a refusal only
// where the end check cannot accept, and removes none.
//
// The reading is made to tell a clock that is wrong from one that is merely
// read late, so it refuses only when the node's clock is beyond the limit
// whatever the delay of the SSH exchange was. A reading that cannot be made or
// understood is said and the run goes on, to be judged by the report check as
// before.
func (e *Executor) checkNodeClock(ctx context.Context, cfg SSHConfig, node string, progress *progressReporter) error {
	before := time.Now()
	output, err := e.remoteSetupCommand(ctx, cfg, []string{"/usr/bin/date", "-u", "+%s"})
	after := time.Now()
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		progress.warning("Could not read the clock of node %s (%s), so a clock that is more than %s from the controller's is found only after the run, when the report is refused.", node, sshReason(err), roughly(reportClockSkew))
		return nil
	}
	reading, parseErr := strconv.ParseInt(strings.TrimSpace(string(output)), 10, 64)
	if parseErr != nil || reading <= 0 {
		progress.warning("The clock of node %s answered %q, which is not a time, so a clock that is more than %s from the controller's is found only after the run, when the report is refused.", node, boundedText(string(output)), roughly(reportClockSkew))
		return nil
	}
	skew := nodeClockDifference(reading, before, after)
	side := "ahead of"
	if skew.estimate < 0 {
		side = "behind"
	}
	switch skew.judge() {
	case clockRefused:
		return nodeClockError(node, side, skew.estimate)
	case clockWarned:
		progress.warning("%s", nodeClockWarningText(node, side, skew.estimate))
	}
	return nil
}

// nodeClockWarningText says what a clock that is off will do to this run's
// report, exactly: past the allowance on the ahead side the report is refused
// unless the controller is slow to check it, and on the behind side only a run
// of enough length is accepted.
func nodeClockWarningText(node, side string, estimate time.Duration) string {
	off := absDuration(estimate)
	fix := "set the node's time from a reliable source (chronyc tracking on the node)"
	switch {
	case estimate > reportClockSkew:
		return fmt.Sprintf("The clock of node %s is about %s %s the controller's, more than the %s a report's timestamp may be ahead of the run, so this run's report is refused unless the controller takes more than about %s to check it after the node stamps it: %s.",
			node, roughly(off), side, roughly(reportClockSkew), roughly(off-reportClockSkew), fix)
	case estimate < -reportClockSkew:
		return fmt.Sprintf("The clock of node %s is about %s %s the controller's. The node stamps its report when the run ends, and a report is accepted only when its timestamp is within %s of the run on the controller's clock, so this run's report is accepted only if the run lasts at least about %s; a shorter run ends with its report refused and no evidence written: %s.",
			node, roughly(off), side, roughly(reportClockSkew), roughly(off-reportClockSkew), fix)
	}
	return fmt.Sprintf("The clock of node %s is about %s %s the controller's. A report is refused when its timestamp is more than %s from the run: %s.", node, roughly(off), side, roughly(reportClockSkew), fix)
}

// clockDifference is the node's clock less the controller's: estimate at the
// middle of the exchange, and the bounds that hold whatever the delay was.
type clockDifference struct {
	estimate, lowest, highest time.Duration
}

// clockVerdict is what a clock difference calls for.
type clockVerdict int

const (
	clockFine clockVerdict = iota
	clockWarned
	clockRefused
)

// judge refuses a node that is ahead by more than the allowance and the lag
// the controller can take to check a report (reportClockSkew and
// maxReportJudgementLag), on every reading the exchange allows: nothing a run
// can do brings such a report back inside the allowance. It does not refuse a
// node that is behind, however far: a run that lasts that long, less the
// allowance, is accepted by the check at the end. It warns of a difference of
// half the allowance or more on either side.
func (d clockDifference) judge() clockVerdict {
	switch {
	case d.lowest > reportClockSkew+maxReportJudgementLag:
		return clockRefused
	case d.estimate >= nodeClockWarning, d.estimate <= -nodeClockWarning:
		return clockWarned
	}
	return clockFine
}

// nodeClockDifference is how far the node's clock was from the controller's,
// given the node's reading in whole seconds (date +%s drops the fraction) and
// the controller's clock before the request was sent and after the answer came
// back. The node read its clock at some moment between the two; the lowest the
// difference can be is that moment being the last one and the reading the
// least it could be, and the highest is the opposite.
func nodeClockDifference(reading int64, before, after time.Time) clockDifference {
	node := time.Unix(reading, 0)
	return clockDifference{
		estimate: node.Add(500 * time.Millisecond).Sub(before.Add(after.Sub(before) / 2)),
		lowest:   node.Sub(after),
		highest:  node.Add(time.Second).Sub(before),
	}
}

func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

func nodeClockError(node, side string, by time.Duration) error {
	return fmt.Errorf("the clock of node %s is about %s %s the controller's, and a report is accepted only when its timestamp is within %s of the run on the controller's clock. The node stamps its report as its run ends and the controller checks it within about %s of that, so a node this far ahead has its report refused whatever the run's length: this run would end with its report refused and no evidence written. Nothing was started on the node. Set the node's time from a reliable source (chronyc tracking on the node), or correct the controller's clock, and run again",
		node, roughly(absDuration(by)), side, roughly(reportClockSkew), roughly(maxReportJudgementLag))
}
