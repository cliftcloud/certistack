// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/probe"
	"github.com/cliftcloud/certistack/pkg/progress"
)

// soakSampleInterval is the cadence of the service checks in a tier's soak: 30
// seconds after the end of the previous check, and one more when the soak's
// period ends. A check is one run of every service probe of the VM
// under the policy the plan gives it, so a probe that polls or retries inside
// its own timeout_sec does so in a check too, and a check that takes longer
// than the interval is followed at once by the next, never by one that
// overlaps it. The period is a floor, not a ceiling: the last check starts when
// the period is over and may end after it.
var soakSampleInterval = 30 * time.Second

// tierVMRun is a VM of the tier being run that passed its restore: the plan's
// VM, where its record is in the result, and the results its probe stage
// recorded, which the soak compares its own checks with.
type tierVMRun struct {
	config      config.VM
	recordIndex int
	results     []probe.Result
}

// soakTracker accumulates one VM's soak summary (probe.SoakEvidence) as its
// service checks run. It keeps counts and the slowest duration, never the
// checks themselves, so a seven-day soak is as small as a one-minute one.
type soakTracker struct {
	// vm is the planned VM reduced to its service probes (the wire probes and
	// the guest-agent probes; config.IsGuestLevelProbe), in plan order.
	vm       config.VM
	started  time.Time
	baseline []probe.Result
	evidence probe.SoakEvidence
}

// newSoakTracker starts the summary of the VM's soak, or returns nil for a VM
// with no service probe to repeat.
func newSoakTracker(run tierVMRun, soakSec int, started time.Time) *soakTracker {
	tracker := &soakTracker{vm: run.config, started: started}
	tracker.vm.Probes = nil
	for index, configured := range run.config.Probes {
		if !config.IsGuestLevelProbe(configured.Type) {
			continue
		}
		tracker.vm.Probes = append(tracker.vm.Probes, configured)
		row := probe.SoakProbeEvidence{Probe: index + 1, Type: configured.Type, Description: configured.Description}
		var stage probe.Result
		if index < len(run.results) {
			stage = run.results[index]
			// The record's own result is what the report holds the row to.
			row.Type, row.Description = stage.Type, stage.Description
		}
		tracker.baseline = append(tracker.baseline, stage)
		tracker.evidence.Probes = append(tracker.evidence.Probes, row)
	}
	if len(tracker.vm.Probes) == 0 {
		return nil
	}
	tracker.evidence.ConfiguredSec = soakSec
	tracker.evidence.IntervalSec = soakIntervalSec()
	tracker.evidence.StartedAt = soakStamp(started, started)
	return tracker
}

// soakIntervalSec is the cadence in whole seconds, rounded up, so a summary
// never records a zero interval.
func soakIntervalSec() int {
	return int((soakSampleInterval + time.Second - 1) / time.Second)
}

// soakStamp is the RFC 3339 UTC time `at` elapsed after the soak began,
// computed from the monotonic clock so that a step of the wall clock during
// a long soak cannot make a check look earlier than the soak's own start.
func soakStamp(started, at time.Time) string {
	return started.Add(at.Sub(started)).UTC().Format(time.RFC3339)
}

// record adds one finished check to the summary and returns why it failed, or
// nil. results are the check's probe results in the order of tracker.vm.Probes
// and err what runProbeSet returned.
func (t *soakTracker) record(at time.Time, results []probe.Result, err error) error {
	stamp := soakStamp(t.started, at)
	if t.evidence.Samples == 0 {
		t.evidence.FirstSampleAt = stamp
	}
	t.evidence.LastSampleAt = stamp
	t.evidence.Samples++

	var failures []error
	for index := range t.evidence.Probes {
		row := &t.evidence.Probes[index]
		var cause string
		switch {
		case index >= len(results):
			// The check ended before it reached this probe: the VM stopped, or
			// the run was told to.
			cause = "the check ended before this probe ran"
			if err != nil {
				cause += ": " + err.Error()
			}
		case results[index].Skipped && t.baseline[index].Skipped:
			row.Skipped++
		case results[index].Skipped:
			cause = "the guest agent answered in the probe stage and did not answer in this check"
		case !results[index].Passed:
			cause = results[index].Error
			if cause == "" {
				cause = "the probe failed"
			}
		default:
			row.Passed++
		}
		if index < len(results) {
			row.WorstDuration = max(row.WorstDuration, results[index].Duration)
		}
		if cause == "" {
			continue
		}
		row.Failed++
		if row.FirstError == "" {
			row.FirstError = boundedSoakError(cause)
		}
		failures = append(failures, fmt.Errorf("probe %q: %s", t.evidence.Probes[index].Description, boundedSoakError(cause)))
	}
	if len(failures) == 0 && err != nil {
		// runProbeSet refused the check as a whole (for example, nothing in the
		// guest was asserted) without any probe failing: the first probe carries it.
		row := &t.evidence.Probes[0]
		if row.Passed > 0 {
			row.Passed--
		} else {
			row.Skipped--
		}
		row.Failed++
		if row.FirstError == "" {
			row.FirstError = boundedSoakError(err.Error())
		}
		failures = append(failures, err)
	}
	if len(failures) == 0 {
		return nil
	}
	t.evidence.FailedSamples++
	return fmt.Errorf("service check %d of the soak failed: %w", t.evidence.Samples, errors.Join(failures...))
}

// summary is the soak summary as it stands.
func (t *soakTracker) summary() *probe.SoakEvidence {
	summary := t.evidence
	summary.Probes = append([]probe.SoakProbeEvidence(nil), t.evidence.Probes...)
	return &summary
}

// boundedSoakError cuts a failure text to what a summary keeps, at a rune
// boundary.
func boundedSoakError(text string) string {
	if len(text) <= attest.MaxSoakErrorBytes {
		return text
	}
	cut := attest.MaxSoakErrorBytes - 3
	for cut > 0 && text[cut]&0xC0 == 0x80 {
		cut--
	}
	return text[:cut] + "..."
}

// soakCheck runs one service check of a VM and records it. A check that the
// run's own interruption ended is not a failed service, so it is not recorded.
func (o *Orchestrator) soakCheck(ctx context.Context, tracker *soakTracker) error {
	at := time.Now()
	results, _, err := o.runProbeSet(ctx, tracker.vm, true)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return tracker.record(at, results, err)
}

// soakTier holds the tier's passing VMs for its soak period and, while it
// does, checks that their services keep answering: every
// soakSampleInterval, and once more when the period is over, it runs each
// VM's service probes again. A VM that stops, or that fails a service check,
// fails the soak; it is dropped from the checks and the others
// go on to the end of the period. The returned maps hold, by VMID, the VMs
// that failed (with why) and the summary of every VM that was checked; the
// error is the run's interruption.
func (o *Orchestrator) soakTier(ctx context.Context, tier config.Tier, runs []tierVMRun) (map[int]error, map[int]*probe.SoakEvidence, error) {
	started := time.Now()
	trackers := make(map[int]*soakTracker, len(runs))
	vmids := make([]int, len(runs))
	for i, run := range runs {
		vmids[i] = run.config.VMID
		if tracker := newSoakTracker(run, tier.SoakTimeSec, started); tracker != nil {
			trackers[run.config.VMID] = tracker
		}
	}
	check := func(ctx context.Context, vmid int) error {
		tracker := trackers[vmid]
		if tracker == nil {
			return nil
		}
		failure := o.soakCheck(ctx, tracker)
		if failure == nil {
			slog.Info("soak service check passed", "vmid", vmid, "check", tracker.evidence.Samples)
		}
		return failure
	}
	failed, observations, err := o.watchVMs(ctx, time.Duration(tier.SoakTimeSec)*time.Second, vmids, check)
	evidence := make(map[int]*probe.SoakEvidence, len(trackers))
	for vmid, tracker := range trackers {
		summary := tracker.summary()
		soakStatus(summary, observations[vmid])
		evidence[vmid] = summary
		if _, stopped := failed[vmid]; !stopped && err == nil {
			progress.Info("Sandbox", "VM %d: %d service check(s) during the soak, none failed (slowest %s); %d of %d status read(s) of the VM failed.", vmid, summary.Samples, soakWorst(tracker), summary.StatusReadFailures, summary.StatusReads)
		}
	}
	return failed, evidence, err
}

func soakWorst(tracker *soakTracker) time.Duration {
	var worst time.Duration
	for _, row := range tracker.evidence.Probes {
		worst = max(worst, row.WorstDuration)
	}
	return worst.Round(time.Millisecond)
}
