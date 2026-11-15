// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/config"
)

// A node behind the controller stamps its report early by its lag, and the run's
// length brings the stamp back, so the end check accepts the report of a run that
// lasts longer than the lag less the allowance. The early check refused such a
// node outright, and the run that would have been signed was never made. It warns
// instead, with the length of run the node needs, and the check at the end
// decides.
func TestNodeBehindTheControllerIsNotRefusedAndIsToldHowLongTheRunMustLast(t *testing.T) {
	// The verifier's case: 12 minutes behind and a run of a few minutes.
	_, result, _, err := runOnNodeWithClockAndRunLength(t, -(reportClockSkew + 2*time.Minute), 3*time.Minute, nil)
	if err != nil || result == nil || result.ReportPath == "" {
		t.Fatalf("a node 12 min behind with a run of 3 min: Run = %v, %v; want the report signed and saved", result, err)
	}

	const lag = reportClockSkew + 20*time.Minute // 30 min behind
	// A run that is too short for that lag still ends with the report refused:
	// it was said so before the run began.
	fake, result, progress, err := runOnNodeWithClock(t, -lag, nil)
	if err == nil || result != nil || !strings.Contains(err.Error(), "is not from this run") {
		t.Fatalf("a node 30 min behind with a run of no length: Run = %v, %v; want the report refused at the end", result, err)
	}
	for _, want := range []string{"The clock of node pve-01 is about 30 min behind the controller's", "accepted only if the run lasts at least about 20 min", "a shorter run ends with its report refused and no evidence written"} {
		if !strings.Contains(progress, want) {
			t.Errorf("the warning lacks %q:\n%s", want, progress)
		}
	}
	if _, started := startedAnything(fake); !started {
		t.Error("the node was refused before the run: a node behind is warned of, and the end check decides")
	}

	// A run that lasts long enough is accepted by the end check, and signed. (The
	// fake run takes no time, so the controller's clock at the check stays at the
	// start; the property test below lets the run and the check move.)
	for name, length := range map[string]time.Duration{"just long enough": lag - reportClockSkew + time.Minute, "longer": 35 * time.Minute} {
		_, result, _, err := runOnNodeWithClockAndRunLength(t, -lag, length, nil)
		if err != nil || result == nil || result.ReportPath == "" {
			t.Errorf("%s (%s): Run = %v, %v; want the report signed and saved", name, length, result, err)
		}
	}

	// A day behind is still not refused: no run has a length the controller
	// knows in advance, and a soak alone may take days.
	_, _, progress, err = runOnNodeWithClock(t, -24*time.Hour, nil)
	if err == nil || strings.Contains(err.Error(), "Nothing was started on the node") {
		t.Fatalf("a node a day behind: err = %v; want the run to start and the end check to refuse its report", err)
	}
	if !strings.Contains(progress, "accepted only if the run lasts at least about 1430 min") {
		t.Errorf("the warning does not say how long the run must last:\n%s", progress)
	}
}

// A node ahead by more than the allowance is warned of, not refused, until it
// is ahead by more than the allowance and the time the controller can take to
// check a report: it is saved only by the controller being slow, and the
// warning says so.
func TestNodeAheadWithinTheJudgementLagIsWarnedNotRefused(t *testing.T) {
	_, result, progress, err := runOnNodeWithClock(t, reportClockSkew+2*time.Minute, nil)
	if err == nil || result != nil || !strings.Contains(err.Error(), "is not from this run") {
		t.Fatalf("Run = %v, %v; want the report refused at the end for a node 12 min ahead", result, err)
	}
	for _, want := range []string{"The clock of node pve-01 is about 12 min ahead of the controller's", "more than the 10 min a report's timestamp may be ahead of the run", "unless the controller takes more than about 2 min to check it after the node stamps it"} {
		if !strings.Contains(progress, want) {
			t.Errorf("the warning lacks %q:\n%s", want, progress)
		}
	}
}

// The early check and the report check at the end of the run are one rule seen
// from two sides, and they drifted once: the early check refused nodes the end
// check would have accepted. This holds them together on the real end check
// (checkWorkerReport): across node clocks from two days behind to two days
// ahead, run lengths from nothing to a week, and every time the controller may
// take to check a report, the early check
//
//   - never refuses a node whose report the end check accepts in any of them
//     (it would refuse a run that could have been signed),
//   - refuses every node ahead by more than the end check can ever accept, so
//     that it still saves the run it can, and
//   - never leaves a node whose report a run of no length would see refused
//     without a warning.
func TestEarlyClockCheckNeverRefusesWhatTheReportCheckCouldAccept(t *testing.T) {
	if maxReportJudgementLag < interruptionCleanupTimeout {
		t.Fatalf("maxReportJudgementLag %s is less than the %s the controller may spend verifying the journal before it checks the report", maxReportJudgementLag, interruptionCleanupTimeout)
	}
	opts := completedWorkerTeardownOptions(t)
	plan, err := config.LoadFromFile(opts.PlanPath)
	if err != nil {
		t.Fatal(err)
	}
	report := workerReportFor(t, opts)
	report.RunID = "run-property"
	start := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC) // the controller's clock at the start and at the reading

	// endCheckAccepts is the end-of-run check on the report of a run that lasted
	// runLength, by a node whose clock is offset from the controller's, judged
	// lag after it was stamped.
	endCheckAccepts := func(offset, runLength, lag time.Duration) bool {
		stamped := *report
		stamped.Timestamp = start.Add(runLength + offset).Format(time.RFC3339)
		err := checkWorkerReport(&stamped, reportExpectation{plan: plan, node: opts.NodeName, runID: "run-property", startedAt: start, now: start.Add(runLength + lag)})
		switch {
		case err == nil:
			return true
		case strings.Contains(err.Error(), "is not from this run"):
			return false
		}
		t.Fatalf("the report was refused for something other than its timestamp: %v", err)
		return false
	}

	limit := reportClockSkew + maxReportJudgementLag
	offsets := []time.Duration{-48 * time.Hour, -3 * time.Hour, -41 * time.Minute, -31 * time.Minute, -21 * time.Minute, -11 * time.Minute, -10*time.Minute - 5*time.Second,
		-9 * time.Minute, -time.Minute, 0, time.Minute, 9 * time.Minute, 10 * time.Minute, 10*time.Minute + 5*time.Second, 11 * time.Minute, 21 * time.Minute, 31 * time.Minute,
		limit - 10*time.Second, limit + 10*time.Second, limit + 5*time.Minute, 3 * time.Hour, 48 * time.Hour}
	runLengths := []time.Duration{0, time.Minute, 5 * time.Minute, 30 * time.Minute, 3 * time.Hour, 7 * 24 * time.Hour}
	lags := []time.Duration{0, 10 * time.Second, 5 * time.Minute, maxReportJudgementLag}

	for _, offset := range offsets {
		verdict := nodeClockDifference(start.Add(offset).Unix(), start, start).judge()
		accepted := ""
		for _, runLength := range runLengths {
			for _, lag := range lags {
				if accepted == "" && endCheckAccepts(offset, runLength, lag) {
					accepted = "a run of " + runLength.String() + " checked " + lag.String() + " after the stamp"
				}
			}
		}
		if verdict == clockRefused && accepted != "" {
			t.Errorf("a node %s from the controller is refused before the run, and the end check accepts its report after %s", offset, accepted)
		}
		if offset > limit && verdict != clockRefused {
			t.Errorf("a node %s ahead, more than the end check can accept after any wait, is not refused (verdict %d)", offset, verdict)
		}
		if offset > limit && accepted != "" {
			t.Errorf("a node %s ahead has its report accepted after %s: the limit the early check refuses at is too low", offset, accepted)
		}
		if !endCheckAccepts(offset, 0, 0) && verdict == clockFine {
			t.Errorf("a node %s from the controller would see a run of no length end with its report refused, and the early check says nothing", offset)
		}
		if offset < 0 && verdict == clockRefused {
			t.Errorf("a node %s behind is refused before a run whose length is unknown", offset)
		}
	}
}

// A plan is what a run would do, so it reads the node's clock as a run does: a
// node a run would refuse before it started is refused by the plan, and a node
// whose clock a run warns of is warned of, on the plan's writer.
func TestPlanReadsTheNodesClockAsRunDoes(t *testing.T) {
	t.Setenv("PVE_URL", "https://pve.example:8006")
	t.Setenv("PVE_TOKEN_ID", "certistack@pve!automation")
	t.Setenv("PVE_TOKEN_SECRET", "pve-secret")
	t.Setenv("PBS_REPOSITORY", "backup@pbs!read@pbs.example:8007:datastore")
	t.Setenv("PBS_PASSWORD", "pbs-secret")
	opts := completedWorkerTeardownOptions(t)

	plan := func(offset time.Duration, configure func(*fakeCommandRunner)) (*fakeCommandRunner, string, []byte, error) {
		fake := &fakeCommandRunner{nodePlanOutput: `{"plan_id":"acme-erp-full-stack-dr","node":"pve-01","steps":[]}`, nodeClockOffset: offset}
		if configure != nil {
			configure(fake)
		}
		var progress bytes.Buffer
		planOpts := opts
		planOpts.Writer = &progress
		output, err := (&Executor{runner: fake}).Plan(context.Background(), planOpts)
		return fake, progress.String(), output, err
	}

	// In step: the plan is made, and nothing is said.
	fake, progress, output, err := plan(0, nil)
	if err != nil || len(output) == 0 || strings.Contains(progress, "clock of node") {
		t.Fatalf("a node in step: err = %v, output %q, progress %q", err, output, progress)
	}
	readClock := false
	for _, call := range fake.calls {
		if strings.Contains(strings.Join(call.args, " "), "'/usr/bin/date'") {
			readClock = true
		}
	}
	if !readClock {
		t.Error("plan never read the node's clock")
	}

	// Far ahead: no plan is made, and nothing was staged.
	fake, _, output, err = plan(reportClockSkew+maxReportJudgementLag+5*time.Minute, nil)
	if err == nil || len(output) != 0 || !strings.Contains(err.Error(), "Nothing was started on the node") {
		t.Fatalf("a node far ahead: err = %v, output %q; want it refused as a run would", err, output)
	}
	if command, started := startedAnything(fake); started {
		t.Errorf("plan staged something on a node it refused: %s", command)
	}

	// Behind: warned, as a run warns, and the plan is made.
	_, progress, output, err = plan(-(reportClockSkew + 5*time.Minute), nil)
	if err != nil || len(output) == 0 || !strings.Contains(progress, "accepted only if the run lasts at least about 5 min") {
		t.Fatalf("a node behind: err = %v, output %q, progress %q", err, output, progress)
	}

	// A clock that cannot be read is said, and the plan goes on.
	_, progress, output, err = plan(0, func(f *fakeCommandRunner) { f.nodeClockError = errors.New("date: command not found") })
	if err != nil || len(output) == 0 || !strings.Contains(progress, "Could not read the clock of node pve-01") {
		t.Fatalf("an unreadable clock: err = %v, output %q, progress %q", err, output, progress)
	}
}

// The guide says what the early check does on each side, in the words of the
// warning a node behind is given, so the two cannot disagree again.
func TestNodeClockLagIsDocumentedOnBothSides(t *testing.T) {
	data, err := os.ReadFile("../../docs/troubleshooting.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := strings.Join(strings.Fields(string(data)), " ")
	behind := nodeClockWarningText("pve-01", "behind", -30*time.Minute)
	for _, quoted := range []string{
		"accepted only if the run lasts at least about",
		"a shorter run ends with its report refused and no evidence written",
	} {
		if !strings.Contains(behind, quoted) {
			t.Errorf("the warning no longer says %q: %s", quoted, behind)
		}
		if !strings.Contains(doc, quoted) {
			t.Errorf("docs/troubleshooting.md does not quote %q", quoted)
		}
	}
	for _, want := range []string{
		"A node **behind** the controller is never refused first, however far",
		"A node **ahead** of the controller by more than 10 minutes plus the time the controller can take between the stamp and the check",
		"`certistack plan` reads it too",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("docs/troubleshooting.md no longer says %q", want)
		}
	}
}
