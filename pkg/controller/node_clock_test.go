// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/nodeapi"
)

// runOnNodeWithClock runs a passing validation on a node whose clock is offset
// from the controller's (positive: ahead). The worker stamps its report with
// the node's clock, as a real one does, so the report check of the end of the
// run sees what a node with that clock would give it.
func runOnNodeWithClock(t *testing.T, offset time.Duration, configure func(*fakeCommandRunner)) (*fakeCommandRunner, *Result, string, error) {
	t.Helper()
	return runOnNodeWithClockAndRunLength(t, offset, 0, configure)
}

// runOnNodeWithClockAndRunLength is runOnNodeWithClock for a run that lasted
// runLength: the fake run takes no time, so the worker's report is stamped as a
// node whose clock is offset from the controller's would stamp it that long
// after the run began.
func runOnNodeWithClockAndRunLength(t *testing.T, offset, runLength time.Duration, configure func(*fakeCommandRunner)) (*fakeCommandRunner, *Result, string, error) {
	t.Helper()
	opts := completedWorkerTeardownOptions(t)
	report := workerReportFor(t, opts)
	report.Timestamp = time.Now().Add(offset + runLength).UTC().Format(time.RFC3339)
	fake := &fakeCommandRunner{nodeResult: nodeapi.RunResult{Report: report}, journalPhase: "cleaned", nodeClockOffset: offset}
	if configure != nil {
		configure(fake)
	}
	var progress bytes.Buffer
	opts.Writer = &progress
	result, err := (&Executor{runner: fake}).Run(context.Background(), opts)
	return fake, result, progress.String(), err
}

// startedAnything reports whether the controller did anything on the node
// beyond looking at it: it staged files, created a workspace or ran the worker.
func startedAnything(fake *fakeCommandRunner) (string, bool) {
	for _, call := range fake.calls {
		joined := call.name + " " + strings.Join(call.args, " ")
		if call.name == "scp" || strings.Contains(joined, "node-run") || strings.Contains(joined, "/workers/") {
			return joined, true
		}
	}
	return "", false
}

// A node whose clock is far ahead of the controller's would run the whole
// validation and then have its report refused for its timestamp. The clock is
// read first, and a node ahead by more than the allowance and the time the
// controller can take to check a report is refused before anything is started
// on it. A node behind is not (see
// TestNodeBehindTheControllerIsNotRefusedAndIsToldHowLongTheRunMustLast).
func TestNodeWithAClockFarAheadOfTheControllerIsRefusedBeforeTheRunStarts(t *testing.T) {
	for name, tc := range map[string]struct {
		offset time.Duration
		side   string
	}{
		"ahead":   {reportClockSkew + maxReportJudgementLag + 2*time.Minute, "ahead of"},
		"a day":   {24 * time.Hour, "ahead of"},
		"in 2100": {24 * 365 * 70 * time.Hour, "ahead of"},
	} {
		t.Run(name, func(t *testing.T) {
			fake, result, progress, err := runOnNodeWithClock(t, tc.offset, nil)
			if err == nil || result != nil {
				t.Fatalf("Run = %v, %v; want the node refused", result, err)
			}
			for _, want := range []string{"the clock of node pve-01 is about", tc.side + " the controller's", "whatever the run's length", "Nothing was started on the node", "chronyc tracking"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q lacks %q", err, want)
				}
			}
			if strings.Contains(err.Error(), "is not from this run") {
				t.Errorf("the refusal came from the report check at the end of the run, after the evidence was made: %v", err)
			}
			if command, started := startedAnything(fake); started {
				t.Errorf("the controller started something on a node it was going to refuse: %s", command)
			}
			if fake.workspaceRemoveCalls != 0 {
				t.Errorf("the controller cleaned up a workspace it never made (%d removals)", fake.workspaceRemoveCalls)
			}
			if strings.Contains(progress, "Temporary node worker staged") {
				t.Errorf("progress says the worker was staged:\n%s", progress)
			}
		})
	}
}

// A node within the allowance runs, and one that is close to it is
// told of with a warning; the end-of-run check agrees with the early one at
// both ends of the allowance.
func TestNodeWithAClockInsideTheReportAllowanceRuns(t *testing.T) {
	for name, tc := range map[string]struct {
		offset time.Duration
		warned bool
	}{
		"in step":             {0, false},
		"a minute ahead":      {time.Minute, false},
		"a minute behind":     {-time.Minute, false},
		"nearly half ahead":   {nodeClockWarning - time.Minute, false},
		"half ahead":          {nodeClockWarning + time.Minute, true},
		"just inside, ahead":  {reportClockSkew - time.Minute, true},
		"just inside, behind": {-(reportClockSkew - time.Minute), true},
	} {
		t.Run(name, func(t *testing.T) {
			_, result, progress, err := runOnNodeWithClock(t, tc.offset, nil)
			if err != nil || result == nil || result.ReportPath == "" {
				t.Fatalf("Run = %v, %v; want the validation to run and its report saved", result, err)
			}
			if warned := strings.Contains(progress, "The clock of node pve-01 is about"); warned != tc.warned {
				t.Errorf("warned = %v, want %v:\n%s", warned, tc.warned, progress)
			}
		})
	}
}

// A clock that cannot be read does not stop a run: the report check at its end
// still judges it, as before. It is said, once.
func TestNodeClockThatCannotBeReadIsSaidAndTheRunGoesOn(t *testing.T) {
	for name, configure := range map[string]func(*fakeCommandRunner){
		"the command fails":     func(f *fakeCommandRunner) { f.nodeClockError = errors.New("date: command not found") },
		"it answers text":       func(f *fakeCommandRunner) { f.nodeClockAnswer = "Wed Oct  1 02:44:16 UTC 2026" },
		"it answers nothing":    func(f *fakeCommandRunner) { f.nodeClockAnswer = " " },
		"it answers a negative": func(f *fakeCommandRunner) { f.nodeClockAnswer = "-5" },
	} {
		t.Run(name, func(t *testing.T) {
			_, result, progress, err := runOnNodeWithClock(t, 0, configure)
			if err != nil || result == nil || result.ReportPath == "" {
				t.Fatalf("Run = %v, %v; want the run to go on", result, err)
			}
			if strings.Count(progress, "found only after the run, when the report is refused") != 1 {
				t.Errorf("the unreadable clock was not said exactly once:\n%s", progress)
			}
		})
	}
	// The report check at the end still refuses what the early check could not
	// see: a node that did not answer its clock and has a wrong one.
	_, result, _, err := runOnNodeWithClock(t, reportClockSkew+5*time.Minute, func(f *fakeCommandRunner) { f.nodeClockError = errors.New("date: command not found") })
	if err == nil || result != nil || !strings.Contains(err.Error(), "is not from this run") {
		t.Fatalf("Run = %v, %v; want the report refused at the end for its timestamp", result, err)
	}
}

// A run that is cancelled while the clock is read is cancelled, not warned about.
func TestNodeClockReadEndedByCancellationEndsTheRun(t *testing.T) {
	opts := completedWorkerTeardownOptions(t)
	ctx, cancel := context.WithCancel(context.Background())
	fake := &fakeCommandRunner{nodeResult: nodeapi.RunResult{Report: workerReportFor(t, opts)}, journalPhase: "cleaned"}
	fake.nodeClockError = context.Canceled
	fake.hook = func(name, joined string) ([]byte, error, bool) {
		if strings.Contains(joined, "'/usr/bin/date'") {
			cancel()
		}
		return nil, nil, false
	}
	_, err := (&Executor{runner: fake}).Run(ctx, opts)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run = %v; want the cancellation", err)
	}
	if command, started := startedAnything(fake); started {
		t.Fatalf("the run went on after it was cancelled: %s", command)
	}
}

// The refusal is decided on what the exchange proves, not on an estimate: an
// answer that was slow in coming does not make a good clock a bad one, and a
// whole second of the node's reading is below its resolution. Only a node ahead
// by more than the allowance and the lag the controller can take is refused; a
// node behind is warned of, however far.
func TestNodeClockDifferenceIsBoundedByTheExchange(t *testing.T) {
	base := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	const limit = reportClockSkew + maxReportJudgementLag
	type exchange struct {
		reading       time.Time // the node's whole seconds
		sent, arrived time.Time
	}
	for name, tc := range map[string]struct {
		exchange
		want clockVerdict
	}{
		"in step, fast":                    {exchange{base, base, base.Add(50 * time.Millisecond)}, clockFine},
		"over the allowance, fast, ahead":  {exchange{base.Add(reportClockSkew + time.Minute), base, base.Add(50 * time.Millisecond)}, clockWarned},
		"over the allowance, fast, behind": {exchange{base.Add(-reportClockSkew - time.Minute), base, base.Add(50 * time.Millisecond)}, clockWarned},
		"a day behind":                     {exchange{base.Add(-24 * time.Hour), base, base.Add(50 * time.Millisecond)}, clockWarned},
		"a day ahead":                      {exchange{base.Add(24 * time.Hour), base, base.Add(50 * time.Millisecond)}, clockRefused},
		"half of it":                       {exchange{base.Add(nodeClockWarning + 10*time.Second), base, base.Add(50 * time.Millisecond)}, clockWarned},
		// A node ahead of the controller may be less ahead than it reads, by as
		// much as the exchange took: it read its clock at some moment of it.
		"just over the limit, a slow exchange":  {exchange{base.Add(limit + 20*time.Second), base, base.Add(time.Minute)}, clockWarned},
		"over by the estimate, not by proof":    {exchange{base.Add(limit + 50*time.Second), base, base.Add(time.Minute)}, clockWarned},
		"over by more than the exchange, ahead": {exchange{base.Add(limit + 2*time.Minute), base, base.Add(time.Minute)}, clockRefused},
		// The lowest the difference can be is the reading itself, so a reading
		// of exactly the limit is not proof of more.
		"exactly the limit":       {exchange{base.Add(limit), base, base}, clockWarned},
		"a second over the limit": {exchange{base.Add(limit + time.Second), base, base}, clockRefused},
		// The allowance alone does not refuse: the controller can take time to
		// check a report that a node ahead has stamped late.
		"just over the allowance, ahead": {exchange{base.Add(reportClockSkew + time.Second), base, base}, clockWarned},
	} {
		t.Run(name, func(t *testing.T) {
			d := nodeClockDifference(tc.reading.Unix(), tc.sent, tc.arrived)
			if got := d.judge(); got != tc.want {
				t.Errorf("judge = %d for %+v, want %d", got, d, tc.want)
			}
			if d.lowest > d.estimate || d.estimate > d.highest {
				t.Errorf("estimate %v is not between %v and %v", d.estimate, d.lowest, d.highest)
			}
		})
	}
}

// The early check and the report check at the end of a run speak of the same
// allowance, and the guides state it: Issue 6 of the troubleshooting guide and
// the limits in docs/compatibility.md give the minutes the controller allows,
// the refusal names the same number, and Issue 6 gives the command the refusal
// names to read the node's clock.
func TestNodeClockRefusalIsDocumented(t *testing.T) {
	minutes := int(reportClockSkew / time.Minute)
	refusal := nodeClockError("pve-01", "ahead of", 15*time.Hour).Error()
	if want := fmt.Sprintf("within %d min of the run", minutes); !strings.Contains(refusal, want) {
		t.Errorf("the refusal does not say %q: %s", want, refusal)
	}
	for _, page := range []string{"troubleshooting.md", "compatibility.md"} {
		data, err := os.ReadFile("../../docs/" + page)
		if err != nil {
			t.Fatal(err)
		}
		doc := strings.Join(strings.Fields(string(data)), " ")
		if want := fmt.Sprintf("%d minutes", minutes); !strings.Contains(doc, want) {
			t.Errorf("docs/%s does not state the clock allowance of %s", page, want)
		}
	}
	data, err := os.ReadFile("../../docs/troubleshooting.md")
	if err != nil {
		t.Fatal(err)
	}
	guide := string(data)
	start := strings.Index(guide, "### Issue 6:")
	if start < 0 {
		t.Fatal("docs/troubleshooting.md has no Issue 6")
	}
	issue := guide[start:]
	if end := strings.Index(issue[1:], "\n### "); end >= 0 {
		issue = issue[:end+1]
	}
	if !strings.Contains(refusal, "chronyc tracking") || !strings.Contains(issue, "`chronyc tracking`") {
		t.Errorf("the refusal and Issue 6 do not both name chronyc tracking:\n%s\n%s", refusal, issue)
	}
}
