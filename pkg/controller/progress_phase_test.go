// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/nodeapi"
	progresspkg "github.com/cliftcloud/certistack/pkg/progress"
	"github.com/cliftcloud/certistack/pkg/runphase"
)

// workerEvent is one line of a worker's progress stream.
func workerEvent(t *testing.T, stage, message string) []byte {
	t.Helper()
	line, err := progresspkg.Encode(progresspkg.Event{Level: "INFO", Stage: stage, Message: message})
	if err != nil {
		t.Fatal(err)
	}
	return line
}

func heartbeat(reporter *progressReporter) string {
	reporter.mu.Lock()
	defer reporter.mu.Unlock()
	return reporter.heartbeatMessageLocked()
}

// The heartbeat of a phase says how long the phase has been going, which is the
// one time the controller can give for work it cannot see into: it does not say
// how long is left. The line it repeats keeps its words.
func TestHeartbeatSaysHowLongThePhaseHasBeenGoing(t *testing.T) {
	const guestStep = "VM 9100: Detecting the guest network manager from the disposable overlay."
	for _, test := range []struct {
		name         string
		stage, text  string
		phase        string
		phaseRunning time.Duration
		want         string
	}{
		{"a step of the phase", "Sandbox", guestStep, "Phase 4 of 9", 129 * time.Second,
			"Still working: [Sandbox] " + guestStep + " (2m09s so far in Phase 4 of 9)"},
		{"the phase's own line", "Phase 5 of 9", "Integrity scan for VM 9100 (web): 12 GiB to read", "Phase 5 of 9", 45 * time.Second,
			"Still working: [Phase 5 of 9] Integrity scan for VM 9100 (web): 12 GiB to read (45s so far)"},
		{"a scan's report loses the time it said was left", "Storage", "VM 9100 full mapped-image integrity scan: 7 GiB verified of 12 GiB (58%), about 1 min left.", "Phase 5 of 9", 70 * time.Second,
			"Still working: [Storage] VM 9100 full mapped-image integrity scan: 7 GiB verified of 12 GiB (58%). (1m10s so far in Phase 5 of 9)"},
		{"an hour into a soak", "Sandbox", "VM 9100: 6 service check(s) during the soak.", "Phase 8 of 9", time.Hour + 2*time.Minute + 9*time.Second,
			"Still working: [Sandbox] VM 9100: 6 service check(s) during the soak. (1h02m09s so far in Phase 8 of 9)"},
		{"before the first phase", "Sandbox", guestStep, "", 0,
			"Still working: [Sandbox] " + guestStep},
		{"a line with no stage", "", "Waiting 180s for guest services to stabilize.", "Phase 6 of 9", 20 * time.Second,
			"Still working: Waiting 180s for guest services to stabilize. (20s so far in Phase 6 of 9)"},
	} {
		t.Run(test.name, func(t *testing.T) {
			reporter := newProgressReporter(&bytes.Buffer{})
			defer reporter.close()
			reporter.lastStage, reporter.lastMessage = test.stage, test.text
			if test.phase != "" {
				reporter.phaseStage, reporter.phaseStarted = test.phase, time.Now().Add(-test.phaseRunning)
			}
			if got := heartbeat(reporter); got != test.want {
				t.Errorf("heartbeat:\n got %q\nwant %q", got, test.want)
			}
		})
	}
	t.Run("nothing said yet", func(t *testing.T) {
		reporter := newProgressReporter(&bytes.Buffer{})
		defer reporter.close()
		reporter.phaseStage, reporter.phaseStarted = "Phase 4 of 9", time.Now()
		if got, want := heartbeat(reporter), "Still working on the node worker; no action is required."; got != want {
			t.Errorf("heartbeat = %q, want %q", got, want)
		}
	})
}

// The reporter knows a phase has begun from the worker's event under its stage,
// and from nothing else: a stage that only looks like one, or a worker line
// that is not an event, does not move it.
func TestReporterNotesWhenAPhaseBegan(t *testing.T) {
	var out bytes.Buffer
	reporter := newProgressReporter(&out)
	write := func(stage, message string) {
		t.Helper()
		if _, err := reporter.Write(workerEvent(t, stage, message)); err != nil {
			t.Fatal(err)
		}
	}
	phaseOf := func() string {
		reporter.mu.Lock()
		defer reporter.mu.Unlock()
		return reporter.phaseStage
	}

	write("Sandbox", "Checking COW-only guest network recovery support on the node worker.")
	if got := phaseOf(); got != "" {
		t.Errorf("a step before any phase set the phase %q", got)
	}
	write("Phase 4 of 9", "Guest network preparation for VM 9100 (web): offline image work, often several minutes on a small or nested host")
	if got := phaseOf(); got != "Phase 4 of 9" {
		t.Errorf("phase = %q after the phase's event", got)
	}
	write("Sandbox", "VM 9100: Detecting the guest network manager from the disposable overlay.")
	write("Phase 4 of 9 and some more", "an event that only looks like a phase")
	write("Phase four", "an event that only looks like a phase")
	if got := phaseOf(); got != "Phase 4 of 9" {
		t.Errorf("phase = %q after steps and stages that are not a phase's", got)
	}
	write("Phase 5 of 9", "Integrity scan for VM 9100 (web): 12 GiB to read")
	if got := phaseOf(); got != "Phase 5 of 9" {
		t.Errorf("phase = %q after the next phase", got)
	}
	if err := reporter.close(); err != nil {
		t.Fatal(err)
	}
	// Every phase line is shown as any other event: time, level, stage, text.
	for _, want := range []string{
		"INFO [Phase 4 of 9] Guest network preparation for VM 9100 (web): offline image work, often several minutes on a small or nested host\n",
		"INFO [Phase 5 of 9] Integrity scan for VM 9100 (web): 12 GiB to read\n",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the output lacks %q:\n%s", want, out.String())
		}
	}
}

// The controller's own phase is shown under its stage and counts as the phase
// that began last.
func TestControllersOwnPhaseIsShownAndNoted(t *testing.T) {
	var out bytes.Buffer
	reporter := newProgressReporter(&out)
	announcement, ok := runphase.NewTracker(runphase.Steps(&config.Plan{}, runphase.Options{})).Begin(runphase.Signing, 0)
	if !ok {
		t.Fatal("no signing phase")
	}
	reporter.phase(announcement, "")
	if got := heartbeat(reporter); !strings.HasPrefix(got, "Still working: [Phase 4 of 4] Journal check and report (") || !strings.HasSuffix(got, " so far)") {
		t.Errorf("heartbeat = %q", got)
	}
	if err := reporter.close(); err != nil {
		t.Fatal(err)
	}
	if want := "INFO [Phase 4 of 4] Journal check and report\n"; !strings.HasSuffix(out.String(), want) {
		t.Errorf("output = %q, want it to end %q", out.String(), want)
	}
}

// Through a whole run: the controller's last phase is announced before it checks
// the node's journal and signs, and it is the last of the plan's phases, the
// same count the node worker makes of the plan it is sent.
func TestARunEndsWithItsSigningPhase(t *testing.T) {
	for name, skipIntegrity := range map[string]bool{"a full run": false, "test mode": true} {
		t.Run(name, func(t *testing.T) {
			opts := completedWorkerTeardownOptions(t)
			t.Setenv("CERTISTACK_ALLOW_TEST_MODE", "1")
			opts.SkipIntegrity = skipIntegrity
			report := workerReportFor(t, opts)
			fake := &fakeCommandRunner{nodeResult: nodeapi.RunResult{Report: report}, journalPhase: "cleaned"}
			var progress bytes.Buffer
			opts.Writer = &progress
			result, err := (&Executor{runner: fake}).Run(t.Context(), opts)
			if err != nil || result == nil || result.ReportPath == "" {
				t.Fatalf("Run = %v, %v", result, err)
			}

			plan, err := config.LoadFromFile(opts.PlanPath)
			if err != nil {
				t.Fatal(err)
			}
			total := len(runphase.Steps(plan, runphase.Options{SkipIntegrity: skipIntegrity}))
			phase := fmt.Sprintf("INFO [Phase %d of %d] Journal check and report\n", total, total)
			text := progress.String()
			at := strings.Index(text, phase)
			if at < 0 {
				t.Fatalf("no signing phase %q in the progress:\n%s", phase, text)
			}
			if strings.Count(text, "Journal check and report") != 1 {
				t.Errorf("the signing phase is announced more than once:\n%s", text)
			}
			verifying := strings.Index(text, "Independently verifying the node worker's durable resource journal before writing the report.")
			if verifying < at {
				t.Errorf("the phase is announced after the work it names began:\n%s", text)
			}
			if saved := strings.Index(text, "SUCCESS "); saved < verifying {
				t.Errorf("the verdict came before the signing phase:\n%s", text)
			}
		})
	}
}

// The count the controller makes of a plan is the count the node worker makes
// of the plan the controller sends it.
func TestControllerAndWorkerCountTheSamePhasesOfAPlan(t *testing.T) {
	opts := completedWorkerTeardownOptions(t)
	plan, err := config.LoadFromFile(opts.PlanPath)
	if err != nil {
		t.Fatal(err)
	}
	data, err := config.MarshalWorkerPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	worker, err := config.LoadFromReaderForWorker(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	for _, skip := range []bool{false, true} {
		controllerSteps := runphase.Steps(plan, runphase.Options{SkipIntegrity: skip})
		workerSteps := runphase.Steps(worker, runphase.Options{SkipIntegrity: skip})
		if len(controllerSteps) != len(workerSteps) {
			t.Fatalf("skip integrity %v: the controller counts %d phases, the worker %d", skip, len(controllerSteps), len(workerSteps))
		}
		for i := range controllerSteps {
			if controllerSteps[i].Kind != workerSteps[i].Kind {
				t.Errorf("skip integrity %v: phase %d is %v for the controller and %v for the worker", skip, i+1, controllerSteps[i].Kind, workerSteps[i].Kind)
			}
		}
	}
}
