// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"errors"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/internal/guestnet"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/pbs"
	"github.com/cliftcloud/certistack/pkg/runphase"
)

const testGiB = int64(1) << 30

// The line a scan reports begins with a fixed form that log-reading tools
// match, and what is known of the size and the time left follows "GiB verified".
func TestScanProgressLineKeepsAFixedStart(t *testing.T) {
	// Patterns a log reader uses: the scan rate, and a marker of a scan under way.
	scanrate := regexp.MustCompile(`\[(\d+):(\d+):(\d+)\] INFO \[Storage\] VM (\d+) full mapped-image integrity scan(?: and copy)?: (\d+) GiB verified`)
	drill := regexp.MustCompile(`full mapped-image integrity scan: [2-9] GiB verified`)

	known := runphase.ScanProgress{Total: 12 * testGiB, Percent: 58, Remaining: 70 * time.Second, HaveRemaining: true}
	sizeOnly := runphase.ScanProgress{Total: 12 * testGiB, Percent: 58}
	for _, test := range []struct {
		name      string
		withCopy  bool
		verified  int64
		progress  runphase.ScanProgress
		want      string
		wantDrill bool
	}{
		{"nothing known of the size: the plain line", false, 7 * testGiB,
			runphase.ScanProgress{Percent: -1},
			"VM 9100 full mapped-image integrity scan: 7 GiB verified.", true},
		{"the copying scan, nothing known", true, 7 * testGiB,
			runphase.ScanProgress{Percent: -1},
			"VM 9100 full mapped-image integrity scan and copy: 7 GiB verified.", false},
		{"the size, no time yet", false, 7 * testGiB, sizeOnly,
			"VM 9100 full mapped-image integrity scan: 7 GiB verified of 12 GiB (58%).", true},
		{"the size and the time left", false, 7 * testGiB, known,
			"VM 9100 full mapped-image integrity scan: 7 GiB verified of 12 GiB (58%), about 1 min left.", true},
		{"the copying scan, the size and the time left", true, 7 * testGiB, known,
			"VM 9100 full mapped-image integrity scan and copy: 7 GiB verified of 12 GiB (58%), about 1 min left.", false},
		{"a first gibibyte", false, testGiB, runphase.ScanProgress{Percent: -1},
			"VM 9100 full mapped-image integrity scan: 1 GiB verified.", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := scanProgressLine(9100, test.withCopy, test.verified, test.progress)
			if got != test.want {
				t.Errorf("line = %q\n want %q", got, test.want)
			}
			rendered := "[00:04:39] INFO [Storage] " + got
			if m := scanrate.FindStringSubmatch(rendered); m == nil || m[4] != "9100" || m[5] != "7" && m[5] != "1" {
				t.Errorf("the scan-rate pattern cannot read %q (%v)", rendered, m)
			}
			if matched := drill.MatchString(got); matched != test.wantDrill {
				t.Errorf("the scan marker matches %q: %v, want %v", got, matched, test.wantDrill)
			}
		})
	}
}

// A VM's disk sizes, from the snapshot's manifest or else the backup's
// configuration, give the scan its total and the phase line its size; one disk
// of unknown size leaves both out.
func TestScanTotalsComeFromWhatTheBackupRecords(t *testing.T) {
	vm := config.VM{
		SourceImageBytes: map[string]int64{"scsi0": 10 * testGiB, "scsi1": 2 * testGiB},
		SourceDiskBytes:  map[string]int64{"scsi0": 9 * testGiB, "scsi2": 4 * testGiB},
	}
	for _, test := range []struct {
		slots     []string
		wantTotal map[string]int64
		wantNote  string
	}{
		{[]string{"scsi0"}, map[string]int64{"scsi0": 10 * testGiB}, "10 GiB to read"},
		{[]string{"scsi0", "scsi1"}, map[string]int64{"scsi1": 2 * testGiB}, "12 GiB to read"},
		{[]string{"scsi2"}, map[string]int64{"scsi2": 4 * testGiB}, "4 GiB to read"}, // the configuration's, the manifest gave none
		{[]string{"scsi0", "virtio0"}, map[string]int64{"virtio0": 0}, ""},
		{nil, nil, ""},
	} {
		for slot, want := range test.wantTotal {
			if got := scanTotal(vm, slot); got != want {
				t.Errorf("scanTotal(%s) = %d, want %d", slot, got, want)
			}
		}
		if got := scanSizeNote(vm, test.slots); got != test.wantNote {
			t.Errorf("scanSizeNote(%v) = %q, want %q", test.slots, got, test.wantNote)
		}
	}
}

// restoreLines runs a restore up to the start of the VM, which the harness's PVE
// refuses, with the phases of the plan it is in, and returns the phase lines the
// restore announced.
func restoreLines(t *testing.T, h *phaseHarness, skipIntegrity bool) []string {
	t.Helper()
	h.o.opts.SkipIntegrity = skipIntegrity
	h.o.plan.Tiers = []config.Tier{{Level: 1, Name: "core", VMs: []config.VM{h.vm}}}
	h.o.phases = runphase.NewTracker(runphase.Steps(h.o.plan, runphase.Options{SkipIntegrity: skipIntegrity}))
	var lines []string
	h.o.phaseFn = func(stage, message string) { lines = append(lines, stage+" | "+message) }
	if err := h.run(t); err == nil || !strings.Contains(err.Error(), "StartVM") {
		t.Fatalf("restore = %v, want the VM start refused", err)
	}
	return lines
}

// The restore announces its phases as it reaches them, counted among the plan's:
// the disks, the guest network preparation when the VM has one, the integrity
// scan (with the size it has to read) when the run has one, and the boot.
func TestARestoreAnnouncesItsPhasesAmongThePlans(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the fake commands are shell scripts")
	}
	t.Run("mode preserve", func(t *testing.T) {
		h := newPhaseHarness(t, okQemuImg, 0, 0, 0, false)
		got := restoreLines(t, h, false)
		want := []string{
			"Phase 3 of 8 | Disk restore (PBS map, COW overlays) for VM 9001",
			"Phase 4 of 8 | Integrity scan for VM 9001: 36 MiB to read",
			"Phase 5 of 8 | Sandbox boot for VM 9001",
		}
		if strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Errorf("phase lines:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
		}
	})
	t.Run("a guest network to prepare", func(t *testing.T) {
		h := newPhaseHarness(t, okQemuImg, 0, 0, 0, false)
		h.vm.NetworkRecovery = config.NetworkRecovery{Mode: "auto"}
		h.vm.Probes = []config.Probe{{Type: "tcp", Description: "web", TargetIP: "10.100.0.5", Port: 80}}
		h.o.applyGuestNetworkFn = func(_ context.Context, cfg guestnet.Config) (guestnet.Result, error) {
			return guestnet.Result{Strategy: "networkmanager", Address: cfg.Address}, nil
		}
		got := restoreLines(t, h, false)
		want := []string{
			"Phase 3 of 9 | Disk restore (PBS map, COW overlays) for VM 9001",
			"Phase 4 of 9 | Guest network preparation for VM 9001: offline image work, often several minutes on a small or nested host",
			"Phase 5 of 9 | Integrity scan for VM 9001: 36 MiB to read",
			"Phase 6 of 9 | Sandbox boot for VM 9001",
		}
		if strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Errorf("phase lines:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
		}
	})
	t.Run("test mode has no integrity scan to announce", func(t *testing.T) {
		h := newPhaseHarness(t, okQemuImg, 0, 0, 0, false)
		got := restoreLines(t, h, true)
		want := []string{
			"Phase 3 of 7 | Disk restore (PBS map, COW overlays) for VM 9001",
			"Phase 4 of 7 | Sandbox boot for VM 9001",
		}
		if strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Errorf("phase lines:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
		}
	})
	t.Run("a restore that is not part of a run's list says nothing", func(t *testing.T) {
		h := newPhaseHarness(t, okQemuImg, 0, 0, 0, false)
		called := false
		h.o.phaseFn = func(string, string) { called = true }
		if err := h.run(t); err == nil {
			t.Fatal("the harness's start refusal did not happen")
		}
		if called {
			t.Error("a restore driven on its own announced a phase it has no number for")
		}
	})
}

// A phase announced through the real progress channel is a "Phase N of M"
// event the controller can recognize.
func TestAPhaseIsAProgressEventUnderItsOwnStage(t *testing.T) {
	stop := captureProgress(t)
	o := &Orchestrator{phases: runphase.NewTracker(runphase.Steps(&config.Plan{}, runphase.Options{}))}
	o.announcePhase(runphase.Admission, 0, "")
	o.announcePhase(runphase.Network, 0, "")
	events := stop()
	if len(events) != 2 {
		t.Fatalf("%d events: %+v", len(events), events)
	}
	for i, want := range []struct{ stage, message string }{
		{"Phase 1 of 4", "Admission checks: node support and host capacity"},
		{"Phase 2 of 4", "Isolated sandbox network"},
	} {
		if events[i].Level != "INFO" || events[i].Stage != want.stage || events[i].Message != want.message {
			t.Errorf("event %d = %+v, want INFO [%s] %s", i+1, events[i], want.stage, want.message)
		}
		if !runphase.IsStage(events[i].Stage) {
			t.Errorf("the controller does not recognize the stage %q", events[i].Stage)
		}
	}
}

// scanTestClock is a clock a test moves.
type scanTestClock struct{ now time.Time }

func (c *scanTestClock) Now() time.Time { return c.now }

// The scan of a disk reports, at each gibibyte, how much it has verified of the
// size the snapshot's manifest records and about how long is left, from the
// rate it has gone at; a disk whose size the backup does not record is reported
// as it always was.
func TestAnIntegrityScanReportsItsSizeAndTheTimeLeft(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the fake commands are shell scripts")
	}
	for _, test := range []struct {
		name       string
		copyBefore string
		sizes      bool
		want       []string
	}{
		{"the integrity scan", config.CopyBeforeBootNever, true, []string{
			"VM 9001 full mapped-image integrity scan: 1 GiB verified of 12 GiB (8%), about 4 min left.",
			"VM 9001 full mapped-image integrity scan: 2 GiB verified of 12 GiB (16%), about 3 min left.",
			"VM 9001 full mapped-image integrity scan: 3 GiB verified of 12 GiB (25%), about 3 min left.",
		}},
		{"the scan that copies before boot", config.CopyBeforeBootAlways, true, []string{
			"VM 9001 full mapped-image integrity scan and copy: 1 GiB verified of 12 GiB (8%), about 4 min left.",
			"VM 9001 full mapped-image integrity scan and copy: 2 GiB verified of 12 GiB (16%), about 3 min left.",
			"VM 9001 full mapped-image integrity scan and copy: 3 GiB verified of 12 GiB (25%), about 3 min left.",
		}},
		{"a backup that recorded no size", config.CopyBeforeBootNever, false, []string{
			"VM 9001 full mapped-image integrity scan: 1 GiB verified.",
			"VM 9001 full mapped-image integrity scan: 2 GiB verified.",
			"VM 9001 full mapped-image integrity scan: 3 GiB verified.",
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			o, vm, _ := scanOrchestrator(t, test.copyBefore)
			if test.sizes {
				vm.SourceImageBytes = map[string]int64{"scsi0": 12 * testGiB}
				vm.SourceDiskBytes = map[string]int64{"scsi0": 12 * testGiB}
			} else {
				vm.SourceImageBytes, vm.SourceDiskBytes = nil, nil
			}
			clock := &scanTestClock{now: time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)}
			o.scanClock = clock.Now
			// The scan reads a gibibyte every 20 s, and reports each.
			report := func(progress func(int64)) {
				for gibibytes := int64(1); gibibytes <= 3; gibibytes++ {
					clock.now = clock.now.Add(20 * time.Second)
					progress(gibibytes * testGiB)
				}
			}
			o.verifyImageFn = func(_ context.Context, _, _ string, _ pbs.DiskSize, progress func(int64)) (*pbs.VerifySummary, string, error) {
				report(progress)
				return nil, "", errScanStops
			}
			o.copyImageFn = func(_ context.Context, _, _, _, _ string, _ pbs.DiskSize, progress func(int64)) (*pbs.VerifySummary, string, error) {
				report(progress)
				return nil, "", errScanStops
			}
			stop := captureProgress(t)
			_, err := o.bootAndVerifyVM(context.Background(), vm, 60, nil)
			events := stop()
			if !errors.Is(err, errScanStops) {
				t.Fatalf("bootAndVerifyVM = %v, want the run to reach the scan", err)
			}
			var got []string
			for _, event := range events {
				if event.Stage == "Storage" && strings.Contains(event.Message, "GiB verified") {
					got = append(got, event.Message)
				}
			}
			if strings.Join(got, "\n") != strings.Join(test.want, "\n") {
				t.Errorf("scan lines:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(test.want, "\n"))
			}
		})
	}
}
