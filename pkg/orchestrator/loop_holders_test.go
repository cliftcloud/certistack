// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/internal/journal"
	"github.com/cliftcloud/certistack/internal/process"
	"github.com/cliftcloud/certistack/internal/sysutil"
	"github.com/cliftcloud/certistack/pkg/pbs"
)

// A guest with Linux software RAID: the host assembles md126 from the mapped
// loop's partitions, md126 holds the loop, and a loop that is held stays after
// the unmap. These tests run the run's teardown over a fake sysfs, a fake
// proxmox-backup-client and losetup, and a fake of the function that stops the
// holders; the stop itself is tested in internal/sysutil.

// holdLoop7 makes md126 hold /dev/loop7 in the fixture's sysfs.
func (f *loopFixture) holdLoop7() {
	f.t.Helper()
	sys := filepath.Dir(filepath.Dir(filepath.Dir(f.state)))
	for _, dir := range []string{
		filepath.Join(sys, "loop7", "loop7p1", "holders", "md126"),
		filepath.Join(sys, "md126", "slaves", "loop7p1"),
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			f.t.Fatal(err)
		}
	}
}

// holderFake replaces the function that stops what holds a loop. It logs its
// calls with the fixture's commands, so their order shows, and answers stopped
// and err.
func (f *loopFixture) holderFake(stopped []sysutil.LoopHolder, err error) *[][]sysutil.LoopIdentity {
	f.t.Helper()
	var owned [][]sysutil.LoopIdentity
	old := releaseLoopHolders
	f.t.Cleanup(func() { releaseLoopHolders = old })
	releaseLoopHolders = func(_ context.Context, device string, ids []sysutil.LoopIdentity) ([]sysutil.LoopHolder, error) {
		owned = append(owned, ids)
		log, openErr := os.OpenFile(f.log, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
		if openErr != nil {
			f.t.Fatal(openErr)
		}
		defer log.Close()
		fmt.Fprintf(log, "holders %s\n", device)
		return stopped, err
	}
	return &owned
}

func settleQuickly(t *testing.T) {
	t.Helper()
	attempts, interval := loopSettleAttempts, loopSettleInterval
	t.Cleanup(func() { loopSettleAttempts, loopSettleInterval = attempts, interval })
	loopSettleAttempts, loopSettleInterval = 2, time.Millisecond
}

// What holds the loop is stopped before the unmap, with the journal's loops as
// the ones the run owns, and the unmap then releases the loop.
func TestNormalCleanupStopsWhatHoldsTheLoopBeforeTheUnmap(t *testing.T) {
	f := newLoopFixture(t, "exit 19")
	owned := f.holderFake([]sysutil.LoopHolder{{Name: "md126"}, {Name: "md127"}}, nil)
	o, _ := mapTestOrchestrator(t, pbs.Config{Repository: "u@pbs!tok@pbs.example:store"})
	f.mapAndFail(o)
	o.record.AddLoop("/dev/loop8", "/run/pbs-loopdev/certistack-test-second-map.img")

	if failures := o.cleanup.Unwind(); len(failures) != 0 {
		t.Fatalf("teardown failures = %v", failures)
	}
	if calls := f.calls(); calls != "holders /dev/loop7\nlosetup -d /dev/loop7" {
		t.Fatalf("calls:\n%s\nwant the holders stopped first, then the verified detach (the client's unmap is never run)", calls)
	}
	if len(*owned) != 1 || len((*owned)[0]) != 2 || (*owned)[0][0] != (sysutil.LoopIdentity{Device: "/dev/loop7", Backing: ownedLoopBacking}) || (*owned)[0][1].Device != "/dev/loop8" {
		t.Fatalf("owned = %+v, want this loop first and the journal's other loop", *owned)
	}
	if all, unmapped, errs := o.verifyTrackedLoopsUnmapped(); !all || len(errs) != 0 || len(unmapped) != 2 {
		t.Fatalf("verification = %v %v %v", all, unmapped, errs)
	}
}

// A holder that cannot be stopped, or that is not shown to be the run's, keeps
// the map in place: nothing is unmapped, the step fails with the reason, and the
// loop is not reported released.
func TestNormalCleanupLeavesTheMapWhenAHolderCannotBeReleased(t *testing.T) {
	f := newLoopFixture(t, "exit 19")
	reason := &sysutil.ReleaseError{Device: "/dev/loop7", Holders: []sysutil.LoopHolder{{Name: "md126"}}, Reason: "md126 is mounted at /mnt/guest"}
	f.holderFake(nil, reason)
	o, _ := mapTestOrchestrator(t, pbs.Config{Repository: "u@pbs!tok@pbs.example:store"})
	f.mapAndFail(o)

	failures := o.cleanup.Unwind()
	if len(failures) != 1 || !strings.Contains(failures[0].Err.Error(), "unmap /dev/loop7") || !strings.Contains(failures[0].Err.Error(), "md126 is mounted at /mnt/guest") || !errors.Is(failures[0].Err, reason) {
		t.Fatalf("teardown failures = %v, want the holder and why it was left", failures)
	}
	if calls := f.calls(); calls != "holders /dev/loop7" {
		t.Fatalf("calls:\n%s\nwant nothing unmapped", calls)
	}
	all, unmapped, errs := o.verifyTrackedLoopsUnmapped()
	if all || len(unmapped) != 0 || len(errs) != 1 || !strings.Contains(errs[0].Error(), "/dev/loop7 remains mapped after cleanup") {
		t.Fatalf("verification = %v %v %v; want the loop reported still mapped", all, unmapped, errs)
	}
}

// The unmap returns, and the loop is still there: not released. The error names
// the loop and what holds it, and the remedy. "Still the map": the detach
// returns and the loop stays (held, so the kernel only marks it for removal).
// "No file behind it": the map's daemon exited and left the loop attached to a
// file that is gone.
func TestNormalCleanupDoesNotReportAHeldLoopReleased(t *testing.T) {
	settleQuickly(t)
	for _, tc := range []struct {
		name      string
		afterStop func(f *loopFixture)
		want      string
	}{
		{"still the map", func(*loopFixture) {}, "PBS loop device /dev/loop7 remains mapped after it was unmapped"},
		{"no file behind it", func(f *loopFixture) { f.attach("/") }, "PBS loop device /dev/loop7 remains attached after cleanup although the file behind it is gone"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newLoopFixture(t, "exit 0")
			f.keepLoop()
			f.holderFake(nil, nil)
			f.holdLoop7()
			o, _ := mapTestOrchestrator(t, pbs.Config{Repository: "u@pbs!tok@pbs.example:store"})
			o.mayStopMapDaemonFn = func(string, journal.MapIntent) (bool, error) { return true, nil }
			o.stopMapDaemonFn = func(string, journal.MapIntent) (string, error) {
				tc.afterStop(f)
				return "", nil
			}
			// The loop number is not another operation's: nothing is asked about a map that is gone.
			o.reusedLoopNoteFn = func(device, backing string) (string, error) {
				t.Errorf("reusedLoopNoteFn(%s, %s): a held loop with no file is the run's own leftover", device, backing)
				return "", nil
			}
			f.mapAndFail(o)

			failures := o.cleanup.Unwind()
			if len(failures) != 1 {
				t.Fatalf("teardown failures = %v, want the held loop reported", failures)
			}
			msg := failures[0].Err.Error()
			for _, want := range []string{tc.want, "md126", "mdadm --stop /dev/md126, then losetup -d /dev/loop7"} {
				if !strings.Contains(msg, want) {
					t.Errorf("failure lacks %q: %s", want, msg)
				}
			}
			// The teardown evidence is derived from the same check: not released.
			all, unmapped, errs := o.verifyTrackedLoopsUnmapped()
			if all || len(unmapped) != 0 || len(errs) != 1 || !strings.Contains(errs[0].Error(), "md126") {
				t.Fatalf("verification = %v %v %v; want the held loop reported, not unmapped", all, unmapped, errs)
			}
		})
	}
}

// No listed block holder does not prove a stale loop is released: a mount or
// open file descriptor can retain it. Teardown and evidence must stay unclean.
func TestNormalCleanupOfAStaleLoopWithNoListedBlockHolder(t *testing.T) {
	settleQuickly(t)
	f := newLoopFixture(t, "exit 0")
	f.keepLoop()
	f.holderFake(nil, nil)
	o, _ := mapTestOrchestrator(t, pbs.Config{Repository: "u@pbs!tok@pbs.example:store"})
	o.mayStopMapDaemonFn = func(string, journal.MapIntent) (bool, error) { return true, nil }
	o.stopMapDaemonFn = func(string, journal.MapIntent) (string, error) {
		f.attach("/") // the daemon exited and left the loop attached to a file that is gone
		return "", nil
	}
	f.mapAndFail(o)
	if failures := o.cleanup.Unwind(); len(failures) == 0 {
		t.Fatal("teardown accepted a still-attached stale loop with no listed block holder")
	}
	if all, unmapped, errs := o.verifyTrackedLoopsUnmapped(); all || len(errs) != 1 || len(unmapped) != 0 {
		t.Fatalf("verification = %v %v %v: attached stale loop must not be credited as released", all, unmapped, errs)
	}
}

// The whole run: a loop the unmap leaves held ends the run cleanup_failed, with
// the loop out of the teardown evidence's released loops and the journal naming
// the holder, whatever else cleaned up.
func TestRunDoesNotClaimAHeldLoopWasReleased(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the node worker needs Linux host memory and mount-table semantics")
	}
	settleQuickly(t)
	f := newLoopFixture(t, "exit 0")
	f.keepLoop()
	f.holderFake(nil, nil)
	f.holdLoop7()
	o, stateDir := mapRun(t)

	res, err := o.Run(context.Background())
	if err == nil {
		t.Fatal("the run's overlay cannot be made here, so the run fails")
	}
	if res == nil || res.TeardownEvidence == nil {
		t.Fatalf("result = %+v", res)
	}
	evidence := res.TeardownEvidence
	if evidence.AllCleaned || evidence.OrphanSweepClean {
		t.Fatalf("evidence = %+v; a held loop must not leave the run cleaned", evidence)
	}
	for _, device := range evidence.LoopDevicesUnmapped {
		if device == "/dev/loop7" {
			t.Fatalf("loop_devices_unmapped = %v, want /dev/loop7 left out", evidence.LoopDevicesUnmapped)
		}
	}
	if !strings.Contains(strings.Join(evidence.CleanupErrors, "\n"), "md126") {
		t.Fatalf("cleanup errors = %v, want the holder named", evidence.CleanupErrors)
	}
	data, readErr := os.ReadFile(filepath.Join(stateDir, "active.json"))
	if readErr != nil || !strings.Contains(string(data), `"cleanup_failed"`) || !strings.Contains(string(data), "md126") {
		t.Fatalf("journal (%v):\n%s", readErr, data)
	}
}

// An inspection maps and unmaps through the same code: a map whose loop stays
// because md126 holds it is not released, and the inspection says what holds it.
func TestInspectionNamesWhatHoldsAMapItCannotRelease(t *testing.T) {
	f := newInspectFixture(t)
	f.set("keepmap")
	sys := filepath.Join(f.dir, "sys")
	for _, dir := range []string{filepath.Join(sys, "loop7", "loop7p1", "holders", "md126"), filepath.Join(sys, "md126", "slaves", "loop7p1")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// What stops the holders is faked: the fake client leaves the loop regardless.
	old := releaseLoopHolders
	t.Cleanup(func() { releaseLoopHolders = old })
	stops := 0
	releaseLoopHolders = func(context.Context, string, []sysutil.LoopIdentity) ([]sysutil.LoopHolder, error) {
		stops++
		return nil, nil
	}
	o, journalPath := inspector(t)
	outcomes, cleanup, err := o.InspectBackups(context.Background(), []InspectTarget{inspectTarget(100)}, nil, func(context.Context, InspectTarget, []string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if stops != 1 || len(outcomes) != 1 || !errors.Is(outcomes[0].Err, ErrMapsNotReleased) {
		t.Fatalf("stops %d, outcomes %+v; want the holders stopped once and the map not released", stops, outcomes)
	}
	text := outcomes[0].Err.Error() + "\n" + strings.Join(cleanup.Errors, "\n")
	for _, want := range []string{"/dev/loop7", "md126", "mdadm --stop /dev/md126, then losetup -d /dev/loop7"} {
		if !strings.Contains(text, want) {
			t.Errorf("the inspection's errors lack %q:\n%s", want, text)
		}
	}
	if record := loadJournal(t, journalPath); cleanup.Verified || record.Phase != "cleanup_failed" || len(record.Loops) != 1 {
		t.Fatalf("cleanup %+v, journal %+v; want cleanup_failed with the loop kept for recovery", cleanup, record)
	}
}

// The map journals the attachment's disk sequence number, in this boot, with
// its backing file.
func TestTheMapJournalsTheAttachmentsDiskSequenceNumber(t *testing.T) {
	f := newLoopFixture(t, "exit 0")
	f.diskseq(47)
	o, _ := mapTestOrchestrator(t, pbs.Config{Repository: "u@pbs!tok@pbs.example:store"})
	f.mapAndFail(o)
	boot, err := process.CurrentBootID()
	if err != nil {
		t.Skipf("this host has no boot id to compare: %v", err)
	}
	if got := o.record.Loops[0]; got.DiskSeq != 47 || got.BootID != strings.TrimSpace(boot) {
		t.Fatalf("journaled loop = %+v, want disk sequence number 47 in boot %s", got, boot)
	}
}

// After the unmap the loop is still the run's attachment (the same disk
// sequence number) although its backing reads "/": teardown and the final
// evidence must not call it released.
func TestNormalCleanupOfTheRunsOwnStaleAttachment(t *testing.T) {
	settleQuickly(t)
	f := newLoopFixture(t, "exit 0")
	f.diskseq(47)
	f.keepLoop()
	f.holderFake(nil, nil)
	o, _ := mapTestOrchestrator(t, pbs.Config{Repository: "u@pbs!tok@pbs.example:store"})
	o.mayStopMapDaemonFn = func(string, journal.MapIntent) (bool, error) { return true, nil }
	o.stopMapDaemonFn = func(string, journal.MapIntent) (string, error) {
		f.attach("/") // the daemon exited; something still has the loop open
		return "", nil
	}
	f.mapAndFail(o)
	failures := o.cleanup.Unwind()
	if len(failures) == 0 || !strings.Contains(fmt.Sprint(failures), "still the attachment this run made (disk sequence number 47)") {
		t.Fatalf("teardown failures = %v, want the run's attachment named", failures)
	}
	if all, unmapped, errs := o.verifyTrackedLoopsUnmapped(); all || len(errs) != 1 || len(unmapped) != 0 {
		t.Fatalf("verification = %v %v %v: the run's attachment must not be credited as released", all, unmapped, errs)
	}
}

// After the unmap the device number reads "/" but is another attachment (a new
// disk sequence number): the run's map is gone, and teardown is clean.
func TestNormalCleanupOfAStaleLoopThatIsAnotherAttachment(t *testing.T) {
	settleQuickly(t)
	f := newLoopFixture(t, "exit 0")
	f.diskseq(47)
	f.keepLoop()
	f.holderFake(nil, nil)
	o, _ := mapTestOrchestrator(t, pbs.Config{Repository: "u@pbs!tok@pbs.example:store"})
	o.mayStopMapDaemonFn = func(string, journal.MapIntent) (bool, error) { return true, nil }
	o.stopMapDaemonFn = func(string, journal.MapIntent) (string, error) {
		f.attach("/") // released, and the number taken by another loop whose file is gone
		f.diskseq(52)
		return "", nil
	}
	o.reusedLoopNoteFn = func(device, backing string) (string, error) {
		return device + " backs another file now and was left alone", nil
	}
	f.mapAndFail(o)
	if failures := o.cleanup.Unwind(); len(failures) != 0 {
		t.Fatalf("teardown failures = %v, want none: the run's attachment is gone", failures)
	}
	if all, unmapped, errs := o.verifyTrackedLoopsUnmapped(); !all || len(errs) != 0 || len(unmapped) != 1 {
		t.Fatalf("verification = %v %v %v, want the loop credited as released", all, unmapped, errs)
	}
}

// The unmap stopped the map's daemon, the loop's backing reads "/", and the loop
// is still the run's attachment for a moment: whatever had it open lets go, and
// the kernel releases it (autoclear). Teardown waits for that instead of
// failing at the first look (a 16-VM lab run had six such loops, all gone four
// seconds after a single look had failed its teardown).
func TestNormalCleanupWaitsForTheRunsAttachmentToLeave(t *testing.T) {
	attempts, interval := loopSettleAttempts, loopSettleInterval
	t.Cleanup(func() { loopSettleAttempts, loopSettleInterval = attempts, interval })
	loopSettleAttempts, loopSettleInterval = 200, 5*time.Millisecond
	f := newLoopFixture(t, "exit 0")
	f.diskseq(47)
	f.keepLoop()
	f.holderFake(nil, nil)
	o, _ := mapTestOrchestrator(t, pbs.Config{Repository: "u@pbs!tok@pbs.example:store"})
	o.mayStopMapDaemonFn = func(string, journal.MapIntent) (bool, error) { return true, nil }
	released := make(chan struct{})
	o.stopMapDaemonFn = func(string, journal.MapIntent) (string, error) {
		f.attach("/") // the daemon exited; something still has the loop open, for a moment
		go func() {
			defer close(released)
			time.Sleep(50 * time.Millisecond)
			_ = os.Remove(f.state) // it lets go, and the kernel releases the loop
		}()
		return "", nil
	}
	f.mapAndFail(o)
	failures := o.cleanup.Unwind()
	<-released
	if len(failures) != 0 {
		t.Fatalf("teardown failures = %v, want none: the run's attachment left within the wait", failures)
	}
	if all, unmapped, errs := o.verifyTrackedLoopsUnmapped(); !all || len(errs) != 0 || len(unmapped) != 1 {
		t.Fatalf("verification = %v %v %v, want the loop gone", all, unmapped, errs)
	}
}
