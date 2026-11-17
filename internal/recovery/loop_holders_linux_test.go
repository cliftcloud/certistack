//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package recovery

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/internal/journal"
	"github.com/cliftcloud/certistack/internal/process"
	"github.com/cliftcloud/certistack/internal/sysutil"
)

// A guest with Linux software RAID: the host assembled md126 from the loop's
// partitions, and a loop that is held stays after it is unmapped. Recovery of a
// map stops what holds it first, then waits for the loop to be gone.

// recordHolders replaces the function that stops what holds a loop with one
// that logs "holders <device>" in log, among the fake commands, and answers
// stopped and err. It returns the loops it was told the run owns, per call.
func recordHolders(t *testing.T, log string, stopped []sysutil.LoopHolder, err error) *[][]sysutil.LoopIdentity {
	t.Helper()
	var owned [][]sysutil.LoopIdentity
	old := releaseLoopHolders
	t.Cleanup(func() { releaseLoopHolders = old })
	releaseLoopHolders = func(_ context.Context, device string, ids []sysutil.LoopIdentity) ([]sysutil.LoopHolder, error) {
		owned = append(owned, ids)
		f, openErr := os.OpenFile(log, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
		if openErr != nil {
			t.Fatal(openErr)
		}
		defer f.Close()
		fmt.Fprintf(f, "holders %s\n", device)
		return stopped, err
	}
	return &owned
}

// waitQuickly shortens the wait for a released loop to leave the kernel.
func waitQuickly(t *testing.T) {
	t.Helper()
	attempts, interval := loopReleaseAttempts, loopReleaseInterval
	t.Cleanup(func() { loopReleaseAttempts, loopReleaseInterval = attempts, interval })
	loopReleaseAttempts, loopReleaseInterval = 2, time.Millisecond
}

// holdLoop makes md126 hold the first partition of loop in the fake sysfs.
func holdLoop(t *testing.T, sysBlock, loop string) {
	t.Helper()
	for _, dir := range []string{
		filepath.Join(sysBlock, loop, loop+"p1", "holders", "md126"),
		filepath.Join(sysBlock, "md126", "slaves", loop+"p1"),
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

// Recorded loops are released with their holders stopped first, and the loops
// the journal records are the ones the run owns.
func TestRecoverLockedStopsWhatHoldsARecordedLoopBeforeReleasingIt(t *testing.T) {
	root, stateDir := t.TempDir(), t.TempDir()
	at := reaperBoot.Add(10 * time.Hour)
	maps := hostWithProcs(t, root, noSignal(t))
	log := fakeLoopTools(t, "exit 19") // the client's unmap is never run: only the detach releases the loop
	owned := recordHolders(t, log, []sysutil.LoopHolder{{Name: "md126"}}, nil)
	recorded := filepath.Join(maps.runDir, "repo"+scsi1Tail)
	maps.add("loop7", maps.runDir, "repo"+scsi1Tail, time.Time{})
	path := journalOf(t, stateDir, []journal.TrackedLoop{{Device: "/dev/loop7", Backing: recorded}, {Device: "/dev/loop8", Backing: recorded}}, resolvedIntent(at, "/dev/loop7"))

	if err := RecoverLocked(stateDir); err != nil {
		t.Fatalf("recovery: %v", err)
	}
	if calls := callsIn(log); calls != "holders /dev/loop7\nlosetup -d /dev/loop7" {
		t.Fatalf("calls:\n%s\nwant the holders stopped first, then the verified detach", calls)
	}
	want := []sysutil.LoopIdentity{{Device: "/dev/loop7", Backing: recorded}, {Device: "/dev/loop8", Backing: recorded}}
	if len(*owned) != 1 || fmt.Sprint((*owned)[0]) != fmt.Sprint(want) {
		t.Fatalf("owned = %+v, want the journal's loops %+v", *owned, want)
	}
	if phase := phaseOf(t, path); phase != "cleaned" {
		t.Fatalf("phase = %q", phase)
	}
}

// A holder that is not stopped keeps the map: nothing is unmapped, and the
// journal stays unclean with the reason.
func TestRecoverLockedLeavesTheMapWhenAHolderCannotBeReleased(t *testing.T) {
	root, stateDir := t.TempDir(), t.TempDir()
	at := reaperBoot.Add(10 * time.Hour)
	maps := hostWithProcs(t, root, noSignal(t))
	log := fakeLoopTools(t, "exit 0")
	reason := &sysutil.ReleaseError{Device: "/dev/loop7", Holders: []sysutil.LoopHolder{{Name: "md126"}}, Reason: "md126 is mounted at /mnt/guest"}
	recordHolders(t, log, nil, reason)
	recorded := filepath.Join(maps.runDir, "repo"+scsi1Tail)
	maps.add("loop7", maps.runDir, "repo"+scsi1Tail, time.Time{})
	path := journalOf(t, stateDir, []journal.TrackedLoop{{Device: "/dev/loop7", Backing: recorded}}, resolvedIntent(at, "/dev/loop7"))

	err := RecoverLocked(stateDir)
	if err == nil || !strings.Contains(err.Error(), "md126 is mounted at /mnt/guest") || !strings.Contains(err.Error(), "release /dev/loop7") {
		t.Fatalf("recovery = %v, want the holder and why it was left", err)
	}
	if calls := callsIn(log); calls != "holders /dev/loop7" {
		t.Fatalf("calls:\n%s\nwant nothing unmapped", calls)
	}
	record, loadErr := journal.Load(path)
	if loadErr != nil || record.Phase != "cleanup_failed" || !strings.Contains(strings.Join(record.CleanupErrors, "\n"), "md126 is mounted") {
		t.Fatalf("journal = %+v, %v; want it unclean with the reason", record, loadErr)
	}
}

// The detach returns and the loop is still there: not released. The journal
// stays unclean and the error names the loop, what holds it and the commands.
func TestRecoverLockedDoesNotCleanAHeldLoop(t *testing.T) {
	waitQuickly(t)
	root, stateDir := t.TempDir(), t.TempDir()
	at := reaperBoot.Add(10 * time.Hour)
	maps := hostWithProcs(t, root, noSignal(t))
	log := fakeLoopTools(t, "exit 0")
	// A losetup -d that returns and leaves the loop in the kernel (it is held, so
	// the kernel only marks it for removal).
	losetup := "#!/bin/sh\nprintf 'losetup %s\\n' \"$*\" >> '" + log + "'\nexit 0\n"
	if err := os.WriteFile(filepath.Join(filepath.Dir(log), "losetup"), []byte(losetup), 0o755); err != nil {
		t.Fatal(err)
	}
	recordHolders(t, log, nil, nil)
	holdLoop(t, maps.sysBlock, "loop7")
	recorded := filepath.Join(maps.runDir, "repo"+scsi1Tail)
	maps.add("loop7", maps.runDir, "repo"+scsi1Tail, time.Time{})
	path := journalOf(t, stateDir, []journal.TrackedLoop{{Device: "/dev/loop7", Backing: recorded}}, resolvedIntent(at, "/dev/loop7"))

	err := RecoverLocked(stateDir)
	if err == nil {
		t.Fatal("recovery reported a held loop released")
	}
	for _, want := range []string{"/dev/loop7", "md126", "mdadm --stop /dev/md126, then losetup -d /dev/loop7"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error lacks %q: %v", want, err)
		}
	}
	if phase := phaseOf(t, path); phase != "cleanup_failed" {
		t.Fatalf("phase = %q, want cleanup_failed", phase)
	}
}

// What an earlier unmap left behind: the loop backs no file ("/") and md126
// holds it. It is the map's own leftover, not another operation's loop, so
// recovery does not call it clean, and it stops nothing: nothing shows the
// device is still the run's. No listed block holder is not proof of release.
func TestRecoverLockedOfALoopAnEarlierUnmapLeftHeld(t *testing.T) {
	for _, held := range []bool{true, false} {
		t.Run(fmt.Sprintf("held %v", held), func(t *testing.T) {
			waitQuickly(t)
			root, stateDir := t.TempDir(), t.TempDir()
			at := reaperBoot.Add(10 * time.Hour)
			maps := hostWithProcs(t, root, noSignal(t))
			log := fakeLoopTools(t, "exit 0")
			stopCalls := recordHolders(t, log, nil, nil)
			recorded := filepath.Join(maps.runDir, "repo"+scsi1Tail)
			maps.add("loop7", "/", "", time.Time{}) // backing "/"
			if held {
				holdLoop(t, maps.sysBlock, "loop7")
			}
			path := journalOf(t, stateDir, []journal.TrackedLoop{{Device: "/dev/loop7", Backing: recorded}}, resolvedIntent(at, "/dev/loop7"))

			err := RecoverLocked(stateDir)
			if calls := callsIn(log); calls != "" || len(*stopCalls) != 0 {
				t.Fatalf("calls:\n%s\nholder calls %v; want nothing done to a loop that is no longer shown to be the run's", calls, *stopCalls)
			}
			if err == nil || !strings.Contains(err.Error(), "remains attached after cleanup although the file behind it is gone") || (held && !strings.Contains(err.Error(), "md126")) || phaseOf(t, path) != "cleanup_failed" {
				t.Fatalf("recovery = %v, phase %q; want the held loop reported and the journal kept", err, phaseOf(t, path))
			}
		})
	}
}

// A map the interrupted run began and never recorded: its loop is released with
// its holders stopped first, and the run owns just that map's loop.
func TestRecoverLockedStopsWhatHoldsAnUnrecordedMapsLoop(t *testing.T) {
	root, stateDir := t.TempDir(), t.TempDir()
	h := newLabHost(t, root)
	d := &deadFixture{t: t, maps: h.maps, at: reaperBoot.Add(10 * time.Hour), pid: 4242, written: 3 * time.Second}
	d.intent = labIntent(d.at)
	img := d.own("loop")
	h.mount(t, img)
	path := journalOf(t, stateDir, nil, d.intent)
	log := installLabTools(t, h.maps.sysBlock, false)
	owned := recordHolders(t, log, []sysutil.LoopHolder{{Name: "md126"}}, nil)

	if err := RecoverLocked(stateDir); err != nil {
		t.Fatalf("recovery: %v", err)
	}
	if calls := callsIn(log); calls != "holders /dev/loop2\nlosetup -d /dev/loop2" {
		t.Fatalf("calls:\n%s\nwant the holders stopped before the detach", calls)
	}
	if len(*owned) != 1 || fmt.Sprint((*owned)[0]) != fmt.Sprint([]sysutil.LoopIdentity{{Device: "/dev/loop2", Backing: img}}) {
		t.Fatalf("owned = %+v, want only the unrecorded map's loop", *owned)
	}
	if phase := phaseOf(t, path); phase != "cleaned" {
		t.Fatalf("phase = %q", phase)
	}
}

// A loop the run recorded with its attachment's disk sequence number: the same
// number in this boot is the run's attachment, still there although its
// backing reads "/", and recovery keeps the journal; another number, or a
// record from another boot, is another attachment, and the run's map is gone.
func TestRecoverLockedJudgesAStaleLoopByItsAttachment(t *testing.T) {
	boot, err := process.CurrentBootID()
	if err != nil || strings.TrimSpace(boot) == "" {
		t.Skipf("this host has no boot id to compare: %v", err)
	}
	boot = strings.TrimSpace(boot)
	for _, c := range []struct {
		name    string
		seq     string
		boot    string
		cleaned bool
	}{
		{"the same attachment", "47", boot, false},
		{"another attachment", "52", boot, true},
		{"recorded in another boot", "47", "5a2e9d44-1c7b-4f60-8e3a-6b0f2d9c4a17", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			waitQuickly(t)
			root, stateDir := t.TempDir(), t.TempDir()
			at := reaperBoot.Add(10 * time.Hour)
			maps := hostWithProcs(t, root, noSignal(t))
			log := fakeLoopTools(t, "exit 0")
			stopCalls := recordHolders(t, log, nil, nil)
			recorded := filepath.Join(maps.runDir, "repo"+scsi1Tail)
			maps.add("loop7", "/", "", time.Time{}) // backing "/"
			if err := os.WriteFile(filepath.Join(maps.sysBlock, "loop7", "diskseq"), []byte(c.seq+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			path := journalOf(t, stateDir, []journal.TrackedLoop{{Device: "/dev/loop7", Backing: recorded, DiskSeq: 47, BootID: c.boot}}, resolvedIntent(at, "/dev/loop7"))

			err := RecoverLocked(stateDir)
			if calls := callsIn(log); calls != "" || len(*stopCalls) != 0 {
				t.Fatalf("calls:\n%s\nholder calls %v; want nothing done to the loop", calls, *stopCalls)
			}
			if c.cleaned {
				if err != nil || phaseOf(t, path) != "cleaned" {
					t.Fatalf("recovery = %v, phase %q; want the journal cleaned: the run's attachment is gone", err, phaseOf(t, path))
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), "still the attachment this run made (disk sequence number 47)") || phaseOf(t, path) != "cleanup_failed" {
				t.Fatalf("recovery = %v, phase %q; want the run's attachment reported and the journal kept", err, phaseOf(t, path))
			}
		})
	}
}

// The run's attachment is still there when recovery looks, and leaves a moment
// later (whatever had it open lets go; the map set autoclear): recovery waits
// for it, as teardown does, and cleans the journal.
func TestRecoverLockedWaitsForTheRunsAttachmentToLeave(t *testing.T) {
	boot, err := process.CurrentBootID()
	if err != nil || strings.TrimSpace(boot) == "" {
		t.Skipf("this host has no boot id to compare: %v", err)
	}
	attempts, interval := loopReleaseAttempts, loopReleaseInterval
	t.Cleanup(func() { loopReleaseAttempts, loopReleaseInterval = attempts, interval })
	loopReleaseAttempts, loopReleaseInterval = 200, 5*time.Millisecond
	root, stateDir := t.TempDir(), t.TempDir()
	at := reaperBoot.Add(10 * time.Hour)
	maps := hostWithProcs(t, root, noSignal(t))
	log := fakeLoopTools(t, "exit 0")
	stopCalls := recordHolders(t, log, nil, nil)
	recorded := filepath.Join(maps.runDir, "repo"+scsi1Tail)
	maps.add("loop7", "/", "", time.Time{}) // backing "/"
	if err := os.WriteFile(filepath.Join(maps.sysBlock, "loop7", "diskseq"), []byte("47\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	path := journalOf(t, stateDir, []journal.TrackedLoop{{Device: "/dev/loop7", Backing: recorded, DiskSeq: 47, BootID: strings.TrimSpace(boot)}}, resolvedIntent(at, "/dev/loop7"))
	released := make(chan struct{})
	go func() {
		defer close(released)
		time.Sleep(50 * time.Millisecond)
		_ = os.Remove(filepath.Join(maps.sysBlock, "loop7", "loop", "backing_file")) // the kernel releases it
	}()
	err = RecoverLocked(stateDir)
	<-released
	if calls := callsIn(log); calls != "" || len(*stopCalls) != 0 {
		t.Fatalf("calls:\n%s\nholder calls %v; want nothing done to the loop", calls, *stopCalls)
	}
	if err != nil || phaseOf(t, path) != "cleaned" {
		t.Fatalf("recovery = %v, phase %q; want the journal cleaned once the attachment left", err, phaseOf(t, path))
	}
}
