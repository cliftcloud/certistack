// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package sysutil

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/internal/journal"
)

const (
	thisBoot  = "0b6f7c1e-3d0a-4a8e-9f5e-2c1d7a9b8e01"
	otherBoot = "5a2e9d44-1c7b-4f60-8e3a-6b0f2d9c4a17"
)

func TestLoopDiskSeqReadsTheKernelsNumber(t *testing.T) {
	f := newHolderFixture(t)
	f.loop("loop0")
	f.write(filepath.Join(f.root, "loop0", "diskseq"), "47\n")
	if seq, err := loopDiskSeq(f.root, "/dev/loop0"); err != nil || seq != 47 {
		t.Fatalf("diskseq = %d, %v; want 47", seq, err)
	}
	if _, err := loopDiskSeq(f.root, "/dev/loop1"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a device that is not there = %v; want os.ErrNotExist", err)
	}
	for _, text := range []string{"0\n", "abc\n", "\n", "-3\n"} {
		f.write(filepath.Join(f.root, "loop0", "diskseq"), text)
		if _, err := loopDiskSeq(f.root, "/dev/loop0"); err == nil || errors.Is(err, os.ErrNotExist) {
			t.Fatalf("diskseq %q = %v; want an error that is not ErrNotExist", text, err)
		}
	}
	if _, err := loopDiskSeq(f.root, "/dev/../loop0"); err == nil {
		t.Fatal("an invalid device name was read")
	}
}

func TestLoopAttachmentRecordsTheNumberOnlyWhenItIsKnown(t *testing.T) {
	boot := func(id string, err error) func() (string, error) {
		return func() (string, error) { return id, err }
	}
	t.Run("number and boot", func(t *testing.T) {
		f := newHolderFixture(t)
		f.loop("loop0")
		f.write(filepath.Join(f.root, "loop0", "loop", "backing_file"), "/run/pbs-loopdev/map.img\n")
		f.write(filepath.Join(f.root, "loop0", "diskseq"), "47\n")
		loop, err := loopAttachment(f.root, "/dev/loop0", boot(thisBoot+"\n", nil))
		want := journal.TrackedLoop{Device: "/dev/loop0", Backing: "/run/pbs-loopdev/map.img", DiskSeq: 47, BootID: thisBoot}
		if err != nil || loop != want {
			t.Fatalf("attachment = %+v, %v; want %+v", loop, err, want)
		}
	})
	t.Run("a kernel without diskseq", func(t *testing.T) {
		f := newHolderFixture(t)
		f.loop("loop0")
		f.write(filepath.Join(f.root, "loop0", "loop", "backing_file"), "/run/pbs-loopdev/map.img\n")
		loop, err := loopAttachment(f.root, "/dev/loop0", boot(thisBoot, nil))
		if err != nil || loop.DiskSeq != 0 || loop.BootID != "" || loop.Backing != "/run/pbs-loopdev/map.img" {
			t.Fatalf("attachment = %+v, %v; want the backing alone", loop, err)
		}
	})
	t.Run("the boot cannot be read", func(t *testing.T) {
		f := newHolderFixture(t)
		f.loop("loop0")
		f.write(filepath.Join(f.root, "loop0", "loop", "backing_file"), "/run/pbs-loopdev/map.img\n")
		f.write(filepath.Join(f.root, "loop0", "diskseq"), "47\n")
		for _, b := range []func() (string, error){boot("", errors.New("no /proc")), boot("  ", nil)} {
			loop, err := loopAttachment(f.root, "/dev/loop0", b)
			if err != nil || loop.DiskSeq != 0 || loop.BootID != "" {
				t.Fatalf("attachment = %+v, %v; a number without its boot must not be recorded", loop, err)
			}
		}
	})
	t.Run("no backing is an error", func(t *testing.T) {
		f := newHolderFixture(t)
		f.loop("loop0")
		f.write(filepath.Join(f.root, "loop0", "diskseq"), "47\n")
		if _, err := loopAttachment(f.root, "/dev/loop0", boot(thisBoot, nil)); err == nil {
			t.Fatal("a loop with no backing file was recorded")
		}
	})
}

// The disk sequence number decides whether a loop whose backing is not the
// recorded file any more is still the run's attachment. Without one the
// backing path decides, and a stale backing is never released.
func TestAwaitLoopReleasedByTheAttachmentsDiskSequenceNumber(t *testing.T) {
	const recorded = "/run/pbs-loopdev/map.img"
	cases := []struct {
		name     string
		backing  string // what the device reads now
		seq      string // its diskseq file, "" for none
		loop     journal.TrackedLoop
		boot     string
		bootErr  error
		released bool
		want     string // a part of the error when not released
	}{
		{"stale, same attachment", "/", "47", journal.TrackedLoop{DiskSeq: 47, BootID: thisBoot}, thisBoot, nil, false, "still the attachment this run made (disk sequence number 47)"},
		{"deleted, same attachment", "/ (deleted)", "47", journal.TrackedLoop{DiskSeq: 47, BootID: thisBoot}, thisBoot, nil, false, "still the attachment this run made"},
		{"another real file, same attachment", "/var/lib/other.img", "47", journal.TrackedLoop{DiskSeq: 47, BootID: thisBoot}, thisBoot, nil, false, "still the attachment this run made"},
		{"stale, another attachment", "/", "52", journal.TrackedLoop{DiskSeq: 47, BootID: thisBoot}, thisBoot, nil, true, ""},
		{"another real file, another attachment", "/var/lib/other.img", "52", journal.TrackedLoop{DiskSeq: 47, BootID: thisBoot}, thisBoot, nil, true, ""},
		{"stale, recorded in another boot", "/", "47", journal.TrackedLoop{DiskSeq: 47, BootID: otherBoot}, thisBoot, nil, true, ""},
		{"stale, no number recorded", "/", "52", journal.TrackedLoop{}, thisBoot, nil, false, "remains attached after cleanup although the file behind it is gone"},
		{"another real file, no number recorded", "/var/lib/other.img", "52", journal.TrackedLoop{}, thisBoot, nil, true, ""},
		{"stale, the kernel has no diskseq", "/", "", journal.TrackedLoop{DiskSeq: 47, BootID: thisBoot}, thisBoot, nil, false, "remains attached after cleanup although the file behind it is gone"},
		{"stale, the boot cannot be read", "/", "52", journal.TrackedLoop{DiskSeq: 47, BootID: thisBoot}, "", errors.New("no /proc"), false, "remains attached after cleanup although the file behind it is gone"},
		{"another real file, the boot cannot be read", "/var/lib/other.img", "47", journal.TrackedLoop{DiskSeq: 47, BootID: thisBoot}, "", errors.New("no /proc"), true, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newHolderFixture(t)
			f.loop("loop0", "loop0p1")
			f.write(filepath.Join(f.root, "loop0", "loop", "backing_file"), c.backing+"\n")
			if c.seq != "" {
				f.write(filepath.Join(f.root, "loop0", "diskseq"), c.seq+"\n")
			}
			f.host.checkLoop = func(string, string) (LoopState, error) { return LoopReused, nil }
			f.host.bootID = func() (string, error) { return c.boot, c.bootErr }
			loop := c.loop
			loop.Device, loop.Backing = "/dev/loop0", recorded
			err := awaitLoopReleased(f.host, loop, 2, 0)
			if len(f.commands) != 0 {
				t.Fatalf("the release check ran %v; it must change nothing", f.commands)
			}
			if c.released {
				if err != nil {
					t.Fatalf("released = %v; want the run's attachment shown gone", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("released = %v; want an error containing %q", err, c.want)
			}
		})
	}
}

// A loop that is still the run's attachment and that an md array holds names
// the array; one that nothing listed holds says what else can hold it.
func TestTheSameAttachmentSaysWhatHoldsIt(t *testing.T) {
	loop := journal.TrackedLoop{Device: "/dev/loop0", Backing: "/run/pbs-loopdev/map.img", DiskSeq: 47, BootID: thisBoot}
	t.Run("held by an array", func(t *testing.T) {
		f := raidFixture(t)
		f.write(filepath.Join(f.root, "loop0", "loop", "backing_file"), "/\n")
		f.write(filepath.Join(f.root, "loop0", "diskseq"), "47\n")
		f.host.checkLoop = func(string, string) (LoopState, error) { return LoopReused, nil }
		f.host.bootID = func() (string, error) { return thisBoot, nil }
		err := awaitLoopReleased(f.host, loop, 1, 0)
		if err == nil || !strings.Contains(err.Error(), "md126") || len(f.commands) != 0 {
			t.Fatalf("released = %v, commands %v; want md126 named and nothing run", err, f.commands)
		}
	})
	t.Run("nothing listed holds it", func(t *testing.T) {
		f := newHolderFixture(t)
		f.loop("loop0", "loop0p1")
		f.write(filepath.Join(f.root, "loop0", "loop", "backing_file"), "/\n")
		f.write(filepath.Join(f.root, "loop0", "diskseq"), "47\n")
		f.host.checkLoop = func(string, string) (LoopState, error) { return LoopReused, nil }
		f.host.bootID = func() (string, error) { return thisBoot, nil }
		err := awaitLoopReleased(f.host, loop, 1, 0)
		if err == nil || !strings.Contains(err.Error(), "lsblk /dev/loop0") || !strings.Contains(err.Error(), "fuser -v /dev/loop0") {
			t.Fatalf("released = %v; want how to see what has it open", err)
		}
	})
}

// The attachment's number is written to the journal and read back.
func TestTrackedLoopKeepsItsAttachmentInTheJournal(t *testing.T) {
	var r journal.Record
	r.AddTrackedLoop(journal.TrackedLoop{Device: "/dev/loop3", Backing: "/run/pbs-loopdev/a.img", DiskSeq: 9, BootID: thisBoot})
	r.AddLoop("/dev/loop3", "/somewhere/else.img") // the same device again is not added twice
	if len(r.Loops) != 1 || r.Loops[0].DiskSeq != 9 || r.Loops[0].BootID != thisBoot || r.LoopDevice != "/dev/loop3" {
		t.Fatalf("record = %+v", r)
	}
}
