// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package sysutil

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/internal/journal"
)

// holderFixture is a private sysfs, mount table and command runner. Its
// commands change the sysfs the way the kernel would: a stopped md array or a
// removed device-mapper device leaves every holders directory.
type holderFixture struct {
	t         *testing.T
	root      string
	mountInfo string
	loops     map[string]loopFixtureState // device -> what CheckLoop says
	commands  []string
	writes    []string
	failOn    map[string]error // command line -> its failure
	noEffect  bool             // commands succeed and change nothing
	noMdadm   bool
	host      holderHost
}

type loopFixtureState struct {
	state LoopState
	err   error
}

var loopPartitionExpr = regexp.MustCompile(`^(loop[0-9]+)p[0-9]+$`)

func newHolderFixture(t *testing.T) *holderFixture {
	t.Helper()
	dir := t.TempDir()
	f := &holderFixture{
		t:         t,
		root:      filepath.Join(dir, "sys", "block"),
		mountInfo: filepath.Join(dir, "mountinfo"),
		loops:     map[string]loopFixtureState{},
		failOn:    map[string]error{},
	}
	f.write(f.mountInfo, "22 1 0:21 / /proc rw - proc proc rw\n36 35 8:1 / /boot rw - ext4 /dev/sda1 rw\n")
	f.host = holderHost{
		sysBlock:  f.root,
		mountInfo: f.mountInfo,
		checkLoop: func(device, recorded string) (LoopState, error) {
			if s, ok := f.loops[device]; ok {
				return s.state, s.err
			}
			return LoopRecorded, nil
		},
		lookPath: func(name string) (string, error) {
			if f.noMdadm && name == "mdadm" {
				return "", errors.New("not found")
			}
			return "/usr/sbin/" + name, nil
		},
		run: func(_ context.Context, name string, args ...string) error {
			line := strings.Join(append([]string{name}, args...), " ")
			f.commands = append(f.commands, line)
			if err := f.failOn[line]; err != nil {
				return err
			}
			if f.noEffect {
				return nil
			}
			switch {
			case name == "mdadm" && len(args) == 2 && args[0] == "--stop":
				f.vanish(filepath.Base(args[1]))
			case name == "dmsetup" && len(args) == 3 && args[0] == "remove":
				f.vanish(f.dmKernelName(args[2]))
			}
			return nil
		},
		writeAttr: func(path, value string) error {
			f.writes = append(f.writes, filepath.Base(filepath.Dir(filepath.Dir(path)))+":"+value)
			if value == "clear" && !f.noEffect {
				f.vanish(filepath.Base(filepath.Dir(filepath.Dir(path))))
			}
			return nil
		},
		sleep:          func(time.Duration) {},
		settleAttempts: 3,
		settleInterval: time.Millisecond,
		stopAttempts:   1,
	}
	return f
}

func (f *holderFixture) write(path, content string) {
	f.t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

func (f *holderFixture) mkdir(parts ...string) {
	f.t.Helper()
	if err := os.MkdirAll(filepath.Join(append([]string{f.root}, parts...)...), 0o755); err != nil {
		f.t.Fatal(err)
	}
}

// loop makes /dev/<name> and its partitions (loop0 and "loop0p1", "loop0p2").
func (f *holderFixture) loop(name string, partitions ...string) {
	f.mkdir(name, "loop")
	f.mkdir(name, "holders")
	for _, p := range partitions {
		f.mkdir(name, p, "holders")
	}
}

// array makes an md array or a device-mapper device name (dev is its
// major:minor) over members, held by the loop partitions in heldBy: the paths
// of their holders directories under the sysfs root.
func (f *holderFixture) array(name, dev string, members ...string) {
	f.t.Helper()
	f.mkdir(name, "holders")
	f.mkdir(name, "slaves")
	f.write(filepath.Join(f.root, name, "dev"), dev+"\n")
	if strings.HasPrefix(name, "md") {
		f.write(filepath.Join(f.root, name, "md", "array_state"), "clean\n")
	}
	for _, m := range members {
		f.mkdir(name, "slaves", m)
		f.holds(m, name)
	}
}

// dm is array for a device-mapper device with its name.
func (f *holderFixture) dm(name, dmName, dev string, members ...string) {
	f.t.Helper()
	f.array(name, dev, members...)
	f.write(filepath.Join(f.root, name, "dm", "name"), dmName+"\n")
}

// holds records that holder holds member (a partition such as loop0p1, or an
// md/dm device), as the kernel's holders directory does.
func (f *holderFixture) holds(member, holder string) {
	f.t.Helper()
	dir := filepath.Join(f.root, member, "holders")
	if m := loopPartitionExpr.FindStringSubmatch(member); m != nil {
		dir = filepath.Join(f.root, m[1], member, "holders")
	}
	if err := os.MkdirAll(filepath.Join(dir, holder), 0o755); err != nil {
		f.t.Fatal(err)
	}
}

func (f *holderFixture) mounted(dev, point string) {
	f.t.Helper()
	data, err := os.ReadFile(f.mountInfo)
	if err != nil {
		f.t.Fatal(err)
	}
	f.write(f.mountInfo, string(data)+fmt.Sprintf("40 30 %s / %s rw - xfs none rw\n", dev, point))
}

func (f *holderFixture) mountedFrom(source, point string) {
	f.t.Helper()
	data, err := os.ReadFile(f.mountInfo)
	if err != nil {
		f.t.Fatal(err)
	}
	f.write(f.mountInfo, string(data)+fmt.Sprintf("41 30 0:99 / %s rw - btrfs %s rw\n", point, source))
}

// vanish removes the device and every holders entry that names it.
func (f *holderFixture) vanish(name string) {
	_ = os.RemoveAll(filepath.Join(f.root, name))
	var holdersDirs []string
	_ = filepath.WalkDir(f.root, func(path string, d os.DirEntry, err error) error {
		if err == nil && d.IsDir() && d.Name() == "holders" {
			holdersDirs = append(holdersDirs, path)
		}
		return nil
	})
	for _, dir := range holdersDirs {
		_ = os.RemoveAll(filepath.Join(dir, name))
	}
}

func (f *holderFixture) dmKernelName(dmName string) string {
	entries, _ := os.ReadDir(f.root)
	for _, e := range entries {
		if data, err := os.ReadFile(filepath.Join(f.root, e.Name(), "dm", "name")); err == nil && strings.TrimSpace(string(data)) == dmName {
			return e.Name()
		}
	}
	return ""
}

func (f *holderFixture) owned(devices ...string) []LoopIdentity {
	var ids []LoopIdentity
	for i, d := range devices {
		ids = append(ids, LoopIdentity{Device: d, Backing: fmt.Sprintf("/run/pbs-loopdev/certistack-test-%d.img", i)})
	}
	return ids
}

func (f *holderFixture) holderNames(device string) []string {
	holders, err := f.host.loopHolders(device)
	if err != nil {
		f.t.Fatal(err)
	}
	var names []string
	for _, h := range holders {
		names = append(names, h.Name)
	}
	return names
}

// raidFixture is the reported case: a guest with two disks, RAID1 across
// their partitions, which the host assembled as md126 (partition 1) and md127
// (partition 2).
func raidFixture(t *testing.T) *holderFixture {
	f := newHolderFixture(t)
	f.loop("loop0", "loop0p1", "loop0p2")
	f.loop("loop1", "loop1p1", "loop1p2")
	f.array("md126", "9:126", "loop0p1", "loop1p1")
	f.array("md127", "9:127", "loop0p2", "loop1p2")
	return f
}

func TestReleaseLoopHoldersStopsTheArraysTheHostAssembledFromTheRunsLoops(t *testing.T) {
	f := raidFixture(t)
	stopped, err := f.host.release(context.Background(), "/dev/loop0", f.owned("/dev/loop0", "/dev/loop1"))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(f.commands, "; "); got != "mdadm --stop /dev/md126; mdadm --stop /dev/md127" {
		t.Fatalf("commands = %s", got)
	}
	if len(stopped) != 2 || stopped[0].Name != "md126" || stopped[1].Name != "md127" {
		t.Fatalf("stopped = %+v", stopped)
	}
	// Nothing holds either loop any more, so the unmap that follows can release them.
	for _, device := range []string{"/dev/loop0", "/dev/loop1"} {
		if names := f.holderNames(device); len(names) != 0 {
			t.Fatalf("%s is still held by %v", device, names)
		}
	}
}

// Every holder is judged before one is touched: an array that is not the run's
// is left alone, and so is every other.
func TestReleaseLoopHoldersRefusesWhatIsNotShownToBeTheRuns(t *testing.T) {
	type tc struct {
		name  string
		setup func(f *holderFixture)
		owned []string
		state map[string]loopFixtureState
		want  string
	}
	for _, c := range []tc{
		{
			name: "an array with a member on a loop the run did not map",
			setup: func(f *holderFixture) {
				f.loop("loop5", "loop5p1")
				f.array("md128", "9:128", "loop0p3", "loop5p1")
				f.holds("loop0p3", "md128")
			},
			owned: []string{"/dev/loop0", "/dev/loop1"},
			want:  "md128 has the member loop5p1: /dev/loop5 is not a loop device the run mapped",
		},
		{
			name: "an array with a member on a disk of the host",
			setup: func(f *holderFixture) {
				f.mkdir("sdb", "sdb1", "holders")
				f.array("md128", "9:128", "loop0p3", "sdb1")
				f.holds("loop0p3", "md128")
			},
			owned: []string{"/dev/loop0", "/dev/loop1"},
			want:  "md128 has the member sdb1, which is not a partition of a loop device the run mapped",
		},
		{
			name:  "a member on a loop whose map is no longer the run's",
			owned: []string{"/dev/loop0", "/dev/loop1"},
			state: map[string]loopFixtureState{"/dev/loop1": {state: LoopReused}},
			want:  "md126 has the member loop1p1: /dev/loop1 no longer backs the PBS map the run recorded",
		},
		{
			name:  "a member on a loop whose identity cannot be read",
			owned: []string{"/dev/loop0", "/dev/loop1"},
			state: map[string]loopFixtureState{"/dev/loop1": {err: errors.New("unreadable")}},
			want:  "it cannot be shown that /dev/loop1 is still the run's PBS map",
		},
		{
			name: "an array that lists no members",
			setup: func(f *holderFixture) {
				f.mkdir("md128", "holders")
				f.mkdir("md128", "slaves")
				f.holds("loop0p3", "md128")
			},
			owned: []string{"/dev/loop0", "/dev/loop1"},
			want:  "md128 lists no members",
		},
		{
			name: "a holder of an unknown kind",
			setup: func(f *holderFixture) {
				f.mkdir("sdc", "slaves")
				f.holds("loop0p3", "sdc")
			},
			owned: []string{"/dev/loop0", "/dev/loop1"},
			want:  "sdc is neither a software RAID (md) array nor a device-mapper device",
		},
		{
			name: "a device-mapper device without a usable name",
			setup: func(f *holderFixture) {
				f.dm("dm-3", "-rf", "9:200", "loop0p3")
			},
			owned: []string{"/dev/loop0", "/dev/loop1"},
			want:  "dm-3 has no usable device-mapper name",
		},
		{
			name: "a mounted array",
			setup: func(f *holderFixture) {
				f.mounted("9:127", "/mnt/guest")
			},
			owned: []string{"/dev/loop0", "/dev/loop1"},
			want:  "md127 is mounted at /mnt/guest",
		},
		{
			name: "an array a partition of which is mounted",
			setup: func(f *holderFixture) {
				f.mkdir("md127", "md127p1")
				f.write(filepath.Join(f.root, "md127", "md127p1", "dev"), "259:4\n")
				f.mounted("259:4", "/mnt/guest/data")
			},
			owned: []string{"/dev/loop0", "/dev/loop1"},
			want:  "md127p1 is mounted at /mnt/guest/data",
		},
		{
			name: "a device-mapper device mounted by its name",
			setup: func(f *holderFixture) {
				f.dm("dm-3", "guest-root", "253:3", "loop0p3")
				f.mountedFrom("/dev/mapper/guest-root", "/mnt/root")
			},
			owned: []string{"/dev/loop0", "/dev/loop1"},
			want:  "dm-3 is mounted at /mnt/root",
		},
		{
			name: "an array mounted by its kernel name, on a file system with an anonymous device",
			setup: func(f *holderFixture) {
				f.mountedFrom("/dev/md126", "/mnt/pool")
			},
			owned: []string{"/dev/loop0", "/dev/loop1"},
			want:  "md126 is mounted at /mnt/pool",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := raidFixture(t)
			if c.setup != nil {
				c.setup(f)
			}
			for device, s := range c.state {
				f.loops[device] = s
			}
			stopped, err := f.host.release(context.Background(), "/dev/loop0", f.owned(c.owned...))
			var refusal *ReleaseError
			if !errors.As(err, &refusal) || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("release = %v, want a refusal containing %q", err, c.want)
			}
			if len(f.commands) != 0 || len(f.writes) != 0 || len(stopped) != 0 {
				t.Fatalf("commands %v, writes %v, stopped %v; want nothing touched", f.commands, f.writes, stopped)
			}
			if !strings.Contains(err.Error(), "md126") || !strings.Contains(err.Error(), "/dev/loop0") {
				t.Fatalf("the error does not name the loop and its holders: %v", err)
			}
		})
	}
}

// A device-mapper device over a partition of a tracked loop is removed by the
// name device-mapper gives it, with a retry for a device that is briefly busy.
func TestReleaseLoopHoldersRemovesADeviceMapperDeviceOverATrackedPartition(t *testing.T) {
	f := newHolderFixture(t)
	f.loop("loop0", "loop0p1", "loop0p2")
	f.dm("dm-0", "rl-root", "253:0", "loop0p2")
	stopped, err := f.host.release(context.Background(), "/dev/loop0", f.owned("/dev/loop0"))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(f.commands, "; "); got != "dmsetup remove --retry rl-root" || len(stopped) != 1 || stopped[0].Label() != "dm-0 (rl-root)" {
		t.Fatalf("commands %q, stopped %+v", got, stopped)
	}
}

// An md array that carries a device-mapper layer (LVM on RAID) is released
// children first: the logical volume, then the array under it.
func TestReleaseLoopHoldersReleasesChildrenFirst(t *testing.T) {
	f := newHolderFixture(t)
	f.loop("loop0", "loop0p1")
	f.loop("loop1", "loop1p1")
	f.array("md126", "9:126", "loop0p1", "loop1p1")
	f.dm("dm-0", "vg-lv", "253:0", "md126")
	f.dm("dm-1", "vg-swap", "253:1", "md126")
	stopped, err := f.host.release(context.Background(), "/dev/loop0", f.owned("/dev/loop0", "/dev/loop1"))
	if err != nil {
		t.Fatal(err)
	}
	want := "dmsetup remove --retry vg-lv; dmsetup remove --retry vg-swap; mdadm --stop /dev/md126"
	if got := strings.Join(f.commands, "; "); got != want {
		t.Fatalf("commands = %s, want %s", got, want)
	}
	if len(stopped) != 3 {
		t.Fatalf("stopped = %+v", stopped)
	}
	// A logical volume that is mounted keeps the array under it in place.
	f = newHolderFixture(t)
	f.loop("loop0", "loop0p1")
	f.array("md126", "9:126", "loop0p1")
	f.dm("dm-0", "vg-lv", "253:0", "md126")
	f.mounted("253:0", "/srv")
	if _, err := f.host.release(context.Background(), "/dev/loop0", f.owned("/dev/loop0")); err == nil || !strings.Contains(err.Error(), "dm-0 is mounted at /srv") || len(f.commands) != 0 {
		t.Fatalf("release = %v, commands %v; want the mounted volume to keep the array in place", err, f.commands)
	}
	// A volume over an array that is not the run's is left.
	f = newHolderFixture(t)
	f.loop("loop0", "loop0p1")
	f.mkdir("sdb", "sdb1", "holders")
	f.array("md126", "9:126", "loop0p1", "sdb1")
	f.dm("dm-0", "vg-lv", "253:0", "md126")
	if _, err := f.host.release(context.Background(), "/dev/loop0", f.owned("/dev/loop0")); err == nil || len(f.commands) != 0 {
		t.Fatalf("release = %v, commands %v; want the layered device left", err, f.commands)
	}
}

// Without mdadm an array is stopped through its own sysfs attributes.
func TestReleaseLoopHoldersFallsBackToSysfsWithoutMdadm(t *testing.T) {
	f := raidFixture(t)
	f.noMdadm = true
	stopped, err := f.host.release(context.Background(), "/dev/loop0", f.owned("/dev/loop0", "/dev/loop1"))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.commands) != 0 {
		t.Fatalf("commands = %v, want none", f.commands)
	}
	if got := strings.Join(f.writes, " "); got != "md126:inactive md126:clear md127:inactive md127:clear" || len(stopped) != 2 {
		t.Fatalf("writes = %s, stopped %+v", got, stopped)
	}
}

// A stop that fails ends the release: the holders after it are not touched,
// and the error names the one that failed and what was already stopped.
func TestReleaseLoopHoldersStopsAtAFailure(t *testing.T) {
	f := raidFixture(t)
	f.failOn["mdadm --stop /dev/md127"] = errors.New("mdadm: Cannot get exclusive access to /dev/md127: Perhaps a running process, mounted filesystem or active volume group?")
	f.mkdir("md128", "holders")
	f.mkdir("md128", "slaves", "loop0p3")
	f.holds("loop0p3", "md128")
	stopped, err := f.host.release(context.Background(), "/dev/loop0", f.owned("/dev/loop0", "/dev/loop1"))
	var failure *ReleaseError
	if !errors.As(err, &failure) {
		t.Fatalf("release = %v, want a ReleaseError", err)
	}
	for _, want := range []string{"md127 could not be stopped", "Cannot get exclusive access", "already stopped: md126", "/dev/loop0"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error lacks %q: %v", want, err)
		}
	}
	if got := strings.Join(f.commands, "; "); got != "mdadm --stop /dev/md126; mdadm --stop /dev/md127" {
		t.Fatalf("commands = %s; want md128 untouched after md127 failed", got)
	}
	if len(stopped) != 1 || stopped[0].Name != "md126" {
		t.Fatalf("stopped = %+v", stopped)
	}

	// The first stop failing leaves everything as it was.
	f = raidFixture(t)
	f.failOn["mdadm --stop /dev/md126"] = errors.New("busy")
	if stopped, err := f.host.release(context.Background(), "/dev/loop0", f.owned("/dev/loop0", "/dev/loop1")); err == nil || len(stopped) != 0 || len(f.commands) != 1 {
		t.Fatalf("release = %v, stopped %v, commands %v", err, stopped, f.commands)
	}
}

// A holder the kernel still lists after the stop returned is an error, not a
// release.
func TestReleaseLoopHoldersChecksTheHoldersAreGone(t *testing.T) {
	f := raidFixture(t)
	f.noEffect = true
	stopped, err := f.host.release(context.Background(), "/dev/loop0", f.owned("/dev/loop0", "/dev/loop1"))
	if err == nil || !strings.Contains(err.Error(), "md126, md127 still hold it after they were stopped") || len(stopped) != 2 {
		t.Fatalf("release = %v, stopped %v", err, stopped)
	}
}

// With nothing holding the loop, or a loop that is not the run's, nothing is
// done.
func TestReleaseLoopHoldersWithNothingToRelease(t *testing.T) {
	f := newHolderFixture(t)
	f.loop("loop0", "loop0p1")
	if stopped, err := f.host.release(context.Background(), "/dev/loop0", f.owned("/dev/loop0")); err != nil || stopped != nil || len(f.commands) != 0 {
		t.Fatalf("release = %v, %v, %v", stopped, err, f.commands)
	}
	// A loop device that is not in the sysfs at all.
	if stopped, err := f.host.release(context.Background(), "/dev/loop9", f.owned("/dev/loop9")); err != nil || stopped != nil {
		t.Fatalf("release of a loop that is gone = %v, %v", stopped, err)
	}
	for name, state := range map[string]loopFixtureState{
		"gone":   {state: LoopGone},
		"reused": {state: LoopReused},
	} {
		f := raidFixture(t)
		f.loops["/dev/loop0"] = state
		if stopped, err := f.host.release(context.Background(), "/dev/loop0", f.owned("/dev/loop0", "/dev/loop1")); err != nil || stopped != nil || len(f.commands) != 0 {
			t.Fatalf("%s: release = %v, %v, commands %v; want nothing done to a loop that is not the run's", name, stopped, err, f.commands)
		}
	}
	// Not knowing whose the loop is, nothing is done either.
	f = raidFixture(t)
	f.loops["/dev/loop0"] = loopFixtureState{err: errors.New("unreadable")}
	if _, err := f.host.release(context.Background(), "/dev/loop0", f.owned("/dev/loop0", "/dev/loop1")); err == nil || len(f.commands) != 0 {
		t.Fatalf("release = %v, commands %v", err, f.commands)
	}
	// A loop device the journal does not record is not released at all.
	f = raidFixture(t)
	if _, err := f.host.release(context.Background(), "/dev/loop0", f.owned("/dev/loop3")); err == nil || len(f.commands) != 0 {
		t.Fatalf("release = %v, commands %v; want an untracked loop refused", err, f.commands)
	}
	if _, err := f.host.release(context.Background(), "/dev/sda", f.owned("/dev/sda")); err == nil {
		t.Fatal("a device that is not a loop was accepted")
	}
	// A mount table that cannot be read leaves the holders alone.
	f = raidFixture(t)
	f.host.mountInfo = filepath.Join(f.root, "missing-mountinfo")
	if _, err := f.host.release(context.Background(), "/dev/loop0", f.owned("/dev/loop0", "/dev/loop1")); err == nil || !strings.Contains(err.Error(), "mount table cannot be read") || len(f.commands) != 0 {
		t.Fatalf("release = %v, commands %v", err, f.commands)
	}
}

// A device that holds partitions of two loops (a RAID across both disks) is
// released once, whichever loop is being released.
func TestReleaseLoopHoldersAcrossTwoLoops(t *testing.T) {
	f := raidFixture(t)
	if _, err := f.host.release(context.Background(), "/dev/loop1", f.owned("/dev/loop0", "/dev/loop1")); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(f.commands, "; "); got != "mdadm --stop /dev/md126; mdadm --stop /dev/md127" {
		t.Fatalf("commands = %s", got)
	}
	// With only loop1 tracked, an array that also has a member on loop0 is not the run's.
	f = raidFixture(t)
	if _, err := f.host.release(context.Background(), "/dev/loop1", f.owned("/dev/loop1")); err == nil || len(f.commands) != 0 {
		t.Fatalf("release = %v, commands %v; want the mixed array left", err, f.commands)
	}
}

func TestLoopHoldersAndStopCommands(t *testing.T) {
	f := newHolderFixture(t)
	f.loop("loop0", "loop0p1", "loop0p2")
	f.array("md126", "9:126", "loop0p1")
	f.dm("dm-0", "rl-root", "253:0", "loop0p2")
	f.dm("dm-1", "rl-swap", "253:1", "loop0p2")
	f.mkdir("sdc", "slaves")
	f.holds("loop0p2", "sdc")
	holders, err := f.host.loopHolders("/dev/loop0")
	if err != nil {
		t.Fatal(err)
	}
	var labels []string
	for _, h := range holders {
		labels = append(labels, h.Label())
	}
	if got := strings.Join(labels, ","); got != "dm-0 (rl-root),dm-1 (rl-swap),md126,sdc" {
		t.Fatalf("holders = %s", got)
	}
	want := []string{"dmsetup remove rl-root rl-swap", "mdadm --stop /dev/md126"}
	if got := StopCommands(holders); !equalStrings(got, want) {
		t.Fatalf("StopCommands = %q, want %q", got, want)
	}
	// Two arrays are one command, in order.
	got := StopCommands([]LoopHolder{{Name: "md126"}, {Name: "md127"}})
	if !equalStrings(got, []string{"mdadm --stop /dev/md126 /dev/md127"}) {
		t.Fatalf("StopCommands = %q", got)
	}
	// A device-mapper device whose name cannot be read has no command.
	if got := StopCommands([]LoopHolder{{Name: "dm-9"}}); len(got) != 0 {
		t.Fatalf("StopCommands = %q, want none for a device without a name", got)
	}
	if _, err := f.host.loopHolders("/dev/sda"); err == nil {
		t.Fatal("a device that is not a loop was listed")
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestIsPartitionOf(t *testing.T) {
	for _, c := range []struct {
		parent, child string
		want          bool
	}{
		{"loop0", "loop0p1", true},
		{"loop0", "loop0p12", true},
		{"loop0", "loop0", false},
		{"loop0", "loop0p", false},
		{"loop0", "loop01", false},
		{"loop0", "loop", false},
		{"loop1", "loop10", false},
		{"md126", "md126p2", true},
		{"sda", "sda1", true},
		{"sda", "sdap1", false},
		{"dm-0", "dm-0p1", true},
		{"loop0", "loop0pa", false},
	} {
		if got := isPartitionOf(c.parent, c.child); got != c.want {
			t.Errorf("isPartitionOf(%q, %q) = %v, want %v", c.parent, c.child, got, c.want)
		}
	}
}

// The reported leftover: the run unmapped the loop, the kernel kept it
// (backing "/") because md126 holds it. That is a release that did not happen.
func TestAwaitLoopReleased(t *testing.T) {
	const recorded = "/run/pbs-loopdev/certistack-test-a.img"
	attach := func(f *holderFixture, device, backing string) {
		f.write(filepath.Join(f.root, filepath.Base(device), "loop", "backing_file"), backing+"\n")
	}
	sleeps := 0
	setup := func(f *holderFixture, states ...LoopState) {
		calls := 0
		f.host.sleep = func(time.Duration) { sleeps++ }
		f.host.checkLoop = func(string, string) (LoopState, error) {
			state := states[min(calls, len(states)-1)]
			calls++
			return state, nil
		}
	}

	t.Run("gone after a moment", func(t *testing.T) {
		f := raidFixture(t)
		sleeps = 0
		setup(f, LoopRecorded, LoopRecorded, LoopGone)
		if err := awaitLoopReleased(f.host, journal.TrackedLoop{Device: "/dev/loop0", Backing: recorded}, 10, time.Second); err != nil || sleeps != 2 {
			t.Fatalf("await = %v after %d waits", err, sleeps)
		}
	})
	t.Run("another file's now", func(t *testing.T) {
		f := raidFixture(t)
		setup(f, LoopReused)
		attach(f, "/dev/loop0", "/run/pbs-loopdev/certistack-test-other.img")
		if err := awaitLoopReleased(f.host, journal.TrackedLoop{Device: "/dev/loop0", Backing: recorded}, 3, time.Second); err != nil {
			t.Fatalf("await = %v, want a loop that backs another file to count as released", err)
		}
	})
	t.Run("still the map, held", func(t *testing.T) {
		f := raidFixture(t)
		setup(f, LoopRecorded)
		err := awaitLoopReleased(f.host, journal.TrackedLoop{Device: "/dev/loop0", Backing: recorded}, 3, time.Second)
		if err == nil {
			t.Fatal("a loop that is still the run's map was reported released")
		}
		for _, want := range []string{"/dev/loop0", "md126, md127", "mdadm --stop /dev/md126 /dev/md127", "losetup -d /dev/loop0"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error lacks %q: %v", want, err)
			}
		}
	})
	t.Run("still the map, nothing holds it", func(t *testing.T) {
		f := newHolderFixture(t)
		f.loop("loop0", "loop0p1")
		setup(f, LoopRecorded)
		err := awaitLoopReleased(f.host, journal.TrackedLoop{Device: "/dev/loop0", Backing: recorded}, 2, time.Second)
		if err == nil || !strings.Contains(err.Error(), "/dev/loop0 remains mapped after it was unmapped") || strings.Contains(err.Error(), "held by") {
			t.Fatalf("await = %v", err)
		}
	})
	t.Run("no file behind it and held", func(t *testing.T) {
		f := raidFixture(t)
		setup(f, LoopReused)
		attach(f, "/dev/loop0", "/")
		err := awaitLoopReleased(f.host, journal.TrackedLoop{Device: "/dev/loop0", Backing: recorded}, 2, time.Second)
		if err == nil || !strings.Contains(err.Error(), "remains attached after cleanup although the file behind it is gone") || !strings.Contains(err.Error(), "mdadm --stop /dev/md126 /dev/md127, then losetup -d /dev/loop0") {
			t.Fatalf("await = %v", err)
		}
	})
	t.Run("no file behind it and no listed block holder", func(t *testing.T) {
		f := newHolderFixture(t)
		f.loop("loop0", "loop0p1")
		setup(f, LoopReused)
		attach(f, "/dev/loop0", "/")
		if err := awaitLoopReleased(f.host, journal.TrackedLoop{Device: "/dev/loop0", Backing: recorded}, 2, time.Second); err == nil {
			t.Fatal("a still-attached stale loop with no listed block holder was reported released")
		}
	})
	t.Run("reads nothing and is held", func(t *testing.T) {
		f := raidFixture(t)
		f.host.checkLoop = func(string, string) (LoopState, error) {
			return 0, errors.New("loop device /dev/loop0 has no backing-file identity")
		}
		attach(f, "/dev/loop0", "")
		err := awaitLoopReleased(f.host, journal.TrackedLoop{Device: "/dev/loop0", Backing: recorded}, 2, time.Second)
		if err == nil || !strings.Contains(err.Error(), "remains attached after cleanup although the file behind it is gone") || !strings.Contains(err.Error(), "md126") {
			t.Fatalf("await = %v", err)
		}
	})
	t.Run("unreadable", func(t *testing.T) {
		f := raidFixture(t)
		f.host.checkLoop = func(string, string) (LoopState, error) { return 0, errors.New("sysfs unreadable") }
		err := awaitLoopReleased(f.host, journal.TrackedLoop{Device: "/dev/loop0", Backing: recorded}, 2, time.Second)
		if err == nil || !strings.Contains(err.Error(), "cannot confirm that /dev/loop0 was released") {
			t.Fatalf("await = %v", err)
		}
	})
}

func TestHeldAfterUnmap(t *testing.T) {
	f := raidFixture(t)
	for _, c := range []struct {
		device, backing string
		write           bool
		want            bool
	}{
		{"/dev/loop0", "/", true, true},
		{"/dev/loop0", "/ (deleted)", true, true},
		{"/dev/loop0", "", true, true}, // nothing at all: its file is gone
		{"/dev/loop0", "/run/pbs-loopdev/certistack-test-a.img", true, false},
		{"/dev/loop1", "", false, false}, // no backing file: gone
		{"/dev/sda", "/", false, false},
	} {
		if c.write {
			f.write(filepath.Join(f.root, filepath.Base(c.device), "loop", "backing_file"), c.backing+"\n")
		}
		holders, held := f.host.heldAfterUnmap(c.device)
		if held != c.want || (held && len(holders) != 2) {
			t.Errorf("heldAfterUnmap(%s, backing %q) = %v, %v; want %v", c.device, c.backing, holders, held, c.want)
		}
	}
	// "/" and nothing holds it.
	g := newHolderFixture(t)
	g.loop("loop0", "loop0p1")
	g.write(filepath.Join(g.root, "loop0", "loop", "backing_file"), "/\n")
	if _, held := g.host.heldAfterUnmap("/dev/loop0"); held {
		t.Fatal("a loop nothing holds was reported held")
	}
}

func TestStaleLoopReleaseDoesNotDependOnBlockHolders(t *testing.T) {
	for _, backing := range []string{"/", "/ (deleted)", ""} {
		t.Run(fmt.Sprintf("backing %q", backing), func(t *testing.T) {
			f := newHolderFixture(t)
			f.loop("loop0", "loop0p1")
			f.write(filepath.Join(f.root, "loop0", "loop", "backing_file"), backing+"\n")
			f.host.checkLoop = func(string, string) (LoopState, error) { return LoopReused, nil }
			f.host.sleep = func(time.Duration) {}
			if err := awaitLoopReleased(f.host, journal.TrackedLoop{Device: "/dev/loop0", Backing: "/recorded.img"}, 2, 0); err == nil {
				t.Fatal("still-attached stale loop credited as released")
			}
			if len(f.commands) != 0 {
				t.Fatal("release verification ran a device mutation")
			}
		})
	}
	t.Run("stale attachment actually disappears", func(t *testing.T) {
		f := newHolderFixture(t)
		path := filepath.Join(f.root, "loop0", "loop", "backing_file")
		f.write(path, "/\n")
		f.host.checkLoop = func(string, string) (LoopState, error) {
			if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
				return LoopGone, nil
			}
			return LoopReused, nil
		}
		sleeps := 0
		f.host.sleep = func(time.Duration) {
			sleeps++
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		}
		if err := awaitLoopReleased(f.host, journal.TrackedLoop{Device: "/dev/loop0", Backing: "/recorded.img"}, 3, 0); err != nil || sleeps != 1 {
			t.Fatalf("release = %v after %d waits", err, sleeps)
		}
	})
	t.Run("real replacement is not held against old run", func(t *testing.T) {
		f := raidFixture(t)
		f.write(filepath.Join(f.root, "loop0", "loop", "backing_file"), "/replacement.img\n")
		f.host.checkLoop = func(string, string) (LoopState, error) { return LoopReused, nil }
		if err := awaitLoopReleased(f.host, journal.TrackedLoop{Device: "/dev/loop0", Backing: "/recorded.img"}, 1, 0); err != nil || len(f.commands) != 0 {
			t.Fatalf("replacement = %v, commands %v", err, f.commands)
		}
	})
	t.Run("backing becomes unreadable on second look", func(t *testing.T) {
		f := newHolderFixture(t)
		if err := os.MkdirAll(filepath.Join(f.root, "loop0", "loop", "backing_file"), 0o755); err != nil {
			t.Fatal(err)
		}
		f.host.checkLoop = func(string, string) (LoopState, error) { return LoopReused, nil }
		if err := awaitLoopReleased(f.host, journal.TrackedLoop{Device: "/dev/loop0", Backing: "/recorded.img"}, 1, 0); err == nil {
			t.Fatal("unreadable second look credited as released")
		}
	})
	t.Run("recorded backing reappears on second look", func(t *testing.T) {
		f := newHolderFixture(t)
		f.write(filepath.Join(f.root, "loop0", "loop", "backing_file"), "/recorded.img\n")
		f.host.checkLoop = func(string, string) (LoopState, error) { return LoopReused, nil }
		if err := awaitLoopReleased(f.host, journal.TrackedLoop{Device: "/dev/loop0", Backing: "/recorded.img"}, 1, 0); err == nil {
			t.Fatal("reattached recorded map credited as released")
		}
	})
}

func TestReleaseErrorNamesTheRemedyAndWhatItCannotDo(t *testing.T) {
	err := (&ReleaseError{
		Device:  "/dev/loop0",
		Holders: []LoopHolder{{Name: "md126"}, {Name: "sdc"}},
		Reason:  "sdc is neither a software RAID (md) array nor a device-mapper device, and CertiStack stops nothing else",
	}).Error()
	for _, want := range []string{"/dev/loop0 is held by md126, sdc", "mdadm --stop /dev/md126", "release the others by hand", "certistack-node recover"} {
		if !strings.Contains(err, want) {
			t.Errorf("error lacks %q: %s", want, err)
		}
	}
	err = (&ReleaseError{Device: "/dev/loop0", Holders: []LoopHolder{{Name: "sdc"}}, Reason: "x"}).Error()
	if !strings.Contains(err, "release them by hand") || strings.Contains(err, "mdadm") {
		t.Errorf("error = %s", err)
	}
}

// An array that udev has open for a moment refuses its stop; the stop is
// retried, and an array that stays busy is reported after the attempts.
func TestReleaseLoopHoldersRetriesABusyArray(t *testing.T) {
	f := raidFixture(t)
	f.host.stopAttempts = 3
	busy := 2
	run := f.host.run
	f.host.run = func(ctx context.Context, name string, args ...string) error {
		if len(args) == 2 && args[1] == "/dev/md126" && busy > 0 {
			busy--
			f.commands = append(f.commands, name+" "+strings.Join(args, " "))
			return errors.New("mdadm: Cannot get exclusive access to /dev/md126")
		}
		return run(ctx, name, args...)
	}
	if _, err := f.host.release(context.Background(), "/dev/loop0", f.owned("/dev/loop0", "/dev/loop1")); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(f.commands, "; "); got != "mdadm --stop /dev/md126; mdadm --stop /dev/md126; mdadm --stop /dev/md126; mdadm --stop /dev/md127" {
		t.Fatalf("commands = %s", got)
	}

	f = raidFixture(t)
	f.host.stopAttempts = 3
	f.failOn["mdadm --stop /dev/md126"] = errors.New("busy")
	if _, err := f.host.release(context.Background(), "/dev/loop0", f.owned("/dev/loop0", "/dev/loop1")); err == nil || strings.Count(strings.Join(f.commands, ";"), "md126") != 3 || strings.Contains(strings.Join(f.commands, ";"), "md127") {
		t.Fatalf("release = %v, commands %v; want three attempts at md126 and md127 untouched", err, f.commands)
	}
}
