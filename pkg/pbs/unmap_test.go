// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pbs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/internal/sysutil"
)

const (
	ownedBacking   = "/run/pbs-loopdev/owned-map.img"
	foreignBacking = "/run/pbs-loopdev/foreign-map.img"
)

// unmapFixture is a private sysfs with /dev/loop7 attached to backing, and
// proxmox-backup-client and losetup that only log their calls. The client
// runs clientBody after logging (it may change the sysfs, or fail): Unmap must
// never run it. No real loop device or command is touched: PATH holds only the
// two.
type unmapFixture struct {
	t     *testing.T
	log   string
	state string // the backing_file of /dev/loop7
}

func newUnmapFixture(t *testing.T, backing, clientBody string) *unmapFixture {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake proxmox-backup-client and losetup are shell scripts")
	}
	dir := t.TempDir()
	f := &unmapFixture{t: t, log: filepath.Join(dir, "calls.log"), state: filepath.Join(dir, "sys", "loop7", "loop", "backing_file")}
	old := sysutil.SysBlockDir
	t.Cleanup(func() { sysutil.SysBlockDir = old })
	sysutil.SysBlockDir = filepath.Join(dir, "sys")
	if err := os.MkdirAll(filepath.Dir(f.state), 0o755); err != nil {
		t.Fatal(err)
	}
	if backing != "" {
		f.attach(backing)
	}
	client := "#!/bin/sh\nprintf 'proxmox-backup-client %s\\n' \"$*\" >> '" + f.log + "'\n" + strings.ReplaceAll(clientBody, "STATE", "'"+f.state+"'") + "\n"
	if err := os.WriteFile(filepath.Join(dir, "proxmox-backup-client"), []byte(client), 0o755); err != nil {
		t.Fatal(err)
	}
	losetup := "#!/bin/sh\nprintf 'losetup %s\\n' \"$*\" >> '" + f.log + "'\n"
	if err := os.WriteFile(filepath.Join(dir, "losetup"), []byte(losetup), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	return f
}

// attach makes /dev/loop7 back file.
func (f *unmapFixture) attach(file string) {
	f.t.Helper()
	if err := os.WriteFile(f.state, []byte(file+"\n"), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

// calls is what the fake commands were asked, one line each.
func (f *unmapFixture) calls() string {
	data, _ := os.ReadFile(f.log)
	return strings.TrimSpace(string(data))
}

// stopFails is a stopDaemon that fails the test: it is called for a device
// that is not the run's, which must come first.
func stopFails(t *testing.T) func() error {
	return func() error {
		t.Error("the map's daemon was stopped for a device that is not the run's")
		return nil
	}
}

// The run's map is gone, the loop number is another map's, and a detach by
// path would detach whatever is at the path. Nothing runs against the device:
// the map's daemon is not stopped (it would be signalled for a map that is not
// the run's), the client is not run, and losetup is not run.
func TestUnmapLeavesAReusedLoopAlone(t *testing.T) {
	f := newUnmapFixture(t, foreignBacking, "exit 19")
	for _, stop := range []func() error{nil, stopFails(t)} {
		err := New(Config{}).Unmap(context.Background(), "/dev/loop7", ownedBacking, stop)
		if !errors.Is(err, sysutil.ErrLoopReused) || strings.Contains(err.Error(), "foreign-map") {
			t.Fatalf("Unmap(stop=%v) = %v, want ErrLoopReused without the other file's name", stop != nil, err)
		}
	}
	if err := New(Config{}).Detach(context.Background(), "/dev/loop7", ownedBacking); !errors.Is(err, sysutil.ErrLoopReused) {
		t.Fatalf("Detach = %v, want ErrLoopReused", err)
	}
	if calls := f.calls(); calls != "" {
		t.Fatalf("commands ran against a device that is not the run's:\n%s", calls)
	}
}

// Reuse between the daemon's stop and the detach: the loop number is another
// map's as the daemon exits and releases it, and the detach is not run.
func TestUnmapRechecksBeforeTheDetachThatFollowsTheDaemonsStop(t *testing.T) {
	f := newUnmapFixture(t, ownedBacking, "exit 0")
	stopped := 0
	err := New(Config{}).Unmap(context.Background(), "/dev/loop7", ownedBacking, func() error {
		stopped++
		f.attach(foreignBacking)
		return nil
	})
	if !errors.Is(err, sysutil.ErrLoopReused) {
		t.Fatalf("Unmap = %v, want ErrLoopReused", err)
	}
	if calls := f.calls(); stopped != 1 || calls != "" {
		t.Fatalf("daemon stopped %d times, calls:\n%s\nwant the daemon stopped once and nothing run: the device was another file's before the detach", stopped, calls)
	}
}

// The run's own loop is released: the daemon is stopped first (it releases the
// loop as it exits, which the detach then finds done), or, with no daemon to
// stop, the verified detach alone runs. The client's unmap is never run (it
// signals the PID in the map's pid file unchecked).
func TestUnmapReleasesTheRunsOwnLoopWithoutTheClient(t *testing.T) {
	f := newUnmapFixture(t, ownedBacking, "exit 0")
	var order []string
	err := New(Config{}).Unmap(context.Background(), "/dev/loop7", ownedBacking, func() error {
		order = append(order, "stop daemon")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls := f.calls(); strings.Join(order, ",") != "stop daemon" || calls != "losetup -d /dev/loop7" {
		t.Fatalf("order %v, calls:\n%s\nwant the daemon stopped, then the detach", order, calls)
	}

	// The daemon released the loop as it exited: only the check remains.
	f = newUnmapFixture(t, ownedBacking, "exit 0")
	if err := New(Config{}).Unmap(context.Background(), "/dev/loop7", ownedBacking, func() error {
		return os.Remove(f.state)
	}); err != nil {
		t.Fatal(err)
	}
	if calls := f.calls(); calls != "" {
		t.Fatalf("calls:\n%s\nwant nothing run: the daemon released the loop", calls)
	}

	// Without a daemon to stop (a pid file that names something else), only the
	// verified detach runs.
	f = newUnmapFixture(t, ownedBacking, "exit 0")
	if err := New(Config{}).Unmap(context.Background(), "/dev/loop7", ownedBacking, nil); err != nil {
		t.Fatal(err)
	}
	if calls := f.calls(); calls != "losetup -d /dev/loop7" {
		t.Fatalf("calls:\n%s\nwant the detach only", calls)
	}
}

// A daemon that cannot be stopped leaves the loop attached: nothing is
// detached under it, and its error is the answer.
func TestUnmapLeavesTheLoopWhenTheDaemonCannotBeStopped(t *testing.T) {
	f := newUnmapFixture(t, ownedBacking, "exit 0")
	want := errors.New("the PBS map daemon 4242 was sent SIGINT and has not exited")
	if err := New(Config{}).Unmap(context.Background(), "/dev/loop7", ownedBacking, func() error { return want }); !errors.Is(err, want) {
		t.Fatalf("Unmap = %v, want the daemon's error", err)
	}
	if calls := f.calls(); calls != "" {
		t.Fatalf("calls:\n%s\nwant nothing run", calls)
	}
}

// A device that is gone is released already; one whose identity cannot be
// established, or was never recorded, or that has none, is left alone: the
// daemon is not stopped and nothing runs.
func TestUnmapFailsClosedWhenTheIdentityIsNotKnown(t *testing.T) {
	f := newUnmapFixture(t, "", "exit 0")
	if err := New(Config{}).Unmap(context.Background(), "/dev/loop7", ownedBacking, stopFails(t)); err != nil {
		t.Fatalf("a device that is gone: %v", err)
	}
	f.attach(ownedBacking)
	for name, tc := range map[string]struct {
		device, backing string
	}{
		"no recorded identity":        {"/dev/loop7", ""},
		"a device that is not a loop": {"/dev/nbd0", ownedBacking},
	} {
		err := New(Config{}).Unmap(context.Background(), tc.device, tc.backing, stopFails(t))
		if err == nil || errors.Is(err, sysutil.ErrLoopReused) {
			t.Errorf("%s: Unmap = %v, want an error that is not a reuse", name, err)
		}
	}
	// The kernel's answer cannot be read.
	if err := os.Remove(f.state); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(f.state, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := New(Config{}).Unmap(context.Background(), "/dev/loop7", ownedBacking, stopFails(t)); err == nil || errors.Is(err, sysutil.ErrLoopReused) {
		t.Errorf("an unreadable backing: Unmap = %v, want an error", err)
	}
	if calls := f.calls(); calls != "" {
		t.Fatalf("commands ran without an established identity:\n%s", calls)
	}
}

// Unmap runs no proxmox-backup-client command at all, whatever the client
// would answer or print (so it takes no --ns and has no output to limit).
func TestUnmapRunsNoClientCommand(t *testing.T) {
	spew := "/usr/bin/yes xxxxxxxxxxxxxxx | /usr/bin/head -c " + itoa(pbsCommandOutputLimit+1) + "\nexit 19"
	f := newUnmapFixture(t, ownedBacking, spew)
	if err := New(Config{Namespace: nsTenant}).Unmap(context.Background(), "/dev/loop7", ownedBacking, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if calls := f.calls(); strings.Contains(calls, "proxmox-backup-client") || calls != "losetup -d /dev/loop7" {
		t.Fatalf("calls:\n%s\nwant the detach only: the client's unmap is never run", calls)
	}
}
