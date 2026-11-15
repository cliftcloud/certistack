//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package recovery

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/internal/journal"
)

// The race of audit F30: proxmox-backup-client unmap rereads the map's pid file
// and signals that bare PID, after recovery has looked at the process. Recovery
// now stops the map's daemon itself, through a pidfd it opened for the process
// it verified, and only detaches the loop. This test runs recovery of a
// recorded loop whose pid file names the run's own daemon, a real process,
// and the host's real /proc: the client's unmap is never run, the daemon is sent
// SIGINT (what the client's unmap sends), and the loop is then released by the
// verified detach. (The old code ran the client and left the daemon to it, so
// this test fails there: that is how the new behaviour is pinned where the race
// itself cannot be made to happen on demand.)
func TestRecoverLockedStopsTheRunsDaemonItselfAndNeverRunsTheClientsUnmap(t *testing.T) {
	signalFile := filepath.Join(t.TempDir(), "signal")
	daemon := startFakeClient(t, "record", realMapArgv(ownRepo), append(realMapEnv(ownRepo, "team-a", ownToken), fakeClientSignalFile+"="+signalFile))
	real := realReaper()
	maps := hostWithProcs(t, t.TempDir(), noSignal(t))
	hostMapReaper = real
	log := fakeLoopTools(t, "exit 0")
	recorded := filepath.Join(maps.runDir, "repo"+scsi1Tail)
	maps.add("loop7", maps.runDir, "repo"+scsi1Tail, time.Time{})
	if err := os.WriteFile(strings.TrimSuffix(recorded, ".img")+".pid", []byte(strconv.Itoa(daemon.id.PID)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	intent := intentFor(t, daemon)
	intent.Device = "/dev/loop7"
	stateDir := t.TempDir()
	path := journalOf(t, stateDir, []journal.TrackedLoop{{Device: "/dev/loop7", Backing: recorded}}, intent)

	if err := RecoverLocked(stateDir); err != nil {
		t.Fatalf("recovery: %v", err)
	}
	if !daemon.exited(5 * time.Second) {
		t.Fatal("the run's map daemon was not stopped by recovery")
	}
	if got, _ := os.ReadFile(signalFile); string(got) != "interrupt" {
		t.Fatalf("the daemon received %q, want SIGINT (\"interrupt\"), which is what the client's unmap sends", got)
	}
	if calls := callsIn(log); calls != "losetup -d /dev/loop7" {
		t.Fatalf("calls:\n%s\nwant the verified detach only: the client's unmap rereads the pid file and signals a bare PID", calls)
	}
	if phase := phaseOf(t, path); phase != "cleaned" {
		t.Fatalf("phase = %q", phase)
	}
}
