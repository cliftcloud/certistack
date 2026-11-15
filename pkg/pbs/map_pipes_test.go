// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pbs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/internal/process"
)

// A map starts a client that forks a daemon and leaves it running: the daemon
// is the run's, recovery stops it, and nothing here may kill it. The fake
// client prints its loop device and ends at once, leaving a "daemon" that holds
// the client's output pipes until released (which the real daemon does not:
// it releases them before the client ends, or the map call would never have
// returned). The call must not wait for it, must not take the output as whole,
// and must leave the daemon alone.
func TestMapDoesNotWaitForADaemonThatHoldsItsPipesAndDoesNotStopIt(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fake proxmox-backup-client is a shell script")
	}
	saved := process.PipeWaitDelay
	process.PipeWaitDelay = 200 * time.Millisecond
	t.Cleanup(func() { process.PipeWaitDelay = saved })

	dir := t.TempDir()
	release, pidFile := filepath.Join(dir, "release"), filepath.Join(dir, "daemon.pid")
	t.Cleanup(func() { _ = os.WriteFile(release, nil, 0o600) })
	script := "#!/bin/sh\n" +
		"/bin/sh -c 'echo $$ > \"$2\"; while [ ! -e \"$1\" ] && [ -d \"${1%/*}\" ]; do /bin/sleep 0.05; done' sh " + release + " " + pidFile + " &\n" +
		"while [ ! -s " + pidFile + " ]; do /bin/sleep 0.01; done\n" +
		"echo /dev/loop9\n"
	if err := os.WriteFile(filepath.Join(dir, "proxmox-backup-client"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))

	type result struct {
		device string
		err    error
	}
	done := make(chan result, 1)
	go func() {
		device, err := (&Client{}).MapWithToken(context.Background(), "vm/100/2026-01-01T00:00:00Z", "drive-scsi0.img.fidx", "")
		done <- result{device, err}
	}()
	var got result
	select {
	case got = <-done:
	case <-time.After(30 * time.Second):
		_ = os.WriteFile(release, nil, 0o600)
		<-done
		t.Fatal("MapWithToken waited for a daemon that holds the client's pipes")
	}
	if got.device != "" || !errors.Is(got.err, process.ErrPipeHeld) {
		t.Fatalf("MapWithToken = %q, %v; want no device and the held pipe reported, not a map taken on output that may be cut short", got.device, got.err)
	}
	data, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat("/proc/" + strconv.Itoa(pid)); err != nil {
		t.Fatalf("the daemon (PID %d) was stopped by the bounded wait: %v", pid, err)
	}
}
