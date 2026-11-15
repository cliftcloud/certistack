// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pbs

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// spewingClient installs a proxmox-backup-client that writes bytes bytes of x
// for any command, then exits with status 1 (so the failure path is taken) or 0.
func spewingClient(t *testing.T, bytes int, status int) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake proxmox-backup-client is a shell script")
	}
	dir := t.TempDir()
	script := "#!/bin/sh\nyes xxxxxxxxxxxxxxx | head -c " + itoa(bytes) + "\nexit " + itoa(status) + "\n"
	if err := os.WriteFile(filepath.Join(dir, "proxmox-backup-client"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
}

func itoa(n int) string {
	digits := ""
	for ; n > 0; n /= 10 {
		digits = string(rune('0'+n%10)) + digits
	}
	if digits == "" {
		return "0"
	}
	return digits
}

// The client's output was buffered whole, then converted to a string.
// It is now capped (4 MiB for commands, 16 MiB for JSON listings), the client is
// stopped at the cap, and the error withholds what it wrote, as always.
func TestClientOutputIsCappedAndWithheld(t *testing.T) {
	t.Run("a listing past its limit", func(t *testing.T) {
		spewingClient(t, pbsListOutputLimit+1, 0)
		start := time.Now()
		_, err := (&Client{}).LatestSnapshot(context.Background(), "vm/100")
		if err == nil || !strings.Contains(err.Error(), "wrote more output than CertiStack accepts and was stopped") || strings.Contains(err.Error(), "xxxx") {
			t.Fatalf("LatestSnapshot = %v, want the size limit reported and the output withheld", err)
		}
		if time.Since(start) > 20*time.Second {
			t.Fatalf("the client ran %v", time.Since(start))
		}
	})
	t.Run("a command past its limit, even when it would fail anyway", func(t *testing.T) {
		spewingClient(t, pbsCommandOutputLimit+1, 1)
		_, err := (&Client{}).run(context.Background(), 30*time.Second, "restore")
		if err == nil {
			t.Fatal("a client that wrote more than its limit was accepted")
		}
		if failure := commandFailure("restore PBS image", err, []byte("xxxxxxxx")); !strings.Contains(failure.Error(), "wrote more output than CertiStack accepts") || strings.Contains(failure.Error(), "xxxx") {
			t.Fatalf("failure = %v", failure)
		}
	})
	t.Run("output at the limit is accepted", func(t *testing.T) {
		spewingClient(t, pbsCommandOutputLimit, 0)
		out, err := (&Client{}).run(context.Background(), 30*time.Second, "restore")
		// run trims the whitespace at the end of what it read.
		if err != nil || len(out) < pbsCommandOutputLimit-1 {
			t.Fatalf("run = %d bytes, %v; want the whole %d bytes", len(out), err, pbsCommandOutputLimit)
		}
	})
}

// The cap on the map command could be removed with the whole package's tests
// green, since only the listing and the generic command run were held to the
// limit. This makes the call that reads the client's output through it fail
// for a client that writes more than the limit, and accept one that writes
// exactly the limit. (Unmap runs no client command: TestUnmapRunsNoClientCommand.)
func TestMapStopsAClientThatWritesPastTheLimit(t *testing.T) {
	const snapshot, drive = "vm/100/2026-01-01T00:00:00Z", "drive-scsi0.img.fidx"
	t.Run("past the limit", func(t *testing.T) {
		spewingClient(t, pbsCommandOutputLimit+1, 0)
		start := time.Now()
		device, err := (&Client{}).MapWithToken(context.Background(), snapshot, drive, "")
		if err == nil || device != "" || !strings.Contains(err.Error(), "wrote more output than CertiStack accepts and was stopped") || strings.Contains(err.Error(), "xxxx") {
			t.Fatalf("MapWithToken = %q, %v; want the size limit reported and the output withheld", device, err)
		}
		if time.Since(start) > 20*time.Second {
			t.Fatalf("the client ran %v", time.Since(start))
		}
	})
	t.Run("exactly the limit is read, and is not a loop device", func(t *testing.T) {
		spewingClient(t, pbsCommandOutputLimit, 0)
		_, err := (&Client{}).MapWithToken(context.Background(), snapshot, drive, "")
		if err == nil || strings.Contains(err.Error(), "wrote more output") || !strings.Contains(err.Error(), "client output withheld") {
			t.Fatalf("MapWithToken = %v; want the output read whole and refused as not a loop device", err)
		}
	})
}
