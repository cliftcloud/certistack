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

// The shapes of what `proxmox-backup-client version` writes. The first is
// a test cluster's client 4.2.5 against its server; the others are what it
// writes when it cannot reach the server, and what other output around the
// lines does to them.
func TestParseVersionOutput(t *testing.T) {
	for _, tc := range []struct {
		name, output   string
		client, server string
	}{
		{"client and server", "client version: 4.2.5\nserver version: 4.2.7\n", "4.2.5", "4.2.7"},
		{"older pair", "client version: 3.3.7\nserver version: 3.4.0\n", "3.3.7", "3.4.0"},
		{"no server line", "client version: 3.3.7\n", "3.3.7", ""},
		{"server unreachable", "could not connect to server - error trying to connect: tcp connect error\nclient version: 4.2.5\n", "4.2.5", ""},
		{"extra lines around", "WARNING: something\nclient version: 4.2.5\n\nserver version: 4.2.7\ndone\n", "4.2.5", "4.2.7"},
		{"carriage returns", "client version: 4.2.5\r\nserver version: 4.2.7\r\n", "4.2.5", "4.2.7"},
		{"no final newline", "client version: 4.2.5\nserver version: 4.2.7", "4.2.5", "4.2.7"},
		{"server first", "server version: 4.2.7\nclient version: 4.2.5\n", "4.2.5", "4.2.7"},
		{"capitals and no space", "Client Version:4.2.5\nSERVER VERSION:   4.2.7  \n", "4.2.5", "4.2.7"},
		{"a Debian revision", "client version: 3.3.7-1\n", "3.3.7-1", ""},
		{"the first of each wins", "client version: 4.2.5\nclient version: 1.0.0\nserver version: 4.2.7\nserver version: 2.0.0\n", "4.2.5", "4.2.7"},
		{"no value", "client version:\nserver version:   \n", "", ""},
		{"a line that names neither", "version: 4.2.5\nthe client version is 4.2.5\n", "", ""},
		{"garbage", "\x00\x01 not a version at all", "", ""},
		{"empty", "", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, server := ParseVersionOutput([]byte(tc.output))
			if client != tc.client || server != tc.server {
				t.Errorf("ParseVersionOutput = %q, %q; want %q, %q", client, server, tc.client, tc.server)
			}
		})
	}
}

// fakeVersionClient installs a proxmox-backup-client that records its
// arguments and credentials in dir/seen and then runs script.
func fakeVersionClient(t *testing.T, script string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake proxmox-backup-client is a shell script")
	}
	dir := t.TempDir()
	body := "#!/bin/sh\n" +
		"printf '%s|%s|%s|%s\\n' \"$*\" \"$PBS_REPOSITORY\" \"$PBS_PASSWORD\" \"$PBS_FINGERPRINT\" > " + filepath.Join(dir, "seen") + "\n" +
		script + "\n"
	if err := os.WriteFile(filepath.Join(dir, "proxmox-backup-client"), []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	return filepath.Join(dir, "seen")
}

func TestVersionsRunsTheClientWithTheRepositoryAndReadsBothVersions(t *testing.T) {
	seen := fakeVersionClient(t, "echo 'client version: 4.2.5'; echo 'server version: 4.2.7'")
	client := New(Config{Repository: "certistack@pbs!restore@pbs.lab.example:backup-store", Password: "s3cret", Fingerprint: "aa:bb"})
	gotClient, gotServer, err := client.Versions(context.Background())
	if err != nil || gotClient != "4.2.5" || gotServer != "4.2.7" {
		t.Fatalf("Versions = %q, %q, %v", gotClient, gotServer, err)
	}
	data, readErr := os.ReadFile(seen)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if got, want := strings.TrimSpace(string(data)), "version|certistack@pbs!restore@pbs.lab.example:backup-store|s3cret|aa:bb"; got != want {
		t.Errorf("the client ran as %q, want %q", got, want)
	}
}

func TestVersionsWithoutAServerReturnsTheClientAlone(t *testing.T) {
	fakeVersionClient(t, "echo 'client version: 3.3.7'; echo 'could not connect to server - tcp connect error: pbs.lab.example refused' >&2")
	gotClient, gotServer, err := New(Config{}).Versions(context.Background())
	if err != nil || gotClient != "3.3.7" || gotServer != "" {
		t.Fatalf("Versions = %q, %q, %v; want the client's version alone and no error", gotClient, gotServer, err)
	}
}

func TestVersionsReadsWhatAFailingClientPrinted(t *testing.T) {
	fakeVersionClient(t, "echo 'client version: 4.2.5'; exit 1")
	gotClient, _, err := New(Config{}).Versions(context.Background())
	if err != nil || gotClient != "4.2.5" {
		t.Fatalf("Versions = %q, %v; a version that was printed is a version", gotClient, err)
	}
}

// A client that printed no version is an error the caller turns into
// "unknown"; its output, which can echo the repository, stays out of it.
func TestVersionsErrorWithholdsTheClientsOutput(t *testing.T) {
	fakeVersionClient(t, "echo 'Error: authentication failed for certistack@pbs!restore@pbs.lab.example:backup-store' >&2; exit 255")
	_, _, err := New(Config{Repository: "certistack@pbs!restore@pbs.lab.example:backup-store"}).Versions(context.Background())
	if err == nil {
		t.Fatal("a client that printed no version and failed was not an error")
	}
	for _, leaked := range []string{"pbs.lab.example", "certistack@pbs", "backup-store", "authentication failed"} {
		if strings.Contains(err.Error(), leaked) {
			t.Errorf("error names %q: %v", leaked, err)
		}
	}
}

func TestVersionsWithNoClientInstalledIsAnError(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if _, _, err := New(Config{}).Versions(context.Background()); err == nil {
		t.Fatal("no proxmox-backup-client on the path was not an error")
	}
}

func TestVersionsStopsWithItsContext(t *testing.T) {
	fakeVersionClient(t, "sleep 30")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := New(Config{}).Versions(ctx); err == nil {
		t.Fatal("a cancelled context was not an error")
	}
}

// Each operation's own time limit holds under a caller's longer deadline. The
// daemon runs the engine under its run budget (hours); a hung client call
// must not hold the run, its slot and the host lock for that long.
func TestOperationLimitsHoldUnderALongerCallerDeadline(t *testing.T) {
	// exec: the client itself is the sleeper, so killing it frees the pipe
	// (a child that kept the pipe open is the inherited-pipe wait, F104).
	fakeVersionClient(t, "exec sleep 5")
	long, cancel := context.WithTimeout(context.Background(), time.Hour)
	defer cancel()

	start := time.Now()
	if _, err := New(Config{}).run(long, 200*time.Millisecond, "snapshot", "list"); err == nil || time.Since(start) > 3*time.Second {
		t.Fatalf("run under a one-hour deadline: err = %v after %v, want the 200 ms limit to end it", err, time.Since(start))
	}

	previous := versionTimeout
	versionTimeout = 200 * time.Millisecond
	t.Cleanup(func() { versionTimeout = previous })
	start = time.Now()
	if _, _, err := New(Config{}).Versions(long); err == nil || time.Since(start) > 3*time.Second {
		t.Fatalf("Versions under a one-hour deadline: err = %v after %v, want the limit to end it", err, time.Since(start))
	}
}
