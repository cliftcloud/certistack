// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/cliftcloud/certistack/internal/nodesetup"
)

// runRootWithInput runs the CLI with the given standard input and returns what
// it printed to standard output. It is runRoot for commands that read stdin.
func runRootWithInput(t *testing.T, stdin string, args ...string) (string, error) {
	t.Helper()
	// The command that ran is remembered process-wide for the interrupt
	// wording; a test that follows must find it as it was.
	t.Cleanup(func() { activeCommand.Store(""); remoteWorkerStaged.Store(false); localInspection.Store(false) })
	root := newRootCmd(nil)
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&bytes.Buffer{})
	root.SetIn(strings.NewReader(stdin))
	root.SetArgs(args)
	err := root.ExecuteContext(context.Background())
	return out.String(), err
}

// assertGolden compares got with testdata/<name>. UPDATE_GOLDEN=1 rewrites the
// file, which a reviewer then reads in the diff.
func assertGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run the test with UPDATE_GOLDEN=1 to create it)", err)
	}
	if string(want) != got {
		t.Errorf("output differs from testdata/%s (UPDATE_GOLDEN=1 rewrites it):\n--- got ---\n%s\n--- want ---\n%s", name, got, want)
	}
}

// fixedHostKey is a deterministic ED25519 host key, so a golden file holds the
// same fingerprint and known_hosts line on every run.
func fixedHostKey(t *testing.T, seed byte) nodesetup.HostKey {
	t.Helper()
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
	key, err := ssh.NewPublicKey(private.Public())
	if err != nil {
		t.Fatal(err)
	}
	return nodesetup.HostKey{Key: key, Fingerprint: ssh.FingerprintSHA256(key)}
}

// withHostKey makes `setup trust-node` see a node that offers key, and returns
// what it was asked for.
func withHostKey(t *testing.T, key nodesetup.HostKey, err error) *[]string {
	t.Helper()
	previous := fetchNodeHostKey
	t.Cleanup(func() { fetchNodeHostKey = previous })
	var asked []string
	fetchNodeHostKey = func(_ context.Context, host string, port int) (nodesetup.HostKey, error) {
		asked = append(asked, host+":"+strconv.Itoa(port))
		return key, err
	}
	return &asked
}

// newBlockedInput is a standard input nothing is ever typed on: reads wait
// until the returned closer is closed.
func newBlockedInput() (io.Reader, io.Closer) {
	reader, writer := io.Pipe()
	return reader, writer
}
