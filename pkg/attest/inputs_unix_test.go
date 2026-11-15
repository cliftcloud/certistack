//go:build unix

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package attest

import (
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// within runs f and fails the test if it does not return, as a load that
// waits on a FIFO's writer would not.
func within(t *testing.T, what string, f func() error) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- f() }()
	select {
	case err := <-done:
		return err
	case <-time.After(10 * time.Second):
		t.Fatalf("%s waited on a special file instead of refusing it", what)
		return nil
	}
}

func makeFIFO(t *testing.T, dir, name string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := unix.Mkfifo(path, 0600); err != nil {
		t.Skipf("named pipes unavailable: %v", err)
	}
	return path
}

// A FIFO, a device, a socket or a directory given as a keyring, a
// public key or a report is refused at once, where a FIFO used to keep the
// verifier waiting for a writer. No writer ever opens these FIFOs.
func TestTrustInputsRefuseSpecialFilesWithoutWaiting(t *testing.T) {
	dir := t.TempDir()
	fifo := makeFIFO(t, dir, "fifo")
	socketDir, err := os.MkdirTemp("", "sock")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(socketDir)
	socketPath := filepath.Join(socketDir, "s")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Skipf("unix sockets unavailable: %v", err)
	}
	defer listener.Close()

	specials := map[string]struct{ path, want string }{
		"FIFO":      {fifo, "a named pipe, not a regular file"},
		"directory": {dir, "a directory, not a regular file"},
		"socket":    {socketPath, "a socket, not a regular file"},
	}
	for _, device := range []string{"/dev/null", "/dev/zero"} {
		if _, err := os.Stat(device); err == nil {
			specials["device "+device] = struct{ path, want string }{device, "a device, not a regular file"}
		}
	}
	loaders := map[string]func(string) error{
		"keyring":    func(p string) error { _, err := LoadKeyringFile(p); return err },
		"public key": func(p string) error { _, err := LoadPublicKeyFile(p); return err },
		"report":     func(p string) error { _, err := ReadRegularFile(p, "report", MaxReportFileBytes); return err },
	}
	for kind, load := range loaders {
		for name, special := range specials {
			path := special.path
			err := within(t, kind+" loader on a "+name, func() error { return load(path) })
			if err == nil || !strings.Contains(err.Error(), special.want) {
				t.Errorf("%s given a %s: %v, want an error containing %q", kind, name, err, special.want)
			}
		}
	}
}

// A symbolic link to a FIFO is refused too, and a FIFO planted in
// place of the file after it was inspected is refused without blocking on
// the open.
func TestReadRegularFileRefusesFIFOReachedOrPlantedLate(t *testing.T) {
	dir := t.TempDir()
	fifo := makeFIFO(t, dir, "fifo")
	link := filepath.Join(dir, "link-to-fifo")
	if err := os.Symlink(fifo, link); err != nil {
		t.Skipf("symbolic links unavailable: %v", err)
	}
	err := within(t, "ReadRegularFile on a link to a FIFO", func() error {
		_, err := ReadRegularFile(link, "keyring", 100)
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "a named pipe") {
		t.Errorf("link to a FIFO: %v", err)
	}

	checked := filepath.Join(dir, "checked")
	if err := os.WriteFile(checked, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	withFileStep(t, func(step, path string) error {
		if step == "input-inspected" && path == checked {
			if err := os.Remove(checked); err != nil {
				return err
			}
			return unix.Mkfifo(checked, 0644)
		}
		return nil
	})
	err = within(t, "ReadRegularFile on a FIFO planted after its inspection", func() error {
		_, err := ReadRegularFile(checked, "keyring", 100)
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "a named pipe") {
		t.Errorf("FIFO planted after the inspection: %v", err)
	}
}

// A keyring reached through a link to a regular file loads (a mounted
// secret store is often laid out with links), and is read once.
func TestKeyringLinkToRegularFileLoads(t *testing.T) {
	pub, _ := newKey(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "..data-keyring")
	if err := os.WriteFile(target, []byte(hex.EncodeToString(pub)+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "keyring")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symbolic links unavailable: %v", err)
	}
	if kr, err := LoadKeyringFile(link); err != nil || len(kr.PublicKeys()) != 1 {
		t.Fatalf("keyring behind a link: %v", err)
	}
	if key, err := LoadPublicKeyFile(link); err != nil || !key.Equal(pub) {
		t.Fatalf("public key behind a link: %v", err)
	}
}
