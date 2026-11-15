//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
)

// readWatchFixture is a read-only workspace with the files that carry its
// credentials, and a lease watch over it, run by the shell as the node would.
type readWatchFixture struct {
	workspace, lease string
	cmd              *exec.Cmd
	stderr           bytes.Buffer
	done             chan error
}

func startReadWatch(t *testing.T, leaseSeconds, tick int) *readWatchFixture {
	t.Helper()
	stateDir := t.TempDir()
	workspace := filepath.Join(stateDir, "workers", uuid.NewString())
	if err := os.MkdirAll(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"runtime.env", "pbs-encryption.key", "certistack-node", "controller.lease"} {
		if err := os.WriteFile(filepath.Join(workspace, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	f := &readWatchFixture{workspace: workspace, lease: filepath.Join(workspace, "controller.lease"), done: make(chan error, 1)}
	script := readLeaseWatchScript(workspaceShellVariables(f.lease, filepath.Join(workspace, "certistack-node"), stateDir, filepath.Join(workspace, "runtime.env"), filepath.Join(workspace, "worker-progress.log"), workspace), leaseSeconds, tick)
	f.cmd = exec.Command("/bin/sh", "-c", script)
	f.cmd.Stderr = &f.stderr
	if err := f.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.cmd.Process.Kill(); _ = os.RemoveAll(stateDir) })
	go func() { f.done <- f.cmd.Wait() }()
	return f
}

func (f *readWatchFixture) ended(within time.Duration) (bool, error) {
	select {
	case err := <-f.done:
		f.done <- err
		return true, err
	case <-time.After(within):
		return false, nil
	}
}

// A controller that dies leaves a workspace whose lease nobody renews. The
// watch on the node removes it, credentials and all, once the lease is older
// than it allows, without another run having to find it.
func TestReadLeaseWatchRemovesAWorkspaceWhoseLeaseIsNotRenewed(t *testing.T) {
	f := startReadWatch(t, 2, 1)
	if ended, err := f.ended(15 * time.Second); !ended || err != nil {
		t.Fatalf("the watch ended = %v (%v), want it to end cleanly once the lease lapsed:\n%s", ended, err, f.stderr.String())
	}
	if exists(f.workspace) {
		t.Fatal("the workspace, with its credentials, is still there after its lease lapsed")
	}
}

// A live controller renews the lease for as long as the read lasts: the
// workspace stays while it does, and goes only after it stops.
func TestReadLeaseWatchLeavesAWorkspaceWhoseLeaseIsRenewed(t *testing.T) {
	f := startReadWatch(t, 2, 1)
	stop := time.After(4 * time.Second)
	renew := time.NewTicker(300 * time.Millisecond)
	defer renew.Stop()
renewing:
	for {
		select {
		case <-renew.C:
			now := time.Now()
			if err := os.Chtimes(f.lease, now, now); err != nil {
				t.Fatalf("renew: %v", err)
			}
			if !exists(f.workspace) {
				t.Fatalf("the workspace was removed while its lease was being renewed:\n%s", f.stderr.String())
			}
		case <-stop:
			break renewing
		}
	}
	if ended, _ := f.ended(0); ended {
		t.Fatalf("the watch ended while the lease was being renewed:\n%s", f.stderr.String())
	}
	if ended, err := f.ended(15 * time.Second); !ended || err != nil {
		t.Fatalf("the watch ended = %v (%v), want it to end once renewals stopped:\n%s", ended, err, f.stderr.String())
	}
	if exists(f.workspace) {
		t.Fatal("the workspace is still there after the renewals stopped and its lease lapsed")
	}
}

// A controller that is alive removes the workspace itself, and the watch,
// which has no more to watch, ends at once and removes nothing of its own.
func TestReadLeaseWatchEndsWhenTheControllerRemovedTheWorkspace(t *testing.T) {
	f := startReadWatch(t, 90, 1)
	time.Sleep(1500 * time.Millisecond)
	if err := os.RemoveAll(f.workspace); err != nil {
		t.Fatal(err)
	}
	if ended, err := f.ended(10 * time.Second); !ended || err != nil {
		t.Fatalf("the watch ended = %v (%v), want it to end once the workspace was gone:\n%s", ended, err, f.stderr.String())
	}
	if f.stderr.Len() != 0 {
		t.Fatalf("the watch said something: %s", f.stderr.String())
	}
}
