//go:build unix

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package config

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A FIFO, or a device, named like a plan used to make every plan
// loader wait for a writer in os.Open, ahead of the size limit. Both loaders
// now refuse anything that is not a regular file, at once.
func TestLoadersRefuseANonRegularPlanWithoutWaiting(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "plan.yaml")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("no FIFOs here: %v", err)
	}
	for name, path := range map[string]string{"FIFO": fifo, "device": "/dev/zero", "directory": dir} {
		for loader, load := range map[string]func(string) (*Plan, error){"controller": LoadFromFile, "worker": LoadFromFileForWorker} {
			done := make(chan error, 1)
			go func() { _, err := load(path); done <- err }()
			select {
			case err := <-done:
				if err == nil || !strings.Contains(err.Error(), "not a regular file") {
					t.Errorf("%s %s loader: %v", name, loader, err)
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("the %s loader is waiting on a %s", loader, name)
			}
		}
	}
	// A symbolic link to a plan is still a plan.
	real := filepath.Join(dir, "real.yaml")
	if err := os.WriteFile(real, []byte(planText(t, validPlan())), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.yaml")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFromFile(link); err != nil {
		t.Fatalf("a linked plan: %v", err)
	}
}
