//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// localShellRunner runs a recorded SSH command's shell script here, as the
// node's login shell would: from its /bin/sh argument on, each argument is
// already quoted for that shell.
type localShellRunner struct{ calls int }

func (r *localShellRunner) Run(ctx context.Context, name string, args []string) ([]byte, error) {
	r.calls++
	for i, arg := range args {
		if arg == shellQuote("/bin/sh") {
			output, err := exec.CommandContext(ctx, "/bin/sh", "-c", strings.Join(args[i:], " ")).CombinedOutput()
			if err != nil {
				// As runCommand reports a failed ssh: with its stderr.
				return nil, fmt.Errorf("ssh failed: %w: %s", err, strings.TrimSpace(string(output)))
			}
			return output, nil
		}
	}
	return nil, nil
}

// GNU install -d changed an existing state directory's mode (a
// private-mount replay turned /tmp from 1777 to 0700) before the worker
// refused it. The controller's actual workspace preparation, run here on
// real directories, now creates what is absent private and changes nothing
// that exists: a directory that is not private, or a path through a
// symbolic link, is refused as it is.
func TestInstallWorkspaceNeverChangesAnExistingDirectory(t *testing.T) {
	install := func(stateDir string) error {
		workspaceRoot, err := workerWorkspaceRoot(stateDir)
		if err != nil {
			t.Fatal(err)
		}
		workspace := filepath.Join(workspaceRoot, uuid.NewString())
		return (&Executor{runner: &localShellRunner{}}).installWorkspace(context.Background(), SSHConfig{Host: "pve.example", User: "root"}, stateDir, workspaceRoot, "/tmp/unused-staging", workspace, nil)
	}
	mode := func(p string) os.FileMode {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		return info.Mode()
	}

	for name, perm := range map[string]os.FileMode{"shared": os.ModeSticky | 0o777, "readable": 0o755} {
		dir := filepath.Join(t.TempDir(), name)
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, perm); err != nil {
			t.Fatal(err)
		}
		before := mode(dir)
		err := install(dir)
		if err == nil || !strings.Contains(err.Error(), "is not private") || !strings.Contains(err.Error(), "changes nothing there") {
			t.Fatalf("%s: err = %v, want the directory refused", name, err)
		}
		if after := mode(dir); after != before {
			t.Fatalf("%s: mode changed from %v to %v", name, before, after)
		}
		if _, err := os.Stat(filepath.Join(dir, "workers")); !os.IsNotExist(err) {
			t.Fatalf("%s: something was created in the refused directory: %v", name, err)
		}
	}

	// A path through a symbolic link is refused, and nothing is created.
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if err := install(filepath.Join(root, "link", "state")); err == nil || !strings.Contains(err.Error(), "is a symbolic link") {
		t.Fatalf("symlinked path: err = %v", err)
	}
	if entries, _ := os.ReadDir(target); len(entries) != 0 {
		t.Fatalf("symlinked path: created %v", entries)
	}

	// An absent state directory is created private with its children, and a
	// second preparation (a retried one) accepts the private directories.
	fresh := filepath.Join(t.TempDir(), "srv", "certistack")
	for try := 1; try <= 2; try++ {
		if err := install(fresh); err != nil {
			t.Fatalf("try %d: %v", try, err)
		}
	}
	for _, dir := range []string{fresh, filepath.Join(fresh, "workers")} {
		if got := mode(dir).Perm(); got != 0o700 {
			t.Fatalf("%s mode = %v, want 0700", dir, got)
		}
	}
}
