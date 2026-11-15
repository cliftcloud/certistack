// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func makeWorkspace(t *testing.T, root, name string, files map[string]string, age time.Duration) string {
	t.Helper()
	dir := filepath.Join(root, name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	then := time.Now().Add(-age)
	for file, body := range files {
		p := filepath.Join(dir, file)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, then, then); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chtimes(dir, then, then); err != nil {
		t.Fatal(err)
	}
	return dir
}

// A retained workspace keeps its logs but loses its credentials once a
// later run holds the host lock with a clean journal. Workspaces that may
// still be in use are left alone.
func TestScrubRetainedWorkspacesRemovesOnlyIdleCredentials(t *testing.T) {
	root := t.TempDir()
	all := map[string]string{
		"runtime.env": "PVE_TOKEN_SECRET=s", "pbs-encryption.key": "k", "certistack-node": "bin",
		"controller.lease": "", "worker-progress.log": "log", "worker-result.json": "{}", "plan.yaml": "plan",
	}
	retained := makeWorkspace(t, root, "0b8e6c2e-8f65-4c55-9b0a-3f4f3c1f5a11", all, 2*time.Hour)
	own := makeWorkspace(t, root, "1c9f7d3f-9076-4d66-8c1b-404f4d2a6b22", all, 2*time.Hour)
	live := makeWorkspace(t, root, "2dab8e40-a187-4e77-9d2c-515a5e3b7c33", all, time.Minute)                                                          // lease renewed a minute ago
	staging := makeWorkspace(t, root, "3ebc9f51-b298-4f88-8e3d-626b6f4c8d44", map[string]string{"runtime.env": "PVE_TOKEN_SECRET=s"}, 10*time.Second) // no lease yet
	other := makeWorkspace(t, root, "not-a-workspace", all, 2*time.Hour)

	scrubbed, err := scrubRetainedWorkspaces(root, own, "run-test", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(scrubbed) != 1 || scrubbed[0] != retained {
		t.Fatalf("scrubbed %v, want only %s", scrubbed, retained)
	}
	for _, name := range retainedSecrets {
		if _, err := os.Lstat(filepath.Join(retained, name)); !os.IsNotExist(err) {
			t.Errorf("%s survived in the retained workspace", name)
		}
	}
	for _, name := range []string{"worker-progress.log", "worker-result.json", "plan.yaml", "controller.lease"} {
		if _, err := os.Stat(filepath.Join(retained, name)); err != nil {
			t.Errorf("evidence %s was removed: %v", name, err)
		}
	}
	note, err := os.ReadFile(filepath.Join(retained, retainedNoteName))
	if err != nil || !strings.Contains(string(note), "run run-test") || !strings.Contains(string(note), "runtime.env") {
		t.Errorf("note = %q, %v", note, err)
	}
	for _, dir := range []string{own, live, staging, other} {
		if _, err := os.Stat(filepath.Join(dir, "runtime.env")); err != nil {
			t.Errorf("%s lost its runtime.env: %v", filepath.Base(dir), err)
		}
	}

	// A second pass finds nothing left to remove.
	if again, err := scrubRetainedWorkspaces(root, own, "run-test", time.Now()); err != nil || len(again) != 0 {
		t.Errorf("second pass scrubbed %v, %v", again, err)
	}
}

func TestScrubRetainedWorkspacesIgnoresSymlinksAndAMissingRoot(t *testing.T) {
	if scrubbed, err := scrubRetainedWorkspaces(filepath.Join(t.TempDir(), "absent"), "", "run", time.Now()); err != nil || scrubbed != nil {
		t.Fatalf("missing root: %v, %v", scrubbed, err)
	}
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	root := t.TempDir()
	target := makeWorkspace(t, t.TempDir(), "elsewhere", map[string]string{"runtime.env": "secret"}, 2*time.Hour)
	if err := os.Symlink(target, filepath.Join(root, "4fcd0a62-c3a9-4a99-9f3e-737c7a5d9e55")); err != nil {
		t.Fatal(err)
	}
	if scrubbed, err := scrubRetainedWorkspaces(root, "", "run", time.Now()); err != nil || len(scrubbed) != 0 {
		t.Fatalf("followed a symlink: %v, %v", scrubbed, err)
	}
	if _, err := os.Stat(filepath.Join(target, "runtime.env")); err != nil {
		t.Fatalf("symlink target lost its runtime.env: %v", err)
	}
}
