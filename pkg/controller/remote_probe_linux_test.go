//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// shellOnThisHostRunner stands in for ssh: it runs the remote command string
// the way the node's login shell does (every argument after the target, joined
// by spaces, handed to "sh -c"), so a probe script is exercised for real.
type shellOnThisHostRunner struct{ target string }

func (r shellOnThisHostRunner) Run(ctx context.Context, name string, args []string) ([]byte, error) {
	for i, arg := range args {
		if arg == r.target {
			return exec.CommandContext(ctx, "/bin/sh", "-c", strings.Join(args[i+1:], " ")).Output()
		}
	}
	return nil, errors.New("no ssh target in " + strings.Join(args, " "))
}

// A remote existence probe tells a path that is present from one that is
// definitely absent (the filesystem says "no such file or directory") from one
// it could not inspect. "[ -e path ]" is false for all three, so a probe that
// prints "absent" whenever the test is false reports an unreadable journal as
// no journal at all.
func TestRemotePathProbeSeparatesAbsenceFromAFailedLookup(t *testing.T) {
	root := t.TempDir()
	present := filepath.Join(root, "active.json")
	if err := os.WriteFile(present, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A directory this user cannot search: the lookup of anything beneath it
	// fails with EACCES, which says nothing of whether the path exists.
	sealed := filepath.Join(root, "sealed")
	if err := os.Mkdir(sealed, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sealed, "active.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sealed, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(sealed, 0o755) })
	sealedProbe := filepath.Join(sealed, "active.json")
	if _, err := os.Stat(sealedProbe); err == nil {
		t.Skip("this user can search a mode 0 directory (root): a failed lookup cannot be made here")
	}
	// A symlink that points at itself: ELOOP.
	loop := filepath.Join(root, "loop")
	if err := os.Symlink(loop, loop); err != nil {
		t.Fatal(err)
	}
	// A path beneath a regular file: ENOTDIR.
	underFile := filepath.Join(present, "below")

	cfg := SSHConfig{Host: "node.test", User: "root"}
	executor := &Executor{runner: shellOnThisHostRunner{target: "root@node.test"}}
	for _, tc := range []struct {
		name        string
		path        string
		wantPresent bool
		wantUnknown bool
	}{
		{"present", present, true, false},
		{"absent in an existing directory", filepath.Join(root, "missing.json"), false, false},
		{"absent below a directory that does not exist", filepath.Join(root, "no-such-dir", "active.json"), false, false},
		{"unreadable directory", sealedProbe, false, true},
		{"symlink loop", filepath.Join(loop, "active.json"), false, true},
		{"beneath a file", underFile, false, true},
	} {
		got, err := executor.remotePathExists(context.Background(), cfg, tc.path)
		var unknown *remoteInspectionError
		if errors.As(err, &unknown) != tc.wantUnknown || (err != nil) != tc.wantUnknown {
			t.Errorf("%s: err = %v, want an unknown outcome = %v", tc.name, err, tc.wantUnknown)
			continue
		}
		if got != tc.wantPresent {
			t.Errorf("%s: present = %v, want %v", tc.name, got, tc.wantPresent)
		}
	}
}
