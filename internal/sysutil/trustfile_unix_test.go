//go:build unix

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package sysutil

import (
	"errors"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

type fakeInfo struct {
	mode os.FileMode
	uid  uint32
}

func (f fakeInfo) Name() string       { return "known_hosts" }
func (f fakeInfo) Size() int64        { return 0 }
func (f fakeInfo) Mode() os.FileMode  { return f.mode }
func (f fakeInfo) ModTime() time.Time { return time.Time{} }
func (f fakeInfo) IsDir() bool        { return false }
func (f fakeInfo) Sys() any           { return &syscall.Stat_t{Uid: f.uid} }

// A file the controller trusts is refused when group or other users can write
// it, or when its owner is neither the user running CertiStack nor root, with
// the command that makes it safe.
func TestUnsafeToTrustFollowsStrictModes(t *testing.T) {
	previous := currentUID
	currentUID = func() int { return 1000 }
	t.Cleanup(func() { currentUID = previous })

	for _, tc := range []struct {
		mode    os.FileMode
		uid     uint32
		problem string
		fix     string
	}{
		{0o600, 1000, "", ""},
		{0o644, 1000, "", ""},
		{0o644, 0, "", ""},
		{0o664, 1000, "can be written by group or other users (mode 0664)", "chmod 600 /secure/known_hosts"},
		{0o646, 0, "can be written by group or other users (mode 0646)", "chmod 600 /secure/known_hosts"},
		{0o600, 1001, "is owned by", "sudo chown "},
	} {
		err := UnsafeToTrust("/secure/known_hosts", fakeInfo{mode: tc.mode, uid: tc.uid}, KnownHostsWhat, KnownHostsRisk)
		if tc.problem == "" {
			if err != nil {
				t.Errorf("mode %04o uid %d: %v, want it trusted", tc.mode, tc.uid, err)
			}
			continue
		}
		var untrusted *UntrustedFileError
		if !errors.As(err, &untrusted) || !strings.Contains(untrusted.Problem, tc.problem) || !strings.Contains(untrusted.Fix, tc.fix) {
			t.Errorf("mode %04o uid %d: %v, want %q and %q", tc.mode, tc.uid, err, tc.problem, tc.fix)
		}
		if tc.uid == 1001 && (!strings.Contains(untrusted.Problem, "neither root nor the user CertiStack runs as") || !strings.HasSuffix(untrusted.Fix, " /secure/known_hosts")) {
			t.Errorf("owner refusal: %v", err)
		}
	}
}
