//go:build unix

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The Community Edition's report is unsigned: the report directory's
// permissions are all that keep it as the run wrote it. In a directory other
// users can write, any of them could replace a failed run's report with a
// passing one that verify-report --unsigned then reads as the run's own claim.
// The report directory and the plan's directory in it are refused before the
// run starts when group or other users can write them, with the fix.
func TestReportDirectoryOthersCanWriteIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name       string
		base, plan os.FileMode
	}{
		{"report directory 0777", 0o777, 0},
		{"report directory 0770", 0o770, 0},
		{"plan directory 0757", 0o700, 0o757},
	} {
		out := filepath.Join(t.TempDir(), "reports")
		if err := os.Mkdir(out, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(out, tc.base); err != nil {
			t.Fatal(err)
		}
		bad := out
		if tc.plan != 0 {
			bad = filepath.Join(out, "nightly-web")
			if err := os.Mkdir(bad, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(bad, tc.plan); err != nil {
				t.Fatal(err)
			}
		}
		err := checkReportDirectoryWritable(out, "nightly-web")
		if err == nil || !strings.Contains(err.Error(), "can be written by group or other users") || !strings.Contains(err.Error(), "chmod 700 "+bad) {
			t.Errorf("%s: %v; want a refusal with chmod 700 %s", tc.name, err, bad)
		}
	}
	// The controls: what setup, the installer and the docs make (0700), and a
	// directory others may read but not write (0755), pass; a new plan
	// directory is made 0700.
	for _, mode := range []os.FileMode{0o700, 0o755} {
		out := filepath.Join(t.TempDir(), "reports")
		if err := os.Mkdir(out, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(out, mode); err != nil {
			t.Fatal(err)
		}
		if err := checkReportDirectoryWritable(out, "nightly-web"); err != nil {
			t.Errorf("report directory %04o: %v", mode, err)
		}
	}
}
