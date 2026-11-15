// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"path/filepath"
	"testing"
)

// `run --output linger/reports` said "controller output directory must be a
// clean absolute path": not the value, not the flag, not what to give instead
// (lab chaos L10). Each path option that must be absolute names the flag and
// the value as the operator gave them, and says what to use.
func TestAPathOptionThatIsNotAbsoluteNamesTheFlagTheValueAndTheFix(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	want := filepath.Join(dir, "linger", "reports")
	opts := preflightTestOptions(t)
	opts.OutputDir = "linger/reports"
	err := validateOptions(&opts)
	if err == nil || err.Error() != "--output linger/reports is not an absolute path; use "+want {
		t.Fatalf("validateOptions: %v, want %q", err, "--output linger/reports is not an absolute path; use "+want)
	}

	for _, tc := range []struct {
		name  string
		check func() error
		want  string
	}{
		{"an unclean controller output", func() error {
			o := preflightTestOptions(t)
			o.OutputDir = "/var/lib//certistack/../reports/"
			return validateOptions(&o)
		}, "--output /var/lib//certistack/../reports/ is not a clean path (no .., //, ./ or trailing /); use /var/lib/reports"},
		{"the root as controller output", func() error {
			o := preflightTestOptions(t)
			o.OutputDir = "/"
			return validateOptions(&o)
		}, "--output / must be a directory of its own, not the root"},
		{"a control character in the controller output", func() error {
			o := preflightTestOptions(t)
			o.OutputDir = "/var/lib/rep\norts"
			return validateOptions(&o)
		}, `--output "/var/lib/rep\norts" holds a control character`},
		{"a relative remote scratch", func() error {
			o := preflightTestOptions(t)
			o.ScratchDir = "scratch/work"
			return validateOptions(&o)
		}, "--scratch scratch/work is not an absolute path on the node; start it with /, as in /var/lib/certistack/scratch"},
		{"an unclean remote state directory", func() error {
			o := preflightTestOptions(t)
			o.StateDir = "/var/lib/certistack/"
			return validateOptions(&o)
		}, "--state-dir /var/lib/certistack/ is not a clean path (no .., //, ./ or trailing /); use /var/lib/certistack"},
		{"a relative state directory", func() error {
			o := preflightTestOptions(t)
			o.StateDir = "state"
			return validateOptions(&o)
		}, "--state-dir state is not an absolute path on the node; start it with /, as in /var/lib/certistack"},
		{"a relative scratch from the plan or the environment", func() error {
			o := RunOptions{ScratchDir: "work"}
			return resolveScratchDir(&o, nil)
		}, "--scratch work is not an absolute path on the node; start it with /, as in /var/lib/certistack/scratch"},
		{"a relative known_hosts", func() error {
			cfg := preflightTestOptions(t).SSH
			cfg.KnownHostsFile = "known_hosts"
			return validateSSHConfig(cfg)
		}, "--ssh-known-hosts known_hosts is not an absolute path; use " + filepath.Join(dir, "known_hosts")},
		{"a relative identity", func() error {
			cfg := preflightTestOptions(t).SSH
			cfg.IdentityFile = "keys/id"
			return validateSSHConfig(cfg)
		}, "--ssh-identity keys/id is not an absolute path; use " + filepath.Join(dir, "keys", "id")},
	} {
		if err := tc.check(); err == nil || err.Error() != tc.want {
			t.Errorf("%s: err = %v, want %q", tc.name, err, tc.want)
		}
	}
}
