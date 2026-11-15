// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package guestnet

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// The tests that ask netplan's own generator which .network file
// networkd applies used to skip wherever netplan was not installed, so on a CI
// image without it the guard against an existing Netplan definition winning
// over the recovery profile vanished without a sign. A missing generator is now
// a failure wherever CERTISTACK_REQUIRE_NETPLAN is set, which the CI and
// release jobs do after installing netplan.
func TestNetplanStateFailsWhereTheGeneratorIsRequired(t *testing.T) {
	present := filepath.Join(t.TempDir(), "generate")
	if err := os.WriteFile(present, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	absent := filepath.Join(t.TempDir(), "no-such-generator")
	for _, tc := range []struct {
		name, generator, require, want string
	}{
		{"installed", present, "", "run"},
		{"installed and required", present, "1", "run"},
		{"missing on a development machine", absent, "", "skip"},
		{"missing where CI requires it", absent, "1", "fail"},
		{"missing where CI requires it (any non-empty value)", absent, "yes", "fail"},
	} {
		if got := netplanState(tc.generator, tc.require); got != tc.want {
			t.Errorf("%s: netplanState = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// recordedT stands in for the *testing.T a netplan-dependent test calls: it
// records whether the test would have failed or been skipped, and stops the
// call as the real one does.
type recordedT struct {
	testing.TB
	outcome string
}

func (r *recordedT) Helper() {}

func (r *recordedT) Fatalf(string, ...any) {
	r.outcome = "fail"
	runtime.Goexit()
}

func (r *recordedT) Skip(...any) {
	r.outcome = "skip"
	runtime.Goexit()
}

// outcomeOf runs needNetplan as a test would and says what it did.
func outcomeOf(generator, require string) string {
	r := &recordedT{TB: nil, outcome: "ran on"}
	done := make(chan struct{})
	go func() {
		defer close(done)
		needNetplan(r, generator, require)
	}()
	<-done
	return r.outcome
}

func TestNeedNetplanFailsInsteadOfSkippingWhereCIRequiresIt(t *testing.T) {
	present := filepath.Join(t.TempDir(), "generate")
	if err := os.WriteFile(present, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	absent := filepath.Join(t.TempDir(), "no-such-generator")
	for name, tc := range map[string]struct{ generator, require, want string }{
		"installed":                       {present, "", "ran on"},
		"missing, nothing requires it":    {absent, "", "skip"},
		"missing, CI requires it":         {absent, "1", "fail"},
		"installed, CI requires it (run)": {present, "1", "ran on"},
	} {
		if got := outcomeOf(tc.generator, tc.require); got != tc.want {
			t.Errorf("%s: the test would %s, want %s", name, got, tc.want)
		}
	}
}

// Where CI requires netplan, its generator is installed: the job fails here
// even if no other test reaches it.
func TestNetplanIsInstalledWhereCIRequiresIt(t *testing.T) {
	if os.Getenv(requireNetplanEnv) == "" {
		t.Logf("%s is not set: netplan-dependent tests skip on this machine if it lacks %s", requireNetplanEnv, netplanGenerator)
		return
	}
	if _, err := os.Stat(netplanGenerator); err != nil {
		t.Fatalf("%s is set but the netplan generator is missing: %v", requireNetplanEnv, err)
	}
}
