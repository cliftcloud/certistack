//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package recovery

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/sdn/sdntest"
)

// A journal written by a run on a PVE with an SDN lock (PVE 9) holds the lock's
// token. Recovered against a PVE 8, whose DELETE of cluster/sdn/lock is answered
// 501 (or 404), recovery failed on the release and kept the token for good,
// though nothing on a PVE 8 can hold it. These tests give recovery a journal
// image carrying a token, with the run's objects already gone (the path that
// releases the token before anything else), against a PVE 8 fake and against a
// PVE 9 fake that misanswers the release.

// recoveryLogText is what recovery wrote to the state directory's logs.
func recoveryLogText(t *testing.T, dir string) string {
	t.Helper()
	files, _ := filepath.Glob(filepath.Join(dir, "logs", "*.log"))
	var text strings.Builder
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		text.Write(data)
	}
	return text.String()
}

func TestRecoverDropsAPVE9TokenOnAPVE8AndGoesOn(t *testing.T) {
	for _, status := range []int{http.StatusNotImplemented, http.StatusNotFound} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			fake := pve8(sdntest.New())
			fake.NoLockStatus = status
			recoverAgainst(t, fake)
			record := sandboxRecord("recover-pve9-token-on-pve8")
			record.SDNLockToken = "tok-pve9"
			dir := writeRecord(t, record)

			if err := RecoverLocked(dir); err != nil {
				t.Fatalf("RecoverLocked = %v; a token nothing can hold must not fail the recovery", err)
			}
			got := loadRecord(t, dir)
			if got.Phase != "cleaned" || got.SDNLockToken != "" || got.SDNLockRequested != "" {
				t.Fatalf("journal %+v; want it cleaned and the token dropped", got)
			}
			// The release was tried once with the token, and PVE's answer to a
			// request for the lock confirmed there is none; nothing else.
			want := []string{"DELETE cluster/sdn/lock?lock-token=tok-pve9", "POST cluster/sdn/lock"}
			if calls := lockRequests(fake); strings.Join(calls, "\n") != strings.Join(want, "\n") {
				t.Fatalf("lock calls %v, want %v", calls, want)
			}
			if writes := fake.Writes(); len(writes) != 2 {
				t.Fatalf("writes %v; recovery had nothing to write but the two lock requests", writes)
			}
			if text := recoveryLogText(t, dir); !strings.Contains(text, "This PVE has no SDN configuration lock (PVE 8)") || !strings.Contains(text, "dropped from the journal") {
				t.Fatalf("recovery log lacks the status line:\n%s", text)
			} else if strings.Count(text, "no SDN configuration lock") != 1 {
				t.Fatalf("the status line is not said once:\n%s", text)
			}
		})
	}
}

// PVE 9 is unchanged: a lock that stands, and that the release cannot give back,
// is an error that keeps the token, whatever the release was answered. The
// answer "missing" is not trusted alone: PVE's answer to a request for the lock
// says the lock stands.
func TestRecoverKeepsAHeldPVE9LockWhoseReleaseIsAnsweredAsMissing(t *testing.T) {
	for _, status := range []int{http.StatusNotImplemented, http.StatusNotFound} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			fake := sdntest.New()
			fake.Lock = "tok-held"
			fake.Fault("DELETE cluster/sdn/lock", sdntest.Fault{Refuse: "Method 'DELETE /cluster/sdn/lock' not implemented", Status: status})
			recoverAgainst(t, fake)
			record := sandboxRecord("recover-held-lock")
			record.SDNLockToken = "tok-held"
			dir := writeRecord(t, record)

			err := RecoverLocked(dir)
			if err == nil || !strings.Contains(err.Error(), "release PVE's SDN configuration lock") {
				t.Fatalf("RecoverLocked = %v; want the release's error", err)
			}
			if got := loadRecord(t, dir); got.Phase == "cleaned" || got.SDNLockToken != "tok-held" {
				t.Fatalf("journal %+v; want the token kept", got)
			}
			if fake.Lock != "tok-held" {
				t.Fatalf("lock %q; the held lock was disturbed", fake.Lock)
			}
		})
	}
}

// A journaled token whose lock no longer stands on a PVE 9, the release answered
// as missing by something in front of it: PVE grants a lock, so none stood and
// nothing held the token. The probe's own lock is given back and the recovery
// finishes.
func TestRecoverDropsATokenNoLockStandsForWhenTheReleaseIsAnsweredAsMissing(t *testing.T) {
	fake := sdntest.New()
	fake.Fault("DELETE cluster/sdn/lock", sdntest.Fault{Refuse: "Method 'DELETE /cluster/sdn/lock' not implemented", Status: http.StatusNotFound})
	recoverAgainst(t, fake)
	record := sandboxRecord("recover-gone-lock")
	record.SDNLockToken = "tok-gone"
	dir := writeRecord(t, record)

	if err := RecoverLocked(dir); err != nil {
		t.Fatalf("RecoverLocked = %v", err)
	}
	if got := loadRecord(t, dir); got.Phase != "cleaned" || got.SDNLockToken != "" {
		t.Fatalf("journal %+v", got)
	}
	if fake.Lock != "" {
		t.Fatalf("lock %q left standing by the probe", fake.Lock)
	}
}

// Any other failure to release stays an error with the token kept,
// including on a PVE where no lock stands: only the answer "missing" to the
// release of the lock opens the question, and no other 501 or 404 does.
func TestRecoverKeepsAJournaledTokenWhenTheReleaseFailsForAnotherReason(t *testing.T) {
	cases := map[string]sdntest.Fault{
		"a server error": {Refuse: "temporary failure"},
		"forbidden":      {Refuse: "permission denied", Status: http.StatusForbidden},
		"a bad gateway":  {Refuse: "bad gateway", Status: http.StatusBadGateway},
		"a lost reply":   {Lose: true},
	}
	for name, fault := range cases {
		t.Run(name, func(t *testing.T) {
			fake := sdntest.New() // no lock stands
			fake.Fault("DELETE cluster/sdn/lock", fault)
			recoverAgainst(t, fake)
			record := sandboxRecord("recover-release-fails")
			record.SDNLockToken = "tok-kept"
			dir := writeRecord(t, record)
			if err := RecoverLocked(dir); err == nil {
				t.Fatal("a release that failed was not reported")
			}
			if got := loadRecord(t, dir); got.Phase == "cleaned" || got.SDNLockToken != "tok-kept" {
				t.Fatalf("journal %+v; want the token kept", got)
			}
			if calls := lockRequests(fake); len(calls) != 1 || !strings.HasPrefix(calls[0], "DELETE ") {
				t.Fatalf("lock calls %v; no probe is sent for an answer that is not a missing endpoint", calls)
			}
		})
	}
}

// When the release is answered as missing and PVE's answer to the request for
// the lock is not one that settles it either (an error that says nothing of the
// lock), recovery cannot tell a PVE without a lock from a PVE with one: it keeps
// the token, and fails.
func TestRecoverKeepsTheTokenWhenTheProbeSettlesNothing(t *testing.T) {
	fake := sdntest.New()
	fake.Lock = "tok-held"
	fake.Fault("DELETE cluster/sdn/lock", sdntest.Fault{Refuse: "Method 'DELETE /cluster/sdn/lock' not implemented", Status: http.StatusNotImplemented})
	fake.Fault("POST cluster/sdn/lock", sdntest.Fault{Refuse: "boom"})
	recoverAgainst(t, fake)
	record := sandboxRecord("recover-probe-unclear")
	record.SDNLockToken = "tok-held"
	dir := writeRecord(t, record)
	err := RecoverLocked(dir)
	if err == nil || !strings.Contains(err.Error(), "not implemented") || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("RecoverLocked = %v; want the release's error and the probe's answer", err)
	}
	if got := loadRecord(t, dir); got.Phase == "cleaned" || got.SDNLockToken != "tok-held" {
		t.Fatalf("journal %+v; want the token kept", got)
	}
	if fake.Lock != "tok-held" {
		t.Fatalf("lock %q", fake.Lock)
	}
}
