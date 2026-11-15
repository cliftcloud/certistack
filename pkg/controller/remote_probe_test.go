// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
)

const unreadableLookup = "unknown stat: cannot statx '/var/lib/certistack/active.json': Input/output error"

// The probe's answer is one of three words; anything else, or a transport
// failure, is an error, never "absent".
func TestRemotePathProbeAnswers(t *testing.T) {
	for _, tc := range []struct {
		answer      string
		wantPresent bool
		wantUnknown bool
	}{
		{"present\n", true, false},
		{"absent\n", false, false},
		{unreadableLookup + "\n", false, true},
		{"unknown\n", false, true},
		{"unknownish\n", false, true},
		{"\n", false, true},
		{"absent but\n", false, true},
	} {
		fake := &fakeCommandRunner{hook: func(name, joined string) ([]byte, error, bool) {
			return []byte(tc.answer), nil, true
		}}
		present, err := (&Executor{runner: fake}).remotePathExists(context.Background(), SSHConfig{Host: "pve.example", User: "root"}, "/var/lib/certistack/active.json")
		var unknown *remoteInspectionError
		if present != tc.wantPresent || errors.As(err, &unknown) != tc.wantUnknown || (err != nil) != tc.wantUnknown {
			t.Errorf("answer %q: present = %v, err = %v; want present %v, unknown %v", tc.answer, present, err, tc.wantPresent, tc.wantUnknown)
		}
	}
	fake := &fakeCommandRunner{hook: func(name, joined string) ([]byte, error, bool) {
		return nil, errors.New("ssh failed: connection reset"), true
	}}
	if present, err := (&Executor{runner: fake}).remotePathExists(context.Background(), SSHConfig{Host: "pve.example", User: "root"}, "/var/lib/certistack/active.json"); present || err == nil {
		t.Errorf("a failed command: present = %v, err = %v; want an error", present, err)
	}
}

// A journal lookup that failed is no record of the run: the check ends in an
// error, the run is not taken as having created nothing, and recovery is not
// run on a journal that was never read.
func TestAnUnknownJournalLookupIsNotNoRecord(t *testing.T) {
	workspaceRoot := "/var/lib/certistack/workers"
	workspace := workspaceRoot + "/" + uuid.NewString()
	for name, fake := range map[string]*fakeCommandRunner{
		"active journal": {journalState: unreadableLookup},
		"transition record": {journalState: "absent", hook: func(name, joined string) ([]byte, error, bool) {
			if strings.Contains(joined, "/runs/run-") && strings.Contains(joined, "if [ -e") {
				return []byte(unreadableLookup + "\n"), nil, true
			}
			return nil, nil, false
		}},
	} {
		var outcome journalOutcome
		err := (&Executor{runner: fake}).reconcileCompletedWorker(context.Background(), SSHConfig{Host: "pve.example", User: "root"}, workspaceRoot, workspace, "/var/lib/certistack", journalCheck{runID: workerRunID(workspace), noRecordIsClean: true, outcome: &outcome})
		var unknown *remoteInspectionError
		if !errors.As(err, &unknown) {
			t.Errorf("%s: err = %v, want the failed lookup reported", name, err)
		}
		if outcome.noRecord || outcome.ownCleaned || outcome.transition || outcome.recovered || fake.recoverCalls != 0 {
			t.Errorf("%s: outcome %+v, recover ran %d times; want nothing concluded", name, outcome, fake.recoverCalls)
		}
	}
}

// A run interrupted before any evidence, whose journal cannot be inspected,
// keeps its workspace and says the cleanup could not be verified. The same
// interruption with a journal that is conclusively absent is the clean exit.
func TestInterruptedRunKeepsItsWorkspaceWhenTheJournalCannotBeInspected(t *testing.T) {
	for _, tc := range []struct {
		name        string
		fake        *fakeCommandRunner
		wantRemoved int
		wantUnknown bool
	}{
		{"journal lookup failed", &fakeCommandRunner{nodeRunError: errors.New("ssh session ended"), journalState: unreadableLookup}, 0, true},
		{"no journal at all", &fakeCommandRunner{nodeRunError: errors.New("ssh session ended"), journalState: "absent"}, 1, false},
	} {
		opts := completedWorkerTeardownOptions(t)
		var progress bytes.Buffer
		opts.Writer = &progress
		_, err := (&Executor{runner: tc.fake}).Run(context.Background(), opts)
		if err == nil {
			t.Fatalf("%s: the run succeeded", tc.name)
		}
		if tc.fake.workspaceRemoveCalls != tc.wantRemoved {
			t.Errorf("%s: the workspace was removed %d times, want %d", tc.name, tc.fake.workspaceRemoveCalls, tc.wantRemoved)
		}
		said := strings.Contains(progress.String(), "Automatic interruption cleanup could not be verified")
		saidNoRecord := strings.Contains(progress.String(), "holds no record of this run")
		if said != tc.wantUnknown || saidNoRecord == tc.wantUnknown {
			t.Errorf("%s: says unverified = %v, says no record = %v:\n%s", tc.name, said, saidNoRecord, progress.String())
		}
		if tc.wantUnknown && !strings.Contains(err.Error(), "could not be verified") {
			t.Errorf("%s: err = %v", tc.name, err)
		}
	}
}
