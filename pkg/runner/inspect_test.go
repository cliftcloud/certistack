// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package runner

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/internal/journal"
	"github.com/cliftcloud/certistack/pkg/initplan"
	"github.com/cliftcloud/certistack/pkg/orchestrator"
	"github.com/cliftcloud/certistack/pkg/pbs"
)

// fakeProfiles are the backed-up configurations of the test's VMs.
type fakeProfiles map[string]pbs.VMProfile

func (f fakeProfiles) LoadVMProfile(_ context.Context, snapshot, _ string) (pbs.VMProfile, error) {
	profile, ok := f[snapshot]
	if !ok {
		return pbs.VMProfile{}, errors.New("snapshot not found")
	}
	return profile, nil
}

// inspectionSeams replaces PBS, the orchestrator's inspection and the
// admission check: inspect is handed what the runner gives the orchestrator.
func inspectionSeams(t *testing.T, profiles fakeProfiles, inspect func(context.Context, []orchestrator.InspectTarget, func(context.Context) error, func(context.Context, orchestrator.InspectTarget, []string) error) ([]orchestrator.InspectOutcome, orchestrator.InspectCleanup, error)) {
	t.Helper()
	previousBackups, previousInspect, previousAdmission := inspectionBackups, inspectBackups, inspectionAdmission
	t.Cleanup(func() {
		inspectionBackups, inspectBackups, inspectionAdmission = previousBackups, previousInspect, previousAdmission
	})
	inspectionBackups = func(string) (inspectionProfiles, *pbs.Client, error) {
		return profiles, pbs.New(pbs.Config{Repository: "u@pbs!tok@pbs.example:store"}), nil
	}
	inspectionAdmission = func(context.Context) error { return nil }
	inspectBackups = func(ctx context.Context, _ *orchestrator.Orchestrator, targets []orchestrator.InspectTarget, admit func(context.Context) error, read func(context.Context, orchestrator.InspectTarget, []string) error) ([]orchestrator.InspectOutcome, orchestrator.InspectCleanup, error) {
		return inspect(ctx, targets, admit, read)
	}
}

func inspectRequest(ids ...int) initplan.InspectRequest {
	req := initplan.InspectRequest{Node: "pve1"}
	for _, id := range ids {
		req.Targets = append(req.Targets, initplan.InspectTarget{SourceVMID: id, Snapshot: fmt.Sprintf("vm/%d/2026-10-01T02:00:00Z", id)})
	}
	return req
}

func linuxProfile(drives ...string) pbs.VMProfile {
	profile := pbs.VMProfile{OSType: "l26"}
	for _, drive := range drives {
		profile.Drives = append(profile.Drives, pbs.SourceDrive{Slot: drive, Archive: "drive-" + drive})
	}
	return profile
}

// The runner journals the inspection before anything is mapped, as a run
// journals itself, hands the orchestrator each Linux VM's disks from its
// backup, and files what the reader found, and what went wrong, per VM.
func TestInspectLockedJournalsAndInspectsEachLinuxVM(t *testing.T) {
	stateDir := t.TempDir()
	profiles := fakeProfiles{
		"vm/100/2026-10-01T02:00:00Z": linuxProfile("scsi0", "scsi1"),
		"vm/101/2026-10-01T02:00:00Z": {OSType: "win11", Drives: []pbs.SourceDrive{{Slot: "scsi0", Archive: "drive-scsi0"}}},
		"vm/103/2026-10-01T02:00:00Z": linuxProfile("virtio0"),
	}
	var handed []orchestrator.InspectTarget
	inspectionSeams(t, profiles, func(ctx context.Context, targets []orchestrator.InspectTarget, admit func(context.Context) error, read func(context.Context, orchestrator.InspectTarget, []string) error) ([]orchestrator.InspectOutcome, orchestrator.InspectCleanup, error) {
		handed = targets
		record, err := journal.Load(filepath.Join(stateDir, "active.json"))
		if err != nil || record.RunID != "run-inspect-1" || record.Phase != "running" {
			t.Errorf("before the first map the journal is %+v (%v), want the inspection's, running", record, err)
		}
		if admit == nil {
			t.Error("no admission check is handed to the orchestrator")
		}
		var outcomes []orchestrator.InspectOutcome
		for _, target := range targets {
			outcomes = append(outcomes, orchestrator.InspectOutcome{Target: target, Err: read(ctx, target, []string{"/dev/loop7"})})
		}
		return outcomes, orchestrator.InspectCleanup{Verified: true}, nil
	})
	read := func(_ context.Context, devices []string) (initplan.GuestFindings, error) {
		if strings.Join(devices, ",") != "/dev/loop7" {
			t.Errorf("read handed %v", devices)
		}
		return initplan.GuestFindings{OS: "Rocky Linux 9.4", Services: []initplan.Service{{Kind: initplan.ServiceNginx, Unit: "nginx.service", Listeners: []initplan.Listener{{Port: 80, HTTP: true}}}}}, nil
	}
	in := InspectLocked(context.Background(), inspectRequest(100, 101, 102, 103), InspectOptions{NodeName: "pve1", StateDir: stateDir, ScratchDir: filepath.Join(t.TempDir(), "scratch"), RunID: "run-inspect-1"}, read)
	if in.Refused != "" || !in.Journaled || !in.CleanupVerified || len(in.VMs) != 4 {
		t.Fatalf("inspection %+v", in)
	}
	if len(handed) != 2 || handed[0].SourceVMID != 100 || len(handed[0].Drives) != 2 || handed[0].Drives[1].Archive != "drive-scsi1" || handed[1].SourceVMID != 103 {
		t.Fatalf("the orchestrator was handed %+v", handed)
	}
	if in.VMs[0].OS != "Rocky Linux 9.4" || len(in.VMs[0].Services) != 1 || in.VMs[0].Skipped != "" {
		t.Fatalf("VM 100: %+v", in.VMs[0])
	}
	if !strings.Contains(in.VMs[1].Skipped, `guest OS type "win11"`) {
		t.Fatalf("VM 101: %+v", in.VMs[1])
	}
	if !strings.Contains(in.VMs[2].Skipped, "could not be read") {
		t.Fatalf("VM 102: %+v", in.VMs[2])
	}
}

// What the orchestrator reports per VM is the answer: a VM it skipped, a
// read that failed, a cleanup it could not verify, an interruption.
func TestInspectLockedReportsWhatTheOrchestratorSaid(t *testing.T) {
	stateDir := t.TempDir()
	profiles := fakeProfiles{"vm/100/2026-10-01T02:00:00Z": linuxProfile("scsi0"), "vm/101/2026-10-01T02:00:00Z": linuxProfile("scsi0")}
	inspectionSeams(t, profiles, func(_ context.Context, targets []orchestrator.InspectTarget, _ func(context.Context) error, _ func(context.Context, orchestrator.InspectTarget, []string) error) ([]orchestrator.InspectOutcome, orchestrator.InspectCleanup, error) {
		return []orchestrator.InspectOutcome{
				{Target: targets[0], Err: fmt.Errorf("%w: PBS loop device /dev/loop7 remains mapped after cleanup", orchestrator.ErrMapsNotReleased)},
				{Target: targets[1], Skipped: "a map of an earlier VM's backup could not be shown released, so nothing more was mapped"},
			}, orchestrator.InspectCleanup{Errors: []string{"PBS loop device /dev/loop7 remains mapped after cleanup"}},
			&orchestrator.InterruptedError{Signal: "SIGTERM"}
	})
	in := InspectLocked(context.Background(), inspectRequest(100, 101), InspectOptions{NodeName: "pve1", StateDir: stateDir, ScratchDir: filepath.Join(t.TempDir(), "scratch"), RunID: "run-inspect-2"}, func(context.Context, []string) (initplan.GuestFindings, error) {
		return initplan.GuestFindings{}, nil
	})
	if !in.Journaled || in.CleanupVerified || len(in.CleanupErrors) != 1 || in.Interrupted != "interrupted by SIGTERM" {
		t.Fatalf("inspection %+v", in)
	}
	if !strings.Contains(in.VMs[0].Failed, "remains mapped") || !strings.Contains(in.VMs[1].Skipped, "nothing more was mapped") {
		t.Fatalf("VMs %+v", in.VMs)
	}
}

// Nothing is mapped while the node's journal records an unfinished run, and
// a request with no Linux VM to read leaves the journal as it was.
func TestInspectLockedMapsNothingItMayNot(t *testing.T) {
	called := false
	inspectionSeams(t, fakeProfiles{"vm/100/2026-10-01T02:00:00Z": {OSType: "other"}}, func(context.Context, []orchestrator.InspectTarget, func(context.Context) error, func(context.Context, orchestrator.InspectTarget, []string) error) ([]orchestrator.InspectOutcome, orchestrator.InspectCleanup, error) {
		called = true
		return nil, orchestrator.InspectCleanup{}, nil
	})
	read := func(context.Context, []string) (initplan.GuestFindings, error) { return initplan.GuestFindings{}, nil }

	stateDir := t.TempDir()
	if err := journal.Write(filepath.Join(stateDir, "active.json"), journal.Record{RunID: "run-crashed", Phase: "running", UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	in := InspectLocked(context.Background(), inspectRequest(100), InspectOptions{NodeName: "pve1", StateDir: stateDir, ScratchDir: filepath.Join(t.TempDir(), "scratch"), RunID: "run-inspect-3"}, read)
	if !strings.Contains(in.Refused, `recovery journal for run "run-crashed" is phase "running"`) || in.Journaled || called {
		t.Fatalf("over an unfinished journal: %+v (orchestrator called %v)", in, called)
	}
	if record, _ := journal.Load(filepath.Join(stateDir, "active.json")); record.RunID != "run-crashed" {
		t.Fatalf("the unfinished journal was replaced: %+v", record)
	}

	stateDir = t.TempDir()
	in = InspectLocked(context.Background(), inspectRequest(100), InspectOptions{NodeName: "pve1", StateDir: stateDir, ScratchDir: filepath.Join(t.TempDir(), "scratch"), RunID: "run-inspect-4"}, read)
	if in.Journaled || called || !strings.Contains(in.VMs[0].Skipped, `guest OS type "other"`) {
		t.Fatalf("a guest that is not Linux: %+v (orchestrator called %v)", in, called)
	}
	if _, err := journal.Load(filepath.Join(stateDir, "active.json")); err == nil {
		t.Fatal("a journal was started with nothing to map")
	}
}
