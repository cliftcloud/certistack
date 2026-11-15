// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/internal/journal"
	"github.com/cliftcloud/certistack/pkg/cleanup"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/pbs"
)

// artifactOrch is an orchestrator that tracks artifacts and cleans them up.
func artifactOrch(t *testing.T) *Orchestrator {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("file identity needs Linux")
	}
	return &Orchestrator{opts: Options{StateDir: t.TempDir()}, cleanup: cleanup.New()}
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func directoryEntries(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

// A file another tool put at the generated path after tracking was
// unlinked by cleanup and then reported cleanly absent, whether or not the
// creator had refused it. The creator now writes a staging file, and the
// finished file is published without replacing anything.
func TestLateForeignFileAtTheFinalPathIsNeverRemoved(t *testing.T) {
	for name, appearsDuring := range map[string]bool{
		"before the creator runs":         false,
		"while the creator runs (a race)": true,
	} {
		t.Run(name, func(t *testing.T) {
			orch := artifactOrch(t)
			dir := t.TempDir()
			final := filepath.Join(dir, "certistack-delta-vm9102-scsi0-1-0.qcow2")
			creatorRan := false
			if !appearsDuring {
				if err := os.WriteFile(final, []byte("foreign sentinel"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			err := orch.createTracked(9102, final, func(staging string) error {
				creatorRan = true
				if appearsDuring {
					if err := os.WriteFile(final, []byte("foreign sentinel"), 0o644); err != nil {
						t.Fatal(err)
					}
				}
				return os.WriteFile(staging, []byte("the run's overlay"), 0o600)
			})
			if err == nil || !strings.Contains(err.Error(), final) {
				t.Fatalf("createTracked = %v, want an error naming %s", err, final)
			}
			if appearsDuring && !strings.Contains(err.Error(), "is not the file this run created") {
				t.Fatalf("createTracked = %v, want it to say the file is not the run's", err)
			}
			if !appearsDuring && creatorRan {
				t.Fatal("the creator ran although a file was already at the path")
			}

			if failures := orch.cleanup.Unwind(); len(failures) != 0 {
				t.Fatalf("cleanup failures = %v", failures)
			}
			if got := mustRead(t, final); got != "foreign sentinel" {
				t.Fatalf("the foreign file now holds %q", got)
			}
			if names := directoryEntries(t, dir); len(names) != 1 {
				t.Fatalf("the directory holds %v, want the foreign file alone: the run's staging copy is gone", names)
			}
			// The path is not this run's: not journaled, not verified as removed.
			if len(orch.record.DeltaFiles) != 0 || len(orch.record.DeltaIdentities) != 0 {
				t.Fatalf("journal = %+v, want no delta file: the foreign file is not tracked", orch.record)
			}
			allRemoved, removed, errs := orch.verifyTrackedOverlaysRemoved()
			if !allRemoved || len(removed) != 0 || len(errs) != 0 {
				t.Fatalf("verification = %v %v %v; the foreign file must not be reported as this run's removed overlay", allRemoved, removed, errs)
			}
		})
	}
}

// A creator that fails or is interrupted leaves a partial staging file, which
// is the run's own and is removed; nothing appears at the final path.
func TestFailedCreatorLeavesNothingAtTheFinalPathAndItsPartialFileIsRemoved(t *testing.T) {
	orch := artifactOrch(t)
	dir := t.TempDir()
	final := filepath.Join(dir, "certistack-delta-vm9102-scsi0-1-0.qcow2")
	var staging string
	err := orch.createTracked(9102, final, func(path string) error {
		staging = path
		if err := os.WriteFile(path, []byte("partial firmware secrets"), 0o600); err != nil {
			t.Fatal(err)
		}
		return errors.New("qemu-img was killed")
	})
	if err == nil || !strings.Contains(err.Error(), "qemu-img was killed") {
		t.Fatalf("createTracked = %v", err)
	}
	if !strings.HasPrefix(filepath.Base(staging), "certistack-delta-vm9102-") || !strings.Contains(filepath.Base(staging), ".part-") {
		t.Fatalf("staging name %q: want the overlay prefix and an unguessable token", filepath.Base(staging))
	}
	// Journaled before the creator ran, so a killed worker's partial file is found.
	if len(orch.record.DeltaFiles) != 1 || orch.record.DeltaFiles[0] != staging {
		t.Fatalf("journal = %v, want the staging path", orch.record.DeltaFiles)
	}
	if _, err := os.Lstat(final); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("something is at the final path: %v", err)
	}
	if failures := orch.cleanup.Unwind(); len(failures) != 0 {
		t.Fatalf("cleanup failures = %v", failures)
	}
	if names := directoryEntries(t, dir); len(names) != 0 {
		t.Fatalf("the directory holds %v after cleanup", names)
	}
}

// The control: a creator that succeeds leaves the file at the final path with
// its identity journaled, no staging file, and cleanup removes it.
func TestPublishedArtifactIsJournaledByIdentityAndRemoved(t *testing.T) {
	orch := artifactOrch(t)
	dir := t.TempDir()
	final := filepath.Join(dir, "certistack-delta-vm9102-scsi0-1-0.qcow2")
	if err := orch.createTracked(9102, final, func(staging string) error {
		return os.WriteFile(staging, []byte("overlay"), 0o600)
	}); err != nil {
		t.Fatal(err)
	}
	if mustRead(t, final) != "overlay" {
		t.Fatal("the published file has other content")
	}
	if names := directoryEntries(t, dir); len(names) != 1 {
		t.Fatalf("the directory holds %v, want the published file alone", names)
	}
	identity, ok := orch.record.DeltaIdentity(final)
	if !ok || len(orch.record.DeltaFiles) != 1 || orch.record.DeltaFiles[0] != final {
		t.Fatalf("journal = %+v, want the final path with an identity and no staging path", orch.record)
	}
	saved, err := journal.Load(filepath.Join(orch.opts.StateDir, "active.json"))
	if err != nil {
		t.Fatal(err)
	}
	if saved.DeltaIdentities[final] != identity {
		t.Fatalf("the journal on disk has %+v, want %+v", saved.DeltaIdentities, identity)
	}
	if failures := orch.cleanup.Unwind(); len(failures) != 0 {
		t.Fatalf("cleanup failures = %v", failures)
	}
	if _, err := os.Lstat(final); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the run's file survived cleanup: %v", err)
	}
	allRemoved, removed, errs := orch.verifyTrackedOverlaysRemoved()
	if !allRemoved || len(removed) != 1 || len(errs) != 0 {
		t.Fatalf("verification = %v %v %v", allRemoved, removed, errs)
	}
}

// A file that replaces the run's own after publication (another file,
// or a symlink) is left alone by cleanup, and the verification says so instead
// of reporting the path cleanly absent.
func TestFileThatReplacesTheRunsArtifactIsLeftAloneAndReported(t *testing.T) {
	for name, replace := range map[string]func(t *testing.T, path, other string){
		"another file": func(t *testing.T, path, _ string) {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("foreign replacement"), 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"a symlink": func(t *testing.T, path, other string) {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(other, []byte("foreign replacement"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(other, path); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			orch := artifactOrch(t)
			dir := t.TempDir()
			final := filepath.Join(dir, "certistack-delta-vm9102-scsi0-1-0.qcow2")
			other := filepath.Join(t.TempDir(), "elsewhere")
			if err := orch.createTracked(9102, final, func(staging string) error {
				return os.WriteFile(staging, []byte("overlay"), 0o600)
			}); err != nil {
				t.Fatal(err)
			}
			replace(t, final, other)

			failures := orch.cleanup.Unwind()
			if err := failedStep(failures, "remove delta overlay "+final); err == nil || !strings.Contains(err.Error(), "not the one this run created") {
				t.Fatalf("cleanup failures = %v, want the overlay removal to refuse a file that is not the run's", failures)
			}
			if got := mustRead(t, final); got != "foreign replacement" {
				t.Fatalf("the replacement holds %q", got)
			}
			allRemoved, removed, errs := orch.verifyTrackedOverlaysRemoved()
			if allRemoved || len(removed) != 0 || len(errs) != 1 || !strings.Contains(errs[0].Error(), "now holds a file this run did not create") {
				t.Fatalf("verification = %v %v %v, want the replacement reported", allRemoved, removed, errs)
			}
		})
	}
}

// Firmware restores go through the same path: a late sentinel at the volume
// path is neither overwritten nor removed, and the partial restore is removed.
func TestFirmwareRestoreNeverRemovesALateForeignFile(t *testing.T) {
	orch, vm, _ := firmwareFixture(t, nil)
	vm.FirmwareDisks = vm.FirmwareDisks[:1]
	var final string
	orch.restoreImageFn = func(_ context.Context, _, _, target string) error {
		final, _, _ = strings.Cut(target, ".part-")
		if err := os.WriteFile(final, []byte("foreign sentinel"), 0o644); err != nil {
			t.Fatal(err)
		}
		return os.WriteFile(target, []byte("restored firmware with secrets"), 0o644)
	}
	if _, _, err := orch.restoreFirmwareDisks(context.Background(), vm, 1, nil, nil); err == nil || !strings.Contains(err.Error(), "is not the file this run created") {
		t.Fatalf("restoreFirmwareDisks = %v, want the late file refused", err)
	}
	orch.cleanup.Unwind()
	if got := mustRead(t, final); got != "foreign sentinel" {
		t.Fatalf("the foreign file now holds %q", got)
	}
	if names := directoryEntries(t, filepath.Dir(final)); len(names) != 1 {
		t.Fatalf("the volume directory holds %v, want the foreign file alone (the restored secrets are removed)", names)
	}
}

// The sizes a verification is given, and the plan's estimate, prefer the
// image size the snapshot's manifest records over the configuration's size=.
func TestDiskSizeIsWhatTheManifestAndTheConfigurationSay(t *testing.T) {
	vm := config.VM{
		SourceDiskBytes:  map[string]int64{"scsi0": 33 << 20, "scsi1": 8 << 30},
		SourceImageBytes: map[string]int64{"scsi0": 36 << 20},
	}
	if got := diskSize(vm, "scsi0"); got != (pbs.DiskSize{Manifest: 36 << 20, Config: 33 << 20}) {
		t.Errorf("scsi0 = %+v, want both sizes", got)
	}
	if got := diskSize(vm, "scsi1"); got != (pbs.DiskSize{Config: 8 << 30}) {
		t.Errorf("scsi1 = %+v, want the configuration's alone (the manifest listed none)", got)
	}
	if n, ok := sourceDiskLength(vm, "scsi0"); !ok || n != 36<<20 {
		t.Errorf("plan length of scsi0 = %d, %v; want the image's 36 MiB", n, ok)
	}
	if n, ok := sourceDiskLength(vm, "scsi1"); !ok || n != 8<<30 {
		t.Errorf("plan length of scsi1 = %d, %v; want the configuration's 8 GiB", n, ok)
	}
	if _, ok := sourceDiskLength(vm, "scsi2"); ok {
		t.Error("a disk nothing is known of has a length")
	}
}
