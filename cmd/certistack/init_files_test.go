// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/initplan"
)

// Init publishes the plan so that an existing name is never replaced: a file
// another process creates between the check that the output does not exist and
// the publication survives, without --force.
func TestPlanFileIsNotPublishedOverALateCreator(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "plan.yaml")
	planPublishHook = func(target string) {
		if err := os.WriteFile(target, []byte("created by someone else\n"), 0o600); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { planPublishHook = nil })
	err := writePlanFile(path, []byte("the plan\n"), false)
	if err == nil || !strings.Contains(err.Error(), "appeared while the plan was being written") || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("a late creator's file was not refused: %v", err)
	}
	if data, _ := os.ReadFile(path); string(data) != "created by someone else\n" {
		t.Fatalf("the late creator's file was replaced: %q", data)
	}
	if leftovers, _ := filepath.Glob(filepath.Join(dir, ".plan.yaml.*")); len(leftovers) != 0 {
		t.Errorf("the staged plan was left behind: %v", leftovers)
	}
	// With --force the same sequence replaces it, as asked.
	if err := writePlanFile(path, []byte("the plan\n"), true); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(path); string(data) != "the plan\n" {
		t.Fatalf("--force did not replace: %q", data)
	}
	// Without a competitor the plan is published, readable, and complete.
	planPublishHook = nil
	fresh := filepath.Join(dir, "fresh.yaml")
	if err := writePlanFile(fresh, []byte("fresh plan\n"), false); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(fresh); err != nil || info.Mode().Perm() != 0o644 && filepath.Separator == '/' {
		t.Fatalf("published plan: %v, %v", info, err)
	}
	if data, _ := os.ReadFile(fresh); string(data) != "fresh plan\n" {
		t.Fatalf("plan = %q", data)
	}
	if leftovers, _ := filepath.Glob(filepath.Join(dir, ".fresh.yaml.*")); len(leftovers) != 0 {
		t.Errorf("temporary files left: %v", leftovers)
	}
}

// The check before writing treats an error other than "not there" as
// an error, and a dangling symbolic link as something that exists, which a
// rename would have replaced.
func TestPlanOutputCheckIsStrict(t *testing.T) {
	dir := t.TempDir()
	dangling := filepath.Join(dir, "dangling.yaml")
	if err := os.Symlink(filepath.Join(dir, "nowhere"), dangling); err != nil {
		t.Skipf("no symbolic links here: %v", err)
	}
	if err := checkPlanOutput(dangling, false); err == nil || !strings.Contains(err.Error(), "exists") {
		t.Fatalf("a dangling link counted as absent: %v", err)
	}
	if err := writePlanFile(dangling, []byte("x\n"), false); err == nil {
		t.Fatal("a plan was written over a dangling link")
	}
	if _, err := os.Stat(filepath.Join(dir, "nowhere")); err == nil {
		t.Fatal("the plan was written through the link")
	}
	if err := checkPlanOutput(filepath.Join(dir, "absent.yaml"), false); err != nil {
		t.Fatalf("an absent output was refused: %v", err)
	}
	// A parent that is not a directory is an error, not an absence.
	file := filepath.Join(dir, "a-file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkPlanOutput(filepath.Join(file, "plan.yaml"), false); err == nil {
		t.Fatal("an output beneath a file was treated as absent")
	}
}

// The neighbors' plans are found without a glob built from the output's
// directory, so a directory whose own name holds a glob character (an
// unmatched "[" makes a pattern invalid) still reserves its neighbors' IDs,
// and init does not hand out an ID a neighbor already uses.
func TestSiblingReservationsSurviveGlobCharactersInTheDirectory(t *testing.T) {
	const sibling = "network:\n  zone_id: csZone1\n  vnet_id: csVnet1\ntiers:\n  - vms:\n      - vmid: 9100\n"
	for _, name := range []string{"plans", "plans[", "plans]", "pl*ans", "pl?ans", "[plans]", `pl\ans`} {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), name)
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Skipf("this file system cannot name a directory %q: %v", name, err)
			}
			if err := os.WriteFile(filepath.Join(dir, "nightly.yaml"), []byte(sibling), 0o644); err != nil {
				t.Fatal(err)
			}
			avoid, sdnIDs, _, err := siblingPlanIDs(context.Background(), filepath.Join(dir, "new.yaml"))
			if err != nil || fmt.Sprint(avoid) != "[9100]" {
				t.Fatalf("reserved %v (%v), want [9100]", avoid, err)
			}
			d, err := initplan.Discover(context.Background(), siblingInventory{}, siblingInventory{}, initplan.Request{Node: "pve1", VMIDs: []int{100}, AvoidVMIDs: avoid, AvoidSDNIDs: sdnIDs}, t.TempDir())
			if err != nil || len(d.SandboxVMIDs) != 1 || d.SandboxVMIDs[0] != 9101 {
				t.Fatalf("init chose %v (%v), want 9101, past the neighbor's 9100", d.SandboxVMIDs, err)
			}
		})
	}
	// A glob character in the directory's name does not reach into other
	// directories that the pattern would have matched.
	root := t.TempDir()
	for name, id := range map[string]int{"pl*": 9100, "plX": 9200} {
		dir := filepath.Join(root, name)
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Skipf("cannot name a directory %q: %v", name, err)
		}
		content := fmt.Sprintf("tiers:\n  - vms:\n      - vmid: %d\n", id)
		if err := os.WriteFile(filepath.Join(dir, "nightly.yaml"), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	avoid, _, _, err := siblingPlanIDs(context.Background(), filepath.Join(root, "pl*", "new.yaml"))
	if err != nil || fmt.Sprint(avoid) != "[9100]" {
		t.Fatalf("reserved %v (%v), want only the plan beside the output", avoid, err)
	}
}

// The scan honors cancellation and reports what it cannot list.
func TestSiblingScanStopsWithItsContext(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.yaml"), []byte("tiers: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, _, err := siblingPlanIDs(ctx, filepath.Join(dir, "new.yaml")); err == nil || !strings.Contains(err.Error(), "canceled") {
		t.Fatalf("a canceled scan: %v", err)
	}
	// A directory that is not there is for the write to report.
	if avoid, sdn, _, err := siblingPlanIDs(context.Background(), filepath.Join(dir, "missing", "new.yaml")); err != nil || len(avoid)+len(sdn) != 0 {
		t.Fatalf("a missing directory: %v %v %v", avoid, sdn, err)
	}
	// One that cannot be listed is an error, not an empty answer.
	file := filepath.Join(dir, "a-file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := siblingPlanIDs(context.Background(), filepath.Join(file, "new.yaml")); err == nil {
		t.Fatal("an unlistable directory was treated as having no neighbors")
	}
}
