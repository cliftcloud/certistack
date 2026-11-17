// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/initplan"
	"github.com/cliftcloud/certistack/pkg/pbs"
	"github.com/cliftcloud/certistack/pkg/pve"
)

// Plans next to the new one hold sandbox IDs PVE does not know between
// their runs; init avoids them. The file init replaces, and files that are
// not plans, are skipped.
func TestSiblingPlanIDs(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"nightly.yaml": "network:\n  zone_id: csZone1\n  vnet_id: csVnet1\ntiers:\n  - vms:\n      - vmid: 9100\n      - vmid: 9101\n",
		"weekly.yml":   "network:\n  zone_id: csLab70\ntiers:\n  - vms:\n      - vmid: 17214\n",
		"new.yaml":     "network:\n  zone_id: csSelf\ntiers:\n  - vms:\n      - vmid: 9999\n",
		"notes.yaml":   "- just\n- a list\n",
		"broken.yaml":  "tiers: [\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	vmids, sdnIDs, _, err := siblingPlanIDs(context.Background(), filepath.Join(dir, "new.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	got := fmt.Sprint(vmids, sdnIDs)
	for _, want := range []string{"9100", "9101", "17214", "csZone1", "csVnet1", "csLab70"} {
		if !strings.Contains(got, want) {
			t.Errorf("sibling IDs %s lack %s", got, want)
		}
	}
	if strings.Contains(got, "9999") || strings.Contains(got, "csSelf") {
		t.Errorf("the replaced plan's own IDs were avoided: %s", got)
	}
}

// A neighbouring plan that names its sandbox VM with the accepted
// alias target_vmid reserves that ID as vmid does, and init, through the
// real discovery and composer, does not hand it out again.
func TestSiblingPlanTargetVMIDAliasIsAvoided(t *testing.T) {
	for name, key := range map[string]string{"canonical vmid": "vmid", "alias target_vmid": "target_vmid"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			sibling := "network:\n  zone_id: csZone1\n  vnet_id: csVnet1\ntiers:\n  - vms:\n      - " + key + ": 9100\n        source_vmid: 100\n"
			if err := os.WriteFile(filepath.Join(dir, "nightly.yaml"), []byte(sibling), 0o644); err != nil {
				t.Fatal(err)
			}
			avoid, sdnIDs, _, err := siblingPlanIDs(context.Background(), filepath.Join(dir, "new.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			if fmt.Sprint(avoid) != "[9100]" {
				t.Fatalf("reserved sandbox IDs %v, want [9100]", avoid)
			}
			d, err := initplan.Discover(context.Background(), siblingInventory{}, siblingInventory{}, initplan.Request{Node: "pve1", VMIDs: []int{100}, AvoidVMIDs: avoid, AvoidSDNIDs: sdnIDs}, t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if len(d.SandboxVMIDs) != 1 || d.SandboxVMIDs[0] != 9101 {
				t.Fatalf("init chose sandbox IDs %v; want 9101, past the %s 9100 of the plan beside it", d.SandboxVMIDs, key)
			}
		})
	}
}

// siblingInventory is a node with one backed-up VM, 100, and no VMs or SDN
// in use. The VM can be probed (a Linux guest with a NIC), so the plan keeps
// it and discovery gives it a sandbox ID: a VM the plan leaves out is given
// none.
type siblingInventory struct{}

func (siblingInventory) ListVMBackups(context.Context) ([]pbs.VMBackups, error) {
	return []pbs.VMBackups{{VMID: 100, Latest: "vm/100/2026-09-27T03:00:00Z", Count: 1}}, nil
}
func (siblingInventory) LoadVMProfile(context.Context, string, string) (pbs.VMProfile, error) {
	return pbs.VMProfile{Name: "guest", OSType: "l26", BIOS: "seabios", MAC: "BC:24:11:00:00:01"}, nil
}
func (siblingInventory) UsedVMIDs(context.Context) (map[int]bool, error) { return map[int]bool{}, nil }
func (siblingInventory) UsedSDNIDs(context.Context) (map[string]bool, error) {
	return map[string]bool{}, nil
}
func (siblingInventory) ListNodeStorages(context.Context, string) ([]pve.NodeStorage, error) {
	return nil, nil
}

// A file too large to be a plan is not read whole to learn that, and is
// reported as one that cannot be a plan, not as a read that failed.
func TestSiblingPlanReadIsBounded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "huge.yaml")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(config.MaxPlanBytes + 1); err != nil {
		t.Fatal(err)
	}
	file.Close()
	if _, err := readSiblingPlan(path); !errors.Is(err, errNotAPlanFile) {
		t.Fatalf("an oversized neighbour: %v, want it refused as no plan", err)
	}
	if _, err := readSiblingPlan(t.TempDir()); !errors.Is(err, errNotAPlanFile) {
		t.Fatalf("a directory: %v, want it refused as no plan", err)
	}
	if _, err := readSiblingPlan(filepath.Join(t.TempDir(), "absent.yaml")); err == nil || errors.Is(err, errNotAPlanFile) {
		t.Fatalf("a file that is not there: %v, want a failed read", err)
	}
}

func TestWritePlanFileNeverOverwritesUnasked(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plan.yaml")
	if err := writePlanFile(path, []byte("one\n"), false); err != nil {
		t.Fatal(err)
	}
	if err := writePlanFile(path, []byte("two\n"), false); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("overwrite without --force: %v", err)
	}
	if err := writePlanFile(path, []byte("two\n"), true); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(path); string(data) != "two\n" {
		t.Fatalf("plan = %q", data)
	}
	if leftovers, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".plan.yaml.*")); len(leftovers) != 0 {
		t.Errorf("temporary files left: %v", leftovers)
	}
}

// The list says how big each VM's disks are, so that a newcomer can choose a
// small VM for a first run without looking it up in Proxmox.
func TestWriteBackupListShowsTheDiskSizes(t *testing.T) {
	var out bytes.Buffer
	when := time.Date(2026, 9, 27, 3, 0, 0, 0, time.UTC)
	writeBackupList(&out, &initplan.Discovery{Backups: []pbs.VMBackups{
		{VMID: 100, Comment: "web-01", Time: when, Count: 14, DiskBytes: 12 << 30},
		{VMID: 101, Comment: "db-01", Time: when, Count: 14, DiskBytes: 10<<30 + 512<<20},
		{VMID: 102, Comment: "tiny", Time: when, Count: 1, DiskBytes: 300 << 20},
		{VMID: 103, Comment: "no-sizes", Time: when, Count: 1},
		{VMID: 104, Comment: "odd", Time: when, Count: 1, DiskBytes: 1<<20 + 123},
	}})
	for _, want := range []string{"BACKUPS  DISKS", "12 GiB", "10.5 GiB", "300 MiB", "unknown", "1.0 MiB"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("listing lacks %q:\n%s", want, out.String())
		}
	}
	// A size just over 1 MiB rounds to the nearest tenth, not up to 2 MiB.
	if strings.Contains(out.String(), "2 MiB") {
		t.Errorf("a disk of 1 MiB and 123 bytes is listed as 2 MiB:\n%s", out.String())
	}
}

func TestWriteBackupList(t *testing.T) {
	var out bytes.Buffer
	writeBackupList(&out, &initplan.Discovery{Namespace: "prod", Backups: []pbs.VMBackups{
		{VMID: 100, Comment: "web-01", Time: time.Date(2026, 9, 27, 3, 0, 0, 0, time.UTC), Count: 14},
	}})
	for _, want := range []string{`namespace "prod"`, "100", "web-01", "2026-09-27 03:00 UTC", "14", "--vm <id>"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("listing lacks %q:\n%s", want, out.String())
		}
	}
	out.Reset()
	writeBackupList(&out, &initplan.Discovery{})
	if !strings.Contains(out.String(), "No VM has a complete backup in the root namespace of the PBS repository") {
		t.Errorf("empty listing: %s", out.String())
	}
}

// An empty list with no namespace set is the dead end of a newcomer whose
// backups are in a namespace: it must say that only the root namespace was read
// and how to read another one.
func TestWriteBackupListEmptyWithoutANamespaceHintsAtNamespaces(t *testing.T) {
	var out bytes.Buffer
	writeBackupList(&out, &initplan.Discovery{})
	want := "No VM has a complete backup in the root namespace of the PBS repository. If your backups are in a namespace, set PBS_NAMESPACE (or pass --namespace).\n"
	if out.String() != want {
		t.Errorf("empty listing, no namespace:\n got: %q\nwant: %q", out.String(), want)
	}
	if initCmd().Flags().Lookup("namespace") == nil {
		t.Error("the message names --namespace, which init does not have")
	}

	// With a namespace set, the wording is what it was: the namespace is named and
	// there is nothing to hint at.
	out.Reset()
	writeBackupList(&out, &initplan.Discovery{Namespace: "prod"})
	if want := "No VM has a complete backup in PBS namespace \"prod\".\n"; out.String() != want {
		t.Errorf("empty listing, namespace set:\n got: %q\nwant: %q", out.String(), want)
	}
}

// init is registered, and node-discover hidden like node-plan.
func TestInitCommandsAreRegistered(t *testing.T) {
	if cmd := initCmd(); cmd.Hidden || cmd.Flags().Lookup("vm") == nil || cmd.Flags().Lookup("all") == nil {
		t.Error("init is hidden or lacks --vm/--all")
	}
	if !nodeDiscoverCmd().Hidden {
		t.Error("node-discover is not hidden")
	}
}
