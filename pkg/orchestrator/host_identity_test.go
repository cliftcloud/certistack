// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/cliftcloud/certistack/internal/journal"
	"github.com/cliftcloud/certistack/internal/sysutil"
	"github.com/cliftcloud/certistack/pkg/pbs"
	"github.com/cliftcloud/certistack/pkg/sdn/sdntest"
)

// The run journals the kernel's identity of the interface and the
// containment table it installed, and drops the record once their removal is
// confirmed, so a journal kept for another resource's failure cannot later
// remove a replacement that reuses the interface and CIDR.
func TestProbeAddressIdentityIsJournaledAndDroppedOnceRemoved(t *testing.T) {
	fake := sdntest.New()
	orch := New(ephemeralPlan(), Options{ScratchDir: t.TempDir(), StateDir: t.TempDir()}, pbs.New(pbs.Config{}), fake.Serve(t))
	hosts := &fakeHostAddressManager{}
	orch.hostAddresses = hosts
	if err := orch.setupNetwork(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(orch.record.HostAddresses) != 1 || orch.record.HostAddresses[0].IfIndex != 7 || orch.record.HostAddresses[0].TableHandle != 11 {
		t.Fatalf("journaled host addresses = %+v, want the interface index 7 and table handle 11 the kernel answered", orch.record.HostAddresses)
	}
	if failures := orch.cleanup.Unwind(); len(failures) != 0 {
		t.Fatalf("cleanup failures = %v", failures)
	}
	if len(hosts.removed) != 1 || len(orch.record.HostAddresses) != 0 {
		t.Fatalf("removed %v, journal %+v; want the address removed and its record dropped", hosts.removed, orch.record.HostAddresses)
	}
}

// An address that is kept for a VM that may still run stays in the journal, and
// one whose identity cannot be read is journaled without it (removal by name).
func TestKeptProbeAddressStaysInTheJournalAndUnreadableIdentityIsAbsent(t *testing.T) {
	fake := sdntest.New()
	orch := New(ephemeralPlan(), Options{ScratchDir: t.TempDir(), StateDir: t.TempDir()}, pbs.New(pbs.Config{}), fake.Serve(t))
	hosts := &fakeHostAddressManager{identifyErr: errors.New("nft is not readable")}
	orch.hostAddresses = hosts
	if err := orch.setupNetwork(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(orch.record.HostAddresses) != 1 || orch.record.HostAddresses[0].IfIndex != 0 || orch.record.HostAddresses[0].TableHandle != 0 {
		t.Fatalf("journaled host addresses = %+v, want the record without identities", orch.record.HostAddresses)
	}
	orch.vmTeardown = map[int]error{9101: errVMTeardownNotRun}
	orch.cleanup.Push("destroy VM 9101", func() error {
		err := errors.New("PVE refused the destruction")
		orch.vmTeardown[9101] = err
		return err
	})
	orch.cleanup.Unwind()
	if len(orch.record.HostAddresses) != 1 || len(hosts.removed) != 0 {
		t.Fatalf("removed %v, journal %+v; want the kept address still recorded", hosts.removed, orch.record.HostAddresses)
	}
}

// The address was removed and its containment table was not: the journal says
// only the table is left. With the full address record kept, the retry
// (recovery) would run `ip address delete` for an address already gone, and
// delete an address of the same CIDR added on the same interface since.
func TestProbeAddressRemovedButItsTableLeftIsJournaledAsContainmentOnly(t *testing.T) {
	runsInBoot(t, testHostBoot, nil) // the record names the boot of its identities
	fake := sdntest.New()
	stateDir := t.TempDir()
	orch := New(ephemeralPlan(), Options{ScratchDir: t.TempDir(), StateDir: stateDir}, pbs.New(pbs.Config{}), fake.Serve(t))
	hosts := &fakeHostAddressManager{removeErr: fmt.Errorf("%w: address 10.100.0.1/24 is removed from interface csVn01, but its containment table is not: nft: permission denied", sysutil.ErrContainmentLeft)}
	orch.hostAddresses = hosts
	if err := orch.setupNetwork(context.Background()); err != nil {
		t.Fatal(err)
	}
	failures := orch.cleanup.Unwind()
	if failure := failedStep(failures, "remove host probe address"); failure == nil || !errors.Is(failure, sysutil.ErrContainmentLeft) {
		t.Fatalf("teardown failures = %v, want the table that was left", failures)
	}
	want := journal.TrackedHostAddress{Interface: "csVn01", CIDR: "10.100.0.1/24", ContainmentOnly: true, IfIndex: 7, TableHandle: 11, BootID: testHostBoot}
	if len(orch.record.HostAddresses) != 1 || orch.record.HostAddresses[0] != want {
		t.Fatalf("journal in memory = %+v, want %+v", orch.record.HostAddresses, want)
	}
	onDisk, err := journal.Load(filepath.Join(stateDir, "active.json"))
	if err != nil || len(onDisk.HostAddresses) != 1 || onDisk.HostAddresses[0] != want {
		t.Fatalf("journal on disk = %+v, %v; want %+v: recovery reads this one", onDisk.HostAddresses, err, want)
	}

	// An address that may still be assigned is not converted.
	orch = New(ephemeralPlan(), Options{ScratchDir: t.TempDir(), StateDir: t.TempDir()}, pbs.New(pbs.Config{}), fake.Serve(t))
	orch.hostAddresses = &fakeHostAddressManager{removeErr: fmt.Errorf("%w: it is still assigned", sysutil.ErrAddressLeft)}
	if err := orch.setupNetwork(context.Background()); err != nil {
		t.Fatal(err)
	}
	orch.cleanup.Unwind()
	if len(orch.record.HostAddresses) != 1 || orch.record.HostAddresses[0].ContainmentOnly {
		t.Fatalf("journal = %+v, want the full address record kept: the address may still be there", orch.record.HostAddresses)
	}
}
