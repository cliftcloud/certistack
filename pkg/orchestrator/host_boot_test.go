// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/cliftcloud/certistack/internal/journal"
	"github.com/cliftcloud/certistack/pkg/pbs"
	"github.com/cliftcloud/certistack/pkg/sdn/sdntest"
)

// testHostBoot is the boot the tests that compare a whole journaled host
// address record run in (see runsInBoot).
const testHostBoot = "cccccccc-cccc-cccc-cccc-cccccccccccc"

// runsInBoot makes the boot the run records its host address identities in
// this one, or unreadable.
func runsInBoot(t *testing.T, boot string, err error) {
	t.Helper()
	previous := hostBootID
	hostBootID = func() (string, error) { return boot, err }
	t.Cleanup(func() { hostBootID = previous })
}

// An interface index and a table handle name the run's own interface and table
// only within the boot that issued them. The journal says which boot that was,
// beside the numbers, so a recovery after a reboot does not take a replacement
// that carries the same numbers for the run's own.
func TestProbeAddressIdentityIsJournaledWithTheBootItWasCapturedIn(t *testing.T) {
	runsInBoot(t, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", nil)
	fake := sdntest.New()
	stateDir := t.TempDir()
	orch := New(ephemeralPlan(), Options{ScratchDir: t.TempDir(), StateDir: stateDir}, pbs.New(pbs.Config{}), fake.Serve(t))
	orch.hostAddresses = &fakeHostAddressManager{}
	if err := orch.setupNetwork(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := journal.TrackedHostAddress{Interface: "csVn01", CIDR: "10.100.0.1/24", IfIndex: 7, TableHandle: 11, BootID: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"}
	if len(orch.record.HostAddresses) != 1 || orch.record.HostAddresses[0] != want {
		t.Fatalf("journaled host addresses = %+v, want %+v", orch.record.HostAddresses, want)
	}
	onDisk, err := journal.Load(filepath.Join(stateDir, "active.json"))
	if err != nil || len(onDisk.HostAddresses) != 1 || onDisk.HostAddresses[0] != want {
		t.Fatalf("journal on disk = %+v, %v; want %+v: recovery reads this one", onDisk.HostAddresses, err, want)
	}
}

// An identity that cannot be bound to its boot is not recorded: recovery then
// removes nothing of it by name and says what to check (the run's own teardown,
// which knows what it added, still removes it).
func TestProbeAddressIdentityIsNotJournaledWhenTheBootCannotBeRead(t *testing.T) {
	runsInBoot(t, "", errors.New("open /proc/sys/kernel/random/boot_id: permission denied"))
	fake := sdntest.New()
	orch := New(ephemeralPlan(), Options{ScratchDir: t.TempDir(), StateDir: t.TempDir()}, pbs.New(pbs.Config{}), fake.Serve(t))
	hosts := &fakeHostAddressManager{}
	orch.hostAddresses = hosts
	if err := orch.setupNetwork(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := journal.TrackedHostAddress{Interface: "csVn01", CIDR: "10.100.0.1/24"}
	if len(orch.record.HostAddresses) != 1 || orch.record.HostAddresses[0] != want {
		t.Fatalf("journaled host addresses = %+v, want %+v: numbers that no boot can be named for are not recorded", orch.record.HostAddresses, want)
	}
	if failures := orch.cleanup.Unwind(); len(failures) != 0 || len(hosts.removed) != 1 {
		t.Fatalf("cleanup failures %v, removed %v; the run's own teardown still removes the address", failures, hosts.removed)
	}
}

// The boot is recorded although the numbers could not be read: that the
// objects went with a reboot needs no number.
func TestProbeAddressBootIsJournaledWhenTheNumbersCannotBeRead(t *testing.T) {
	runsInBoot(t, "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", nil)
	fake := sdntest.New()
	orch := New(ephemeralPlan(), Options{ScratchDir: t.TempDir(), StateDir: t.TempDir()}, pbs.New(pbs.Config{}), fake.Serve(t))
	orch.hostAddresses = &fakeHostAddressManager{identifyErr: errors.New("nft is not readable")}
	if err := orch.setupNetwork(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := journal.TrackedHostAddress{Interface: "csVn01", CIDR: "10.100.0.1/24", BootID: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"}
	if len(orch.record.HostAddresses) != 1 || orch.record.HostAddresses[0] != want {
		t.Fatalf("journaled host addresses = %+v, want %+v", orch.record.HostAddresses, want)
	}
}
