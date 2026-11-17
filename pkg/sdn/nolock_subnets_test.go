// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package sdn

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/sdn/sdntest"
)

// On a PVE without an SDN lock, reading only the pending zones, VNets and
// controllers would let an administrator's unapplied change to a subnet be
// applied with the run's. There is no lock there to refuse it, so the guard
// reads the pending subnets of every VNet the cluster lists. These tests use an
// administrator's applied zone, VNet and subnet and change the subnet only: the
// VNet itself stays unchanged.

const (
	adminSubnet = "adminZ-10.9.0.0-24"
	adminExtra  = "adminZ-10.8.0.0-24"
)

// adminSubnetChange makes the change to the administrator's subnet that the
// state names, leaving the zone and the VNet unchanged.
func adminSubnetChange(state string) func(p *sdntest.PVE) {
	return func(p *sdntest.PVE) {
		switch state {
		case "new":
			p.Subnets["adminNet"] = append(p.Subnets["adminNet"], adminExtra)
		case "changed":
			p.ChangedSubnets["adminNet/"+adminSubnet] = true
		case "deleted":
			delete(p.Subnets, "adminNet")
		}
	}
}

func adminCluster(fake *sdntest.PVE) {
	fake.Do(func(p *sdntest.PVE) { p.Applied("adminZ", "adminNet", adminSubnet) })
}

func TestNoLockAPIRefusesAnAdministratorsPendingSubnet(t *testing.T) {
	for _, state := range []string{"new", "changed", "deleted"} {
		want := "subnet adminNet/" + adminSubnet + " (" + state + ")"
		if state == "new" {
			want = "subnet adminNet/" + adminExtra + " (new)"
		}
		t.Run(state+" before the run", func(t *testing.T) {
			m, fake, _ := pve8(t, 0)
			adminCluster(fake)
			fake.Do(adminSubnetChange(state))
			err := m.Lock(context.Background())
			if !errors.Is(err, ErrPendingSDNChanges) || !strings.Contains(err.Error(), want) {
				t.Fatalf("Lock = %v; want the refusal over %q", err, want)
			}
			if got := strings.Join(fake.Writes(), "\n"); got != "POST cluster/sdn/lock" {
				t.Fatalf("writes:\n%s", got)
			}
			// The VNet itself was not pending: only the subnet read shows it.
			if strings.Contains(err.Error(), "VNet adminNet") {
				t.Fatalf("the VNet was reported pending: %v", err)
			}
		})
		t.Run(state+" before an apply", func(t *testing.T) {
			m, fake, _ := pve8(t, 0)
			adminCluster(fake)
			ctx := context.Background()
			if err := m.Lock(ctx); err != nil {
				t.Fatal(err)
			}
			sandboxCreated(t, m)
			fake.Do(adminSubnetChange(state)) // the administrator edits meanwhile
			err := m.Reload(ctx)
			if !errors.Is(err, ErrPendingSDNChanges) || !strings.Contains(err.Error(), want) {
				t.Fatalf("Reload = %v; want the administrator's subnet refused", err)
			}
			if fake.Applies != 0 || strings.Contains(strings.Join(fake.Writes(), "\n"), "PUT") {
				t.Fatalf("applies %d, writes %v: the administrator's subnet was applied", fake.Applies, fake.Writes())
			}
		})
		t.Run(state+" before a deletion pass", func(t *testing.T) {
			m, fake, _ := pve8(t, 0)
			adminCluster(fake)
			ctx := context.Background()
			if err := m.Lock(ctx); err != nil {
				t.Fatal(err)
			}
			sandboxCreated(t, m)
			if err := m.Reload(ctx); err != nil {
				t.Fatal(err)
			}
			fake.Do(adminSubnetChange(state))
			if err := m.EnsureLock(ctx); !errors.Is(err, ErrPendingSDNChanges) || !strings.Contains(err.Error(), want) {
				t.Fatalf("EnsureLock = %v; want the teardown refused over %q", err, want)
			}
		})
	}
}

// The run's own subnet, under its own VNet, is the run's: it is read (the read
// is what sees subnets) and it is not foreign.
func TestNoLockAPIReadsTheRunsOwnSubnetAndTakesItForItsOwn(t *testing.T) {
	m, fake, _ := pve8(t, 0)
	adminCluster(fake)
	ctx := context.Background()
	if err := m.Lock(ctx); err != nil {
		t.Fatal(err)
	}
	sandboxCreated(t, m)
	if err := m.EnsureLock(ctx); err != nil {
		t.Fatalf("EnsureLock over the run's own subnet = %v", err)
	}
	foreign, err := m.ForeignPending(ctx)
	if err != nil || len(foreign) != 0 {
		t.Fatalf("foreign pending = %v, %v; the run's own zone, VNet and subnet are its own", foreign, err)
	}
	pending, err := m.PendingChanges(ctx)
	if err != nil || !strings.Contains(strings.Join(pending, "\n"), "subnet csVn01/csSb01-10.100.0.0-24 (new)") {
		t.Fatalf("pending = %v, %v; want the run's subnet listed", pending, err)
	}
	if reads := requestsWith(fake, "GET cluster/sdn/vnets/csVn01/subnets?pending=1"); len(reads) == 0 {
		t.Fatal("the run's own VNet's subnets were never read")
	}
	if reads := requestsWith(fake, "GET cluster/sdn/vnets/adminNet/subnets?pending=1"); len(reads) == 0 {
		t.Fatal("the administrator's VNet's subnets were never read")
	}
}

// A subnet under another VNet is not the run's, whatever its name looks like.
func TestNoLockAPIDoesNotTakeAnotherVNetsSubnetForItsOwn(t *testing.T) {
	m, fake, _ := pve8(t, 0)
	adminCluster(fake)
	fake.Do(func(p *sdntest.PVE) { p.Subnets["adminNet"] = append(p.Subnets["adminNet"], "csSb01-10.100.0.0-24") })
	err := m.Lock(context.Background())
	if !errors.Is(err, ErrPendingSDNChanges) || !strings.Contains(err.Error(), "subnet adminNet/csSb01-10.100.0.0-24 (new)") {
		t.Fatalf("Lock = %v; want a subnet under the administrator's VNet read as foreign", err)
	}
}

// A subnet list nobody could read proves nothing: the guard refuses, with an
// error that is not "nothing pending", and applies nothing.
func TestNoLockAPIRefusesWhenASubnetListCannotBeRead(t *testing.T) {
	t.Run("before the run", func(t *testing.T) {
		m, fake, _ := pve8(t, 0)
		adminCluster(fake)
		fake.Fault("GET cluster/sdn/vnets/adminNet/subnets", sdntest.Fault{Refuse: "boom"})
		err := m.Lock(context.Background())
		if err == nil || errors.Is(err, ErrPendingSDNChanges) || !strings.Contains(err.Error(), "pending subnets of VNet adminNet") {
			t.Fatalf("Lock = %v; want the failed read named", err)
		}
	})
	t.Run("before an apply", func(t *testing.T) {
		m, fake, _ := pve8(t, 0)
		adminCluster(fake)
		ctx := context.Background()
		if err := m.Lock(ctx); err != nil {
			t.Fatal(err)
		}
		sandboxCreated(t, m)
		fake.Fault("GET cluster/sdn/vnets/csVn01/subnets", sdntest.Fault{Refuse: "boom"})
		if err := m.Reload(ctx); err == nil || fake.Applies != 0 {
			t.Fatalf("Reload = %v, applies %d; want nothing applied over a subnet list nobody could read", err, fake.Applies)
		}
	})
}

// A VNet that is pending deletion is gone from the configuration: its own entry
// is the change, and its subnets are not read (PVE has no configured VNet to
// list them of).
func TestNoLockAPIDoesNotReadTheSubnetsOfAVNetPendingDeletion(t *testing.T) {
	m, fake, _ := pve8(t, 0)
	adminCluster(fake)
	fake.Do(func(p *sdntest.PVE) {
		delete(p.Subnets, "adminNet")
		delete(p.VNets, "adminNet")
	})
	err := m.Lock(context.Background())
	if !errors.Is(err, ErrPendingSDNChanges) || !strings.Contains(err.Error(), "VNet adminNet (deleted)") {
		t.Fatalf("Lock = %v; want the deleted VNet named", err)
	}
	if reads := requestsWith(fake, "vnets/adminNet/subnets"); len(reads) != 0 {
		t.Fatalf("the subnets of a VNet pending deletion were read: %v", reads)
	}
}

// The subnet read is bounded: up to maxForeignVNetsRead other VNets, one request
// each; more than that cannot be shown to be free of an unapplied subnet change,
// so the guard refuses and applies nothing.
func TestNoLockAPIBoundsTheSubnetReadsAndRefusesBeyondTheBound(t *testing.T) {
	vnets := func(fake *sdntest.PVE, n int) {
		fake.Do(func(p *sdntest.PVE) {
			for i := 0; i < n; i++ {
				id := fmt.Sprintf("v%03d", i)
				p.Zones["adminZ"], p.RunningZones["adminZ"] = true, true
				p.VNets[id], p.RunningVNets[id] = "adminZ", "adminZ"
			}
		})
	}
	t.Run("at the bound", func(t *testing.T) {
		m, fake, _ := pve8(t, 0)
		vnets(fake, maxForeignVNetsRead)
		if err := m.Lock(context.Background()); err != nil {
			t.Fatalf("Lock with %d other VNets = %v", maxForeignVNetsRead, err)
		}
		if reads := requestsWith(fake, "/subnets?pending=1"); len(reads) != maxForeignVNetsRead {
			t.Fatalf("%d subnet reads for %d VNets", len(reads), maxForeignVNetsRead)
		}
	})
	t.Run("the run's own VNet does not count against it", func(t *testing.T) {
		m, fake, _ := pve8(t, 0)
		vnets(fake, maxForeignVNetsRead)
		ctx := context.Background()
		if err := m.Lock(ctx); err != nil {
			t.Fatal(err)
		}
		sandboxCreated(t, m)
		if err := m.Reload(ctx); err != nil {
			t.Fatalf("Reload with %d other VNets and the run's own = %v; the run's VNet must not push the guard over its bound", maxForeignVNetsRead, err)
		}
	})
	t.Run("beyond the bound", func(t *testing.T) {
		m, fake, _ := pve8(t, 0)
		vnets(fake, maxForeignVNetsRead+1)
		err := m.Lock(context.Background())
		if err == nil || errors.Is(err, ErrPendingSDNChanges) || !strings.Contains(err.Error(), fmt.Sprintf("more than the %d", maxForeignVNetsRead)) {
			t.Fatalf("Lock = %v; want the bound named", err)
		}
		if reads := requestsWith(fake, "/subnets?pending=1"); len(reads) != 0 {
			t.Fatalf("a refused read still sent %d requests", len(reads))
		}
		if got := strings.Join(fake.Writes(), "\n"); got != "POST cluster/sdn/lock" {
			t.Fatalf("writes:\n%s", got)
		}
	})
}

// With PVE's lock (PVE 9), the lock covers every SDN object and the pending
// model is unchanged: no subnet is read.
func TestSubnetsArePendingReadsOnlyWithoutAnSDNLock(t *testing.T) {
	fake := sdntest.New()
	adminCluster(fake)
	m := NewManager(fake.Serve(t))
	m.SetOwnObjects([]string{h1Net.ZoneID}, []string{h1Net.VNetID})
	ctx := context.Background()
	if err := m.Lock(ctx); err != nil {
		t.Fatal(err)
	}
	if m.NoLockAPI() {
		t.Fatal("a PVE with the lock was taken for one without")
	}
	if _, err := m.PendingChanges(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := m.ForeignPending(ctx); err != nil {
		t.Fatal(err)
	}
	if reads := requestsWith(fake, "subnets?pending=1"); len(reads) != 0 {
		t.Fatalf("a PVE with an SDN lock was asked for pending subnets: %v", reads)
	}
}
