//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package recovery

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/internal/journal"
	"github.com/cliftcloud/certistack/internal/sysutil"
)

const (
	allocIface = "csVn77"
	allocCIDR  = "10.89.0.1/24"
)

// allocationShims puts `ip` and `nft` on PATH over a host that has, or does not
// have, the probe address allocIface/allocCIDR and its containment table:
// `ip address show` and `nft list table` answer from the shim's files, and the
// two deletes remove them. failList makes `nft list table` fail as nft does for
// a permission error. Every call is logged.
func allocationShims(t *testing.T, address, table bool, failList bool) (calls func() string) {
	t.Helper()
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	touch := func(name string, on bool) {
		if on {
			if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	touch("address", address)
	touch("table", table)
	touch("faillist", failList)
	write("ip", `#!/bin/sh
dir=$(dirname "$0")
echo "ip $*" >> "$dir/calls"
case "$*" in
"-o link show dev "*)
  echo "9: $5: <BROADCAST> mtu 1500"
  exit 0 ;;
"-o address show dev "*)
  if [ -e "$dir/address" ]; then echo "9: $5    inet `+allocCIDR+` scope global $5"; fi
  exit 0 ;;
"address delete "*)
  rm -f "$dir/address"
  exit 0 ;;
esac
exit 0
`)
	write("nft", `#!/bin/sh
dir=$(dirname "$0")
echo "nft $*" >> "$dir/calls"
case "$*" in
"-a list table inet "*)
  if [ -e "$dir/faillist" ]; then echo "Error: Operation not permitted" >&2; exit 1; fi
  if [ ! -e "$dir/table" ]; then echo "Error: No such file or directory" >&2; exit 1; fi
  echo "table inet $5 { # handle 31"
  echo "}"
  exit 0 ;;
"delete table inet "*)
  rm -f "$dir/table"
  exit 0 ;;
esac
exit 0
`)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return func() string {
		data, _ := os.ReadFile(filepath.Join(dir, "calls"))
		return string(data)
	}
}

func pendingAddressJournal(t *testing.T, mutate func(*journal.Record)) string {
	t.Helper()
	stateDir := t.TempDir()
	record := journal.Record{RunID: "run-crashed-adding", Phase: "running", UpdatedAt: time.Now().UTC(), AllocationPending: journal.HostAddressPending(allocCIDR, allocIface)}
	if mutate != nil {
		mutate(&record)
	}
	if err := journal.Write(filepath.Join(stateDir, "active.json"), record); err != nil {
		t.Fatal(err)
	}
	return stateDir
}

// The run journals "host probe address <cidr> on <vnet>" before it adds the
// address, so a crash between that and the journal write that records the
// address leaves only the pending allocation. Recovery reads the host for what
// the run's addition could have made and settles the allocation, rather than
// refusing on every attempt until active.json is edited by hand.
func TestRecoverySettlesAHostAddressTheRunWasAddingWhenItStopped(t *testing.T) {
	table := sysutil.IsolationTableName(allocIface, allocCIDR)
	for _, tc := range []struct {
		name            string
		address, table  bool
		wantAddressGone string // in the calls, or "" for none
		wantTableGone   string
		wantNote        string
	}{
		{"the address and its table: both are the run's", true, true, "ip address delete " + allocCIDR + " dev " + allocIface, "nft delete table inet " + table, "removed address " + allocCIDR},
		{"only the table: the run stopped between the two", false, true, "", "nft delete table inet " + table, "removed containment table " + table},
		{"only the address: it was there before the run", true, false, "", "", "left address " + allocCIDR + " on interface " + allocIface + " alone"},
		{"nothing: the run stopped before it touched the host", false, false, "", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := allocationShims(t, tc.address, tc.table, false)
			stateDir := pendingAddressJournal(t, nil)
			if err := RecoverLocked(stateDir); err != nil {
				t.Fatalf("recovery = %v; want the allocation settled", err)
			}
			log := calls()
			for want, wanted := range map[string]bool{tc.wantAddressGone: tc.wantAddressGone != "", tc.wantTableGone: tc.wantTableGone != ""} {
				if wanted && !strings.Contains(log, want) {
					t.Errorf("calls:\n%s\nwant %q", log, want)
				}
			}
			if tc.wantAddressGone == "" && strings.Contains(log, "ip address delete") {
				t.Errorf("recovery deleted an address that is not the run's:\n%s", log)
			}
			if tc.wantTableGone == "" && strings.Contains(log, "delete table") {
				t.Errorf("recovery deleted a table that is not there:\n%s", log)
			}
			after := journalPhase(t, stateDir)
			if after.Phase != "cleaned" || after.AllocationPending != "" || len(after.CleanupErrors) != 0 {
				t.Fatalf("journal = %+v; want cleaned with the allocation settled", after)
			}
			if tc.wantNote != "" {
				data, err := os.ReadFile(filepath.Join(stateDir, "logs", "crashed-adding.log"))
				if err != nil || !strings.Contains(string(data), tc.wantNote) {
					t.Errorf("the recovery log %q (%v) lacks %q", data, err, tc.wantNote)
				}
			}
		})
	}
}

// A host that cannot be read does not settle anything: the allocation, and the
// journal, stay for the next attempt, and nothing is removed.
func TestRecoveryKeepsAHostAddressAllocationItCannotReadTheHostFor(t *testing.T) {
	calls := allocationShims(t, true, true, true)
	stateDir := pendingAddressJournal(t, nil)
	err := RecoverLocked(stateDir)
	if err == nil || !strings.Contains(err.Error(), "could not settle the host probe address "+allocCIDR+" on "+allocIface) {
		t.Fatalf("recovery = %v; want the unreadable host reported", err)
	}
	if strings.Contains(calls(), "delete") {
		t.Fatalf("recovery removed something it could not tell was the run's:\n%s", calls())
	}
	after := journalPhase(t, stateDir)
	if after.Phase != "cleanup_failed" || after.AllocationPending != journal.HostAddressPending(allocCIDR, allocIface) {
		t.Fatalf("journal = %+v; want it kept with the allocation", after)
	}
}

// While a VM may still run on the sandbox network nothing is removed or
// settled, as for a recorded address.
func TestRecoveryLeavesAHostAddressAllocationWhileAVMMayStillUseIt(t *testing.T) {
	vmRecoveryPVE(t, "status_unreadable")
	calls := allocationShims(t, true, true, false)
	stateDir := pendingAddressJournal(t, func(r *journal.Record) {
		r.VMs = []journal.TrackedVM{{VMID: 9101, Node: "node1"}}
	})
	err := RecoverLocked(stateDir)
	if err == nil || !strings.Contains(err.Error(), "cannot safely reconcile unconfirmed allocation") {
		t.Fatalf("recovery = %v; want the allocation kept", err)
	}
	if strings.Contains(calls(), "delete") {
		t.Fatalf("recovery touched the sandbox network while VM 9101 may run:\n%s", calls())
	}
	if after := journalPhase(t, stateDir); after.AllocationPending == "" || after.Phase == "cleaned" {
		t.Fatalf("journal = %+v", after)
	}
}

// An allocation that is not a host address, or whose text recovery cannot name
// precisely, is still left for an operator: it is not read into a host address.
func TestRecoveryStillRefusesAnAllocationItCannotName(t *testing.T) {
	for _, pending := range []string{
		"VM 9123 creation",
		"host probe address",
		"host probe address 10.89.0.1/24",
		"host probe address 10.89.0.1/24 on",
		"host probe address 10.89.0.1/24 at csVn77",
		"host probe address 10.89.0.1/24 on csVn77 and more",
		"host probe address  on csVn77",
	} {
		t.Run(pending, func(t *testing.T) {
			calls := allocationShims(t, true, true, false)
			stateDir := pendingAddressJournal(t, func(r *journal.Record) { r.AllocationPending = pending })
			if err := RecoverLocked(stateDir); err == nil || !strings.Contains(err.Error(), "cannot safely reconcile unconfirmed allocation") {
				t.Fatalf("recovery = %v; want the allocation kept for an operator", err)
			}
			if strings.Contains(calls(), "delete") {
				t.Fatalf("recovery removed something for an allocation it cannot name:\n%s", calls())
			}
		})
	}
	// A name that is not a probe address is refused by the settle itself.
	allocationShims(t, true, true, false)
	stateDir := pendingAddressJournal(t, func(r *journal.Record) { r.AllocationPending = "host probe address not-a-cidr on csVn77" })
	if err := RecoverLocked(stateDir); err == nil {
		t.Fatal("recovery settled an allocation whose address is not a CIDR")
	}
}

// A journal that records the address as well as the pending text (a crash
// after the record, before the pending text was cleared): the record's own
// removal, with its identities, is what removes the address, and the pending
// text is then cleared without a second removal by name.
func TestRecoverySettlesAHostAddressAllocationTheJournalAlsoRecords(t *testing.T) {
	calls := allocationShims(t, true, true, false)
	stateDir := pendingAddressJournal(t, func(r *journal.Record) {
		r.HostAddresses = []journal.TrackedHostAddress{{Interface: allocIface, CIDR: allocCIDR, IfIndex: 9, TableHandle: 31}}
	})
	if err := RecoverLocked(stateDir); err != nil {
		t.Fatalf("recovery = %v", err)
	}
	if got := strings.Count(calls(), "ip address delete"); got != 1 {
		t.Fatalf("the address was deleted %d times:\n%s", got, calls())
	}
	if after := journalPhase(t, stateDir); after.Phase != "cleaned" || after.AllocationPending != "" || len(after.HostAddresses) != 0 {
		t.Fatalf("journal = %+v", after)
	}
}

// The journal records the address with the identities of the interface and the
// table the run installed, and what is on the host now is a replacement (another
// interface index, another table handle). Step 3 leaves the replacement alone
// because it is not the run's. The allocation that is still pending for the same
// address must not make recovery remove the replacement by name: the record is
// the run's proof, and it was settled.
func TestRecoveryDoesNotSettleByNameWhatTheRecordedIdentitiesLeftAlone(t *testing.T) {
	calls := allocationShims(t, true, true, false) // the shim's interface has index 9 and its table handle 31
	stateDir := pendingAddressJournal(t, func(r *journal.Record) {
		r.HostAddresses = []journal.TrackedHostAddress{{Interface: allocIface, CIDR: allocCIDR, IfIndex: 5, TableHandle: 41}}
	})
	if err := RecoverLocked(stateDir); err != nil {
		t.Fatalf("recovery = %v", err)
	}
	if strings.Contains(calls(), "delete") {
		t.Fatalf("recovery deleted a replacement that is not the run's:\n%s", calls())
	}
	if after := journalPhase(t, stateDir); after.Phase != "cleaned" || after.AllocationPending != "" || len(after.HostAddresses) != 0 {
		t.Fatalf("journal = %+v", after)
	}
}
