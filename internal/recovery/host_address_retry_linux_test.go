//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package recovery

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/internal/journal"
)

// retryShims is hostShims with an `nft delete` that fails until the test lets it
// through: the first recovery removes the address and cannot remove its table.
// The interface keeps its index and the address stays in the shim's view, as on
// a pre-provisioned VNet that outlives the run, so a second `ip address delete`
// of the same CIDR would remove an address that is no longer the run's.
func retryShims(t *testing.T) (allowDelete func(), calls func() string) {
	t.Helper()
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write("ip", `#!/bin/sh
dir=$(dirname "$0")
echo "ip $*" >> "$dir/calls"
case "$*" in
"-o link show dev "*)
  echo "5: $5: <BROADCAST> mtu 1500"
  exit 0 ;;
esac
exit 0
`)
	write("nft", `#!/bin/sh
dir=$(dirname "$0")
echo "nft $*" >> "$dir/calls"
case "$*" in
"-a list table inet "*)
  echo "table inet $5 { # handle 41"
  echo "}"
  exit 0 ;;
"delete table inet handle "*)
  if [ ! -e "$dir/allow-delete" ]; then echo "Error: Operation not permitted" >&2; exit 1; fi
  exit 0 ;;
esac
exit 0
`)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return func() {
			if err := os.WriteFile(filepath.Join(dir, "allow-delete"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}, func() string {
			data, _ := os.ReadFile(filepath.Join(dir, "calls"))
			return string(data)
		}
}

// A recovery that removed the probe address and could not remove its
// containment table left the journal as it was found: the full address record.
// The next attempt then issued `ip address delete` again, and an address with
// the same CIDR put on the same interface since (the index is unchanged for a
// pre-provisioned VNet) was deleted. The record now says only the table is left.
func TestRecoveryRetryAfterTheTableFailedDoesNotDeleteTheAddressAgain(t *testing.T) {
	allowDelete, calls := retryShims(t)
	recorded := journal.TrackedHostAddress{Interface: "csVnReuse", CIDR: "10.100.77.1/24", IfIndex: 5, TableHandle: 41}
	stateDir := hostAddressJournal(t, recorded)

	err := RecoverLocked(stateDir)
	if err == nil || !strings.Contains(err.Error(), "containment table") {
		t.Fatalf("first recovery = %v, want the table that could not be removed", err)
	}
	first := calls()
	if strings.Count(first, "ip address delete") != 1 {
		t.Fatalf("first attempt calls:\n%s\nwant one address delete", first)
	}
	after := journalPhase(t, stateDir)
	if after.Phase != "cleanup_failed" || len(after.HostAddresses) != 1 || !after.HostAddresses[0].ContainmentOnly || after.HostAddresses[0].TableHandle != 41 {
		t.Fatalf("journal after the first attempt = %+v, want the table kept as a containment-only record with its handle", after)
	}

	allowDelete()
	if err := RecoverLocked(stateDir); err != nil {
		t.Fatalf("second recovery = %v", err)
	}
	second := strings.TrimPrefix(calls(), first)
	if strings.Contains(second, "ip address delete") {
		t.Fatalf("the retry deleted the address again:\n%s", second)
	}
	if !strings.Contains(second, "nft delete table inet handle 41") {
		t.Fatalf("the retry did not remove the table by its handle:\n%s", second)
	}
	if after := journalPhase(t, stateDir); after.Phase != "cleaned" || len(after.HostAddresses) != 0 {
		t.Fatalf("journal after the retry = %+v, want cleaned and no host address", after)
	}
}

// An address that recovery removed is dropped from a journal that stays for
// another resource, as a normal cleanup does: a later attempt must not
// remove a replacement that reuses the interface and CIDR.
func TestRecoveryDropsAnAddressItRemovedFromAJournalThatStays(t *testing.T) {
	allowDelete, calls := retryShims(t)
	allowDelete()
	stateDir := t.TempDir()
	record := journal.Record{RunID: "old-run", Phase: "running", AllocationPending: "VM 9123 creation",
		HostAddresses: []journal.TrackedHostAddress{{Interface: "csVnReuse", CIDR: "10.100.77.1/24", IfIndex: 5, TableHandle: 41}}}
	if err := journal.Write(filepath.Join(stateDir, "active.json"), record); err != nil {
		t.Fatal(err)
	}

	if err := RecoverLocked(stateDir); err == nil {
		t.Fatal("recovery cleaned a journal with an unconfirmed allocation")
	}
	if after := journalPhase(t, stateDir); after.Phase != "cleanup_failed" || len(after.HostAddresses) != 0 {
		t.Fatalf("journal = %+v, want cleanup_failed with the removed address dropped", after)
	}
	first := calls()
	_ = RecoverLocked(stateDir)
	if second := strings.TrimPrefix(calls(), first); strings.Contains(second, "delete") {
		t.Fatalf("a later attempt removed something again:\n%s", second)
	}
}
