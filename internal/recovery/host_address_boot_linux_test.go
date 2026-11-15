//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package recovery

import (
	"errors"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/internal/journal"
	"github.com/cliftcloud/certistack/internal/sysutil"
)

const (
	earlierBoot = "11111111-1111-1111-1111-111111111111"
	thisBoot    = "22222222-2222-2222-2222-222222222222"
)

// thisBootIs makes the boot recovery compares a record with this one (the
// identity of the boot the test pretends to run in), or unreadable.
func thisBootIs(t *testing.T, boot string, err error) {
	t.Helper()
	previous := hostBootID
	hostBootID = func() (string, error) { return boot, err }
	t.Cleanup(func() { hostBootID = previous })
}

// An interface index and an nftables table handle are kernel-lifetime numbers:
// after a reboot a replacement interface or table of the same name can carry
// the very numbers the journal recorded, and was deleted as the run's own.
// A record of another boot is of objects that went with that boot.
func TestRecoveryDoesNotTakeAReplacementOfALaterBootForTheRecordedAddressAndTable(t *testing.T) {
	table := sysutil.IsolationTableName("csVnReuse", "10.100.77.1/24")
	recorded := func(boot string) journal.TrackedHostAddress {
		return journal.TrackedHostAddress{Interface: "csVnReuse", CIDR: "10.100.77.1/24", IfIndex: 5, TableHandle: 41, BootID: boot}
	}

	// The control: the identities were captured in this boot, the host shows
	// them, and they are the run's own.
	t.Run("recorded in this boot, removed", func(t *testing.T) {
		thisBootIs(t, thisBoot, nil)
		_, calls := hostShims(t, 5, 41)
		stateDir := hostAddressJournal(t, recorded(thisBoot))
		if err := RecoverLocked(stateDir); err != nil {
			t.Fatal(err)
		}
		got := calls()
		if !strings.Contains(got, "ip address delete 10.100.77.1/24 dev csVnReuse") || !strings.Contains(got, "nft delete table inet handle 41") {
			t.Fatalf("recovery calls:\n%s\nwant the address and the table of this boot removed", got)
		}
		if after := journalPhase(t, stateDir); after.Phase != "cleaned" || len(after.HostAddresses) != 0 {
			t.Fatalf("journal = %+v, want cleaned with no host address", after)
		}
	})

	// The host looks exactly like the run's own (same index, same handle): that
	// is the finding. The record is of an earlier boot, so none of it exists.
	t.Run("recorded in an earlier boot, nothing is touched and the record is settled", func(t *testing.T) {
		thisBootIs(t, thisBoot, nil)
		_, calls := hostShims(t, 5, 41)
		stateDir := hostAddressJournal(t, recorded(earlierBoot))
		if err := RecoverLocked(stateDir); err != nil {
			t.Fatalf("recovery = %v: the earlier boot's objects are gone, so nothing is left to fail", err)
		}
		if got := calls(); got != "" {
			t.Fatalf("recovery ran commands for a record of an earlier boot (the interface and table of that name now are not the run's):\n%s", got)
		}
		after := journalPhase(t, stateDir)
		if after.Phase != "cleaned" || len(after.HostAddresses) != 0 {
			t.Fatalf("journal = %+v, want the earlier boot's record settled and the journal cleaned", after)
		}
	})

	t.Run("a containment table recorded in an earlier boot", func(t *testing.T) {
		thisBootIs(t, thisBoot, nil)
		_, calls := hostShims(t, 5, 41)
		address := recorded(earlierBoot)
		address.ContainmentOnly, address.IfIndex = true, 0
		stateDir := hostAddressJournal(t, address)
		if err := RecoverLocked(stateDir); err != nil {
			t.Fatal(err)
		}
		if got := calls(); got != "" {
			t.Fatalf("recovery ran commands for a table of an earlier boot:\n%s", got)
		}
		if after := journalPhase(t, stateDir); after.Phase != "cleaned" || len(after.HostAddresses) != 0 {
			t.Fatalf("journal = %+v, want settled and cleaned", after)
		}
	})

	// The boot was recorded even though the interface or table could not be read:
	// that the objects went with the boot needs no identity.
	t.Run("an earlier boot's record without its numbers is settled too", func(t *testing.T) {
		thisBootIs(t, thisBoot, nil)
		_, calls := hostShims(t, 5, 41)
		stateDir := hostAddressJournal(t, journal.TrackedHostAddress{Interface: "csVnReuse", CIDR: "10.100.77.1/24", BootID: earlierBoot})
		if err := RecoverLocked(stateDir); err != nil {
			t.Fatal(err)
		}
		if got := calls(); got != "" {
			t.Fatalf("recovery ran commands:\n%s", got)
		}
		if after := journalPhase(t, stateDir); after.Phase != "cleaned" || len(after.HostAddresses) != 0 {
			t.Fatalf("journal = %+v, want settled and cleaned", after)
		}
	})

	// This boot's identity cannot be read: the record cannot be told to be of
	// this boot or of another, so nothing is removed and the journal stays.
	t.Run("this boot unreadable, nothing is removed and the record stays", func(t *testing.T) {
		thisBootIs(t, "", errors.New("open /proc/sys/kernel/random/boot_id: permission denied"))
		_, calls := hostShims(t, 5, 41)
		stateDir := hostAddressJournal(t, recorded(thisBoot))
		err := RecoverLocked(stateDir)
		if err == nil || !strings.Contains(err.Error(), "boot") || !strings.Contains(err.Error(), "nft delete table inet "+table) {
			t.Fatalf("recovery = %v; want an error that names the boot and what to check and remove", err)
		}
		if got := calls(); got != "" {
			t.Fatalf("recovery ran commands although it could not tell the boot:\n%s", got)
		}
		after := journalPhase(t, stateDir)
		if after.Phase == "cleaned" || len(after.HostAddresses) != 1 || after.HostAddresses[0].BootID != thisBoot {
			t.Fatalf("journal = %+v, want it unresolved with the record kept", after)
		}
	})

	// A journal written before the boot was recorded has none: it is reconciled
	// by the numbers alone, as it always was, and never needs the boot read.
	t.Run("a legacy record without a boot keeps today's behaviour", func(t *testing.T) {
		thisBootIs(t, "", errors.New("this boot must not be consulted"))
		_, calls := hostShims(t, 5, 41)
		stateDir := hostAddressJournal(t, recorded(""))
		if err := RecoverLocked(stateDir); err != nil {
			t.Fatal(err)
		}
		got := calls()
		if !strings.Contains(got, "ip address delete 10.100.77.1/24 dev csVnReuse") || !strings.Contains(got, "nft delete table inet handle 41") {
			t.Fatalf("recovery calls:\n%s\nwant the legacy record removed by its numbers", got)
		}
	})

	t.Run("a legacy record that a replacement carries other numbers is left, as before", func(t *testing.T) {
		thisBootIs(t, thisBoot, nil)
		_, calls := hostShims(t, 9, 77)
		stateDir := hostAddressJournal(t, recorded(""))
		if err := RecoverLocked(stateDir); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(calls(), "delete") {
			t.Fatalf("recovery deleted a replacement:\n%s", calls())
		}
	})

	// The same boot with another interface index is still a replacement.
	t.Run("recorded in this boot but the interface is another one", func(t *testing.T) {
		thisBootIs(t, thisBoot, nil)
		_, calls := hostShims(t, 9, 77)
		stateDir := hostAddressJournal(t, recorded(thisBoot))
		if err := RecoverLocked(stateDir); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(calls(), "delete") {
			t.Fatalf("recovery deleted a replacement of this boot:\n%s", calls())
		}
	})
}
