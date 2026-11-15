//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package recovery

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/internal/journal"
	"github.com/cliftcloud/certistack/internal/sysutil"
)

// hostShims puts private `ip` and `nft` on PATH (the reporter's technique):
// they answer from files in their own directory, which the test sets, and log
// every call there. Nothing on the host's network is touched.
func hostShims(t *testing.T, ifindex int, handle uint64) (setState func(ifindex int, handle uint64), calls func() string) {
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
  i=$(cat "$dir/ifindex")
  if [ "$i" = 0 ]; then echo "Device \"$5\" does not exist." >&2; exit 1; fi
  echo "$i: $5: <BROADCAST> mtu 1500"
  exit 0 ;;
esac
exit 0
`)
	write("nft", `#!/bin/sh
dir=$(dirname "$0")
echo "nft $*" >> "$dir/calls"
case "$*" in
"-a list table inet "*)
  h=$(cat "$dir/handle")
  if [ "$h" = 0 ]; then echo "Error: No such file or directory" >&2; exit 1; fi
  echo "table inet $5 { # handle $h"
  echo "}"
  exit 0 ;;
esac
exit 0
`)
	setState = func(ifindex int, handle uint64) {
		if err := os.WriteFile(filepath.Join(dir, "ifindex"), []byte(strconv.Itoa(ifindex)), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "handle"), []byte(strconv.FormatUint(handle, 10)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	setState(ifindex, handle)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return setState, func() string {
		data, _ := os.ReadFile(filepath.Join(dir, "calls"))
		return string(data)
	}
}

func hostAddressJournal(t *testing.T, address journal.TrackedHostAddress) string {
	t.Helper()
	stateDir := t.TempDir()
	record := journal.Record{RunID: "old-run", Phase: "running", UpdatedAt: time.Now().UTC(), HostAddresses: []journal.TrackedHostAddress{address}}
	if err := journal.Write(filepath.Join(stateDir, "active.json"), record); err != nil {
		t.Fatal(err)
	}
	return stateDir
}

// A stale journal recorded csVnReuse and 10.100.77.1/24; the interface
// and the containment table there now are a replacement's. Recovery issued
// `nft delete table` and `ip address delete` for them and cleaned the journal.
// It now deletes only what carries the identities the run recorded.
func TestRecoveryLeavesAReplacementHostAddressAndTable(t *testing.T) {
	table := sysutil.IsolationTableName("csVnReuse", "10.100.77.1/24")
	recorded := journal.TrackedHostAddress{Interface: "csVnReuse", CIDR: "10.100.77.1/24", IfIndex: 5, TableHandle: 41}

	t.Run("a replacement interface and table", func(t *testing.T) {
		_, calls := hostShims(t, 9, 77) // another interface index, another table handle
		stateDir := hostAddressJournal(t, recorded)
		if err := RecoverLocked(stateDir); err != nil {
			t.Fatalf("recovery = %v: nothing of the run's is left, so nothing is a failure", err)
		}
		if strings.Contains(calls(), "delete") {
			t.Fatalf("recovery deleted something that is not the run's:\n%s", calls())
		}
		log, err := os.ReadFile(filepath.Join(stateDir, "logs", "old-run.log"))
		if err != nil || !strings.Contains(string(log), "left interface csVnReuse, and any address on it, alone") || !strings.Contains(string(log), "left table "+table+" alone") {
			t.Fatalf("recovery log = %q, %v; want both replacements reported", log, err)
		}
		if after := journalPhase(t, stateDir); after.Phase != "cleaned" {
			t.Fatalf("journal phase = %q, want cleaned", after.Phase)
		}
	})

	t.Run("the run's own interface and table", func(t *testing.T) {
		_, calls := hostShims(t, 5, 41)
		stateDir := hostAddressJournal(t, recorded)
		if err := RecoverLocked(stateDir); err != nil {
			t.Fatal(err)
		}
		got := calls()
		if !strings.Contains(got, "ip address delete 10.100.77.1/24 dev csVnReuse") || !strings.Contains(got, "nft delete table inet handle 41") || strings.Contains(got, "nft delete table inet "+table) {
			t.Fatalf("recovery calls:\n%s\nwant the address deleted and the table deleted by its handle", got)
		}
	})

	// A record without the identities cannot be told from an interface or table
	// someone else made under the same name: nothing is deleted, the journal stays
	// unresolved, and the error says what to check and remove.
	for name, address := range map[string]journal.TrackedHostAddress{
		"no identities":               {Interface: "csVnReuse", CIDR: "10.100.77.1/24"},
		"interface index only":        {Interface: "csVnReuse", CIDR: "10.100.77.1/24", IfIndex: 5},
		"table handle only":           {Interface: "csVnReuse", CIDR: "10.100.77.1/24", TableHandle: 41},
		"containment only, no handle": {Interface: "csVnReuse", CIDR: "10.100.77.1/24", ContainmentOnly: true},
	} {
		t.Run("a record without its identities leaves everything: "+name, func(t *testing.T) {
			_, calls := hostShims(t, 5, 41) // the host looks exactly like the run's own
			stateDir := hostAddressJournal(t, address)
			err := RecoverLocked(stateDir)
			if err == nil || !strings.Contains(err.Error(), "not removing") || !strings.Contains(err.Error(), "nft delete table inet "+table) {
				t.Fatalf("recovery = %v; want a refusal that names what to check and remove", err)
			}
			if strings.Contains(calls(), "delete") {
				t.Fatalf("recovery deleted something it could not show was the run's:\n%s", calls())
			}
			if after := journalPhase(t, stateDir); after.Phase == "cleaned" {
				t.Fatal("the journal was cleaned with the address or table still on the host")
			}
		})
	}

	t.Run("containment only, replaced", func(t *testing.T) {
		_, calls := hostShims(t, 9, 77)
		stateDir := hostAddressJournal(t, journal.TrackedHostAddress{Interface: "csVnReuse", CIDR: "10.100.77.1/24", ContainmentOnly: true, TableHandle: 41})
		if err := RecoverLocked(stateDir); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(calls(), "delete") {
			t.Fatalf("recovery deleted a replacement table:\n%s", calls())
		}
	})
}
