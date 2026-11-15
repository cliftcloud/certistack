// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package sysutil

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// kernelState scripts what ip and nft answer: the index of the interface (0:
// none), whether the address is on it, and the handle of the containment table
// (0: none). Every command is kept.
type kernelState struct {
	ifindex     int
	hasAddress  bool
	tableHandle uint64
	handleErr   error // nft cannot list the table
	indexErr    error // ip cannot show the interface
	deleteErr   error // nft delete table fails
	calls       []string
}

func (k *kernelState) install(t *testing.T) {
	t.Helper()
	oldRun := runCommand
	t.Cleanup(func() { runCommand = oldRun })
	runCommand = func(_ context.Context, _ time.Duration, binary string, args ...string) (*Result, error) {
		command := binary + " " + strings.Join(args, " ")
		k.calls = append(k.calls, command)
		switch {
		case strings.HasPrefix(command, "ip -o link show dev"):
			if k.indexErr != nil {
				return &Result{}, k.indexErr
			}
			if k.ifindex == 0 {
				return &Result{Stderr: []byte(`Device "x" does not exist.`)}, errors.New("exit status 1")
			}
			return &Result{Stdout: []byte(fmt.Sprintf("%d: %s: <BROADCAST,MULTICAST,UP> mtu 1500\n", k.ifindex, args[len(args)-1]))}, nil
		case strings.HasPrefix(command, "ip -o address show"):
			if k.hasAddress {
				return &Result{Stdout: []byte("9: csVnReuse    inet 10.100.77.1/24 scope global csVnReuse\n")}, nil
			}
			return &Result{}, nil
		case strings.HasPrefix(command, "ip address delete"):
			k.hasAddress = false
			return &Result{}, nil
		case strings.HasPrefix(command, "nft -a list table"):
			if k.handleErr != nil {
				return &Result{Stderr: []byte("permission denied")}, k.handleErr
			}
			if k.tableHandle == 0 {
				return &Result{Stderr: []byte("Error: No such file or directory")}, errors.New("exit status 1")
			}
			return &Result{Stdout: []byte(fmt.Sprintf("table inet %s { # handle %d\n}\n", args[len(args)-1], k.tableHandle))}, nil
		case strings.HasPrefix(command, "nft delete table inet handle"):
			if k.deleteErr != nil {
				return &Result{Stderr: []byte("permission denied")}, k.deleteErr
			}
			if command == fmt.Sprintf("nft delete table inet handle %d", k.tableHandle) {
				k.tableHandle = 0
				return &Result{}, nil
			}
			return &Result{Stderr: []byte("Error: No such file or directory")}, errors.New("exit status 1")
		case strings.HasPrefix(command, "nft delete table inet csiso_"):
			k.tableHandle = 0
			return &Result{}, nil
		}
		return &Result{}, nil
	}
}

func (k *kernelState) ran(prefix string) bool {
	for _, call := range k.calls {
		if strings.HasPrefix(call, prefix) {
			return true
		}
	}
	return false
}

func TestHostAddressIdentityReadsTheKernelsIdentities(t *testing.T) {
	k := &kernelState{ifindex: 5, tableHandle: 41}
	k.install(t)
	ifindex, handle, err := HostAddressIdentity(context.Background(), "csVnReuse", "10.100.77.1/24")
	if err != nil || ifindex != 5 || handle != 41 {
		t.Fatalf("identity = %d, %d, %v; want 5, 41", ifindex, handle, err)
	}
	// What cannot be read is recorded as absent, with the error, and the other half is kept.
	k.handleErr = errors.New("exit status 1")
	ifindex, handle, err = HostAddressIdentity(context.Background(), "csVnReuse", "10.100.77.1/24")
	if err == nil || ifindex != 5 || handle != 0 {
		t.Fatalf("identity with an unreadable table = %d, %d, %v; want 5, 0 and the error", ifindex, handle, err)
	}
}

// Recovery deleted the table and the address a journal named, whatever
// now carried that interface, CIDR and table name. With the identities recorded
// at install, it removes only what still carries them.
func TestRemoveRecordedHostAddressTouchesOnlyWhatIsTheRuns(t *testing.T) {
	const iface, cidr = "csVnReuse", "10.100.77.1/24"
	for name, tc := range map[string]struct {
		state kernelState
		// the identities the journal recorded (0: not recorded)
		ifindex int
		handle  uint64
		// what the removal must do
		wantAddressDelete, wantTableDelete bool
		wantNotes                          int
		wantAddressLeft                    bool
	}{
		"the run's own interface and table": {
			state: kernelState{ifindex: 5, hasAddress: true, tableHandle: 41}, ifindex: 5, handle: 41,
			wantAddressDelete: true, wantTableDelete: true,
		},
		// The reported case: a replacement interface and table, same names.
		"a replacement interface and table": {
			state: kernelState{ifindex: 9, hasAddress: true, tableHandle: 77}, ifindex: 5, handle: 41,
			wantNotes: 2,
		},
		"a replacement interface, the run's own table": {
			state: kernelState{ifindex: 9, hasAddress: true, tableHandle: 41}, ifindex: 5, handle: 41,
			wantTableDelete: true, wantNotes: 1,
		},
		"the run's own interface, a replacement table": {
			state: kernelState{ifindex: 5, hasAddress: true, tableHandle: 77}, ifindex: 5, handle: 41,
			wantAddressDelete: true, wantNotes: 1,
		},
		"the interface is gone (it took the address), the table is the run's": {
			state: kernelState{ifindex: 0, tableHandle: 41}, ifindex: 5, handle: 41,
			wantTableDelete: true,
		},
		"everything is gone": {
			state: kernelState{}, ifindex: 5, handle: 41,
		},
		// A journal without identities removes by name, as before.
		"no identity recorded": {
			state:             kernelState{ifindex: 9, hasAddress: true, tableHandle: 77},
			wantAddressDelete: true, wantTableDelete: true,
		},
		"the interface cannot be read": {
			state: kernelState{indexErr: errors.New("exit status 1"), hasAddress: true, tableHandle: 41}, ifindex: 5, handle: 41,
			wantAddressLeft: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			k := tc.state
			k.install(t)
			notes, err := RemoveRecordedHostAddress(context.Background(), iface, cidr, tc.ifindex, tc.handle)
			if tc.wantAddressLeft {
				if !errors.Is(err, ErrAddressLeft) || k.ran("ip address delete") || k.ran("nft delete") {
					t.Fatalf("removal = %v, calls %v; want ErrAddressLeft and nothing deleted", err, k.calls)
				}
				return
			}
			if err != nil {
				t.Fatalf("removal: %v", err)
			}
			if got := k.ran("ip address delete"); got != tc.wantAddressDelete {
				t.Errorf("address deleted = %v, want %v (calls %v)", got, tc.wantAddressDelete, k.calls)
			}
			if got := k.ran("nft delete table"); got != tc.wantTableDelete {
				t.Errorf("table deleted = %v, want %v (calls %v)", got, tc.wantTableDelete, k.calls)
			}
			if len(notes) != tc.wantNotes {
				t.Errorf("notes = %v, want %d", notes, tc.wantNotes)
			}
			// A table with a recorded handle is deleted by that handle alone.
			if tc.handle != 0 && k.ran("nft delete table inet csiso_") {
				t.Errorf("the table was deleted by its name although its handle was recorded: %v", k.calls)
			}
		})
	}
}

func TestRemoveRecordedContainmentDeletesOnlyTheRecordedTable(t *testing.T) {
	const iface, cidr = "csVnReuse", "10.100.77.1/24"
	k := &kernelState{tableHandle: 77}
	k.install(t)
	notes, err := RemoveRecordedContainment(context.Background(), iface, cidr, 41)
	if err != nil || len(notes) != 1 || k.ran("nft delete") {
		t.Fatalf("removal of a replaced table = %v, %v, calls %v; want it left with a note", notes, err, k.calls)
	}
	k.tableHandle = 41
	if notes, err := RemoveRecordedContainment(context.Background(), iface, cidr, 41); err != nil || len(notes) != 0 || k.tableHandle != 0 {
		t.Fatalf("removal of the run's table = %v, %v, handle %d", notes, err, k.tableHandle)
	}
	// A failed deletion says the containment is left.
	k.tableHandle, k.deleteErr = 41, errors.New("exit status 1")
	if _, err := RemoveRecordedHostAddress(context.Background(), iface, cidr, 0, 41); !errors.Is(err, ErrContainmentLeft) {
		t.Fatalf("removal with the table deletion failing = %v, want ErrContainmentLeft", err)
	}
}
