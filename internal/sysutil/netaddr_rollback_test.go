// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package sysutil

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

// fakeNetCommands scripts the commands AddInterfaceAddress runs. The address
// is reported present by `ip -o address show` according to presentBefore
// until an `ip address add` runs, then according to presentAfter.
// inspectErr fails every such inspection, with inspectStderr as what ip says.
type fakeNetCommands struct {
	presentBefore, presentAfter bool
	inspectAfterErr             error
	inspectErr                  error
	inspectStderr               string
	addErr, nftDeleteErr        error
	addressDeleteErr            error
	addressDeleteStderr         string
	added                       bool
	calls                       []string
}

func (f *fakeNetCommands) install(t *testing.T) {
	t.Helper()
	oldRun, oldRunWithInput := runCommand, runCommandWithInput
	t.Cleanup(func() { runCommand, runCommandWithInput = oldRun, oldRunWithInput })
	runCommand = func(_ context.Context, _ time.Duration, binary string, args ...string) (*Result, error) {
		command := binary + " " + strings.Join(args, " ")
		f.calls = append(f.calls, command)
		switch {
		case binary == "sysctl":
			return &Result{Stdout: []byte("0\n")}, nil
		case strings.HasPrefix(command, "ip -o address show"):
			if f.inspectErr != nil {
				return &Result{Stderr: []byte(f.inspectStderr)}, f.inspectErr
			}
			present := f.presentBefore
			if f.added {
				if f.inspectAfterErr != nil {
					return &Result{}, f.inspectAfterErr
				}
				present = f.presentAfter
			}
			if present {
				return &Result{Stdout: []byte("7: csVn70    inet 10.60.70.1/24 scope global csVn70\n")}, nil
			}
			return &Result{Stdout: []byte("7: csVn70    inet 10.60.70.9/24 scope global csVn70\n")}, nil
		case strings.HasPrefix(command, "ip address add"):
			f.added = true
			return &Result{}, f.addErr
		case strings.HasPrefix(command, "ip address delete"):
			return &Result{Stderr: []byte(f.addressDeleteStderr)}, f.addressDeleteErr
		case strings.HasPrefix(command, "nft delete table"):
			return &Result{Stderr: []byte("permission denied")}, f.nftDeleteErr
		}
		return &Result{}, nil
	}
	runCommandWithInput = func(_ context.Context, _ time.Duration, _ io.Reader, binary string, args ...string) (*Result, error) {
		f.calls = append(f.calls, binary+" "+strings.Join(args, " "))
		return &Result{}, nil
	}
}

func (f *fakeNetCommands) ran(prefix string) bool {
	for _, call := range f.calls {
		if strings.HasPrefix(call, prefix) {
			return true
		}
	}
	return false
}

func TestAddInterfaceAddressRefusesAddressAlreadyOnInterface(t *testing.T) {
	fake := &fakeNetCommands{presentBefore: true}
	fake.install(t)
	err := AddInterfaceAddress(context.Background(), "csVn70", "10.60.70.1/24")
	if err == nil || !strings.Contains(err.Error(), "not owned by this run") {
		t.Fatalf("error = %v, want a refusal of the existing address", err)
	}
	if fake.ran("nft") || fake.ran("ip address") {
		t.Fatalf("created or removed something for an address it does not own: %v", fake.calls)
	}
}

// A failed rollback used to be discarded: the containment table stayed
// installed while the caller was told nothing of this run was left, and the
// teardown evidence came out clean.
func TestAddInterfaceAddressReportsWhatAFailedRollbackLeft(t *testing.T) {
	addFailed := errors.New("exit status 2")
	for name, tc := range map[string]struct {
		fake              fakeNetCommands
		wantContainment   bool
		wantAddress       bool
		wantAddressDelete bool
	}{
		"clean rollback":              {fake: fakeNetCommands{addErr: addFailed}},
		"table removal failed":        {fake: fakeNetCommands{addErr: addFailed, nftDeleteErr: errors.New("exit status 1")}, wantContainment: true},
		"add took effect, removed":    {fake: fakeNetCommands{addErr: addFailed, presentAfter: true}, wantAddressDelete: true},
		"add took effect, stuck":      {fake: fakeNetCommands{addErr: addFailed, presentAfter: true, addressDeleteErr: errors.New("exit status 2")}, wantAddress: true, wantAddressDelete: true},
		"add took effect, table left": {fake: fakeNetCommands{addErr: addFailed, presentAfter: true, nftDeleteErr: errors.New("exit status 1")}, wantContainment: true, wantAddressDelete: true},
		"state unknown after the add": {fake: fakeNetCommands{addErr: addFailed, inspectAfterErr: errors.New("timeout")}, wantAddress: true},
	} {
		fake := tc.fake
		fake.install(t)
		err := AddInterfaceAddress(context.Background(), "csVn70", "10.60.70.1/24")
		if err == nil {
			t.Fatalf("%s: failed add returned nil", name)
		}
		if got := errors.Is(err, ErrContainmentLeft); got != tc.wantContainment {
			t.Errorf("%s: ErrContainmentLeft = %v, want %v (err %v)", name, got, tc.wantContainment, err)
		}
		if got := errors.Is(err, ErrAddressLeft); got != tc.wantAddress {
			t.Errorf("%s: ErrAddressLeft = %v, want %v (err %v)", name, got, tc.wantAddress, err)
		}
		if got := fake.ran("ip address delete"); got != tc.wantAddressDelete {
			t.Errorf("%s: address delete attempted = %v, want %v", name, got, tc.wantAddressDelete)
		}
	}
}

// Removal deleted the containment table before the address, and a
// failed address delete left the address on the VNet with nothing keeping a
// guest there off the host's services. The table now goes only once the
// address is confirmed gone, and the error says which of the two is left.
func TestRemoveInterfaceAddressKeepsContainmentUntilTheAddressIsGone(t *testing.T) {
	deleteFailed := errors.New("exit status 2")
	table := isolationTableName("csVn70", "10.60.70.1/24")
	for name, tc := range map[string]struct {
		fake fakeNetCommands
		// wantLeft is the sentinel the error wraps; nil wants success.
		wantLeft         error
		wantTableRemoval bool
	}{
		"removed":                         {fake: fakeNetCommands{presentBefore: true}, wantTableRemoval: true},
		"address already absent":          {fake: fakeNetCommands{addressDeleteErr: deleteFailed, addressDeleteStderr: "RTNETLINK answers: Cannot assign requested address"}, wantTableRemoval: true},
		"interface already gone":          {fake: fakeNetCommands{addressDeleteErr: deleteFailed, addressDeleteStderr: `Cannot find device "csVn70"`}, wantTableRemoval: true},
		"delete failed, address gone":     {fake: fakeNetCommands{addressDeleteErr: deleteFailed}, wantTableRemoval: true},
		"delete failed, still assigned":   {fake: fakeNetCommands{presentBefore: true, addressDeleteErr: deleteFailed, addressDeleteStderr: "RTNETLINK answers: Operation not permitted"}, wantLeft: ErrAddressLeft},
		"delete timed out, state unknown": {fake: fakeNetCommands{presentBefore: true, addressDeleteErr: context.DeadlineExceeded, inspectErr: errors.New("exit status 1")}, wantLeft: ErrAddressLeft},
		// The bridge went while the delete was in flight; a query of a
		// missing interface says so on stderr, which is absence, not failure.
		"delete timed out, interface gone":  {fake: fakeNetCommands{addressDeleteErr: context.DeadlineExceeded, inspectErr: errors.New("exit status 1"), inspectStderr: `Device "csVn70" does not exist.`}, wantTableRemoval: true},
		"delete timed out, query timed out": {fake: fakeNetCommands{addressDeleteErr: context.DeadlineExceeded, inspectErr: context.DeadlineExceeded, inspectStderr: `Device "csVn70" does not exist.`}, wantLeft: ErrAddressLeft},
		"address gone, table not":           {fake: fakeNetCommands{presentBefore: true, nftDeleteErr: errors.New("exit status 1")}, wantLeft: ErrContainmentLeft, wantTableRemoval: true},
	} {
		fake := tc.fake
		fake.install(t)
		err := RemoveInterfaceAddress(context.Background(), "csVn70", "10.60.70.1/24")
		if tc.wantLeft == nil && err != nil {
			t.Errorf("%s: %v", name, err)
		}
		if tc.wantLeft != nil && !errors.Is(err, tc.wantLeft) {
			t.Errorf("%s: error %v, want it to wrap %v", name, err, tc.wantLeft)
		}
		if errors.Is(err, ErrAddressLeft) && errors.Is(err, ErrContainmentLeft) {
			t.Errorf("%s: error %v claims both the address and only the table are left", name, err)
		}
		if tc.wantLeft != nil && !strings.Contains(err.Error(), table) {
			t.Errorf("%s: error %v does not name the containment table %s", name, err, table)
		}
		if got := fake.ran("nft delete table"); got != tc.wantTableRemoval {
			t.Errorf("%s: containment removal attempted = %v, want %v (calls %v)", name, got, tc.wantTableRemoval, fake.calls)
		}
		if tc.wantTableRemoval && !strings.HasPrefix(fake.calls[0], "ip address delete") {
			t.Errorf("%s: %q ran before the address delete (calls %v)", name, fake.calls[0], fake.calls)
		}
	}
}

func TestRemoveInterfaceContainmentLeavesAddressesAlone(t *testing.T) {
	fake := &fakeNetCommands{}
	fake.install(t)
	if err := RemoveInterfaceContainment(context.Background(), "csVn70", "10.60.70.1/24"); err != nil {
		t.Fatal(err)
	}
	if !fake.ran("nft delete table") || fake.ran("ip address") {
		t.Fatalf("containment removal ran %v", fake.calls)
	}
}
