// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package sysutil

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	guardIface = "csVnet3"
	guardCIDR  = "192.0.2.1/24"
)

// reloadNode is a node whose network a reload can change: the sandbox bridge
// may be there or gone, carry the probe address or not, and have the
// containment table or not. ip and nft answer from that state; every command
// is kept.
type reloadNode struct {
	bridge, address, table bool
	tableHandle            uint64
	otherAddresses         string // `ip -4 -o address show` lines of other interfaces
	routes                 string
	calls                  []string
	nftScripts             []string
	addErr                 error
	nftListErr             error
	nftInstallErr          error
}

func newReloadNode(t *testing.T) *reloadNode {
	t.Helper()
	sys, _, procNet := fakeNodeRoots(t)
	node := &reloadNode{bridge: true, address: true, table: true, tableHandle: 7}
	node.writeBridge(t, sys)
	for _, family := range []string{"ipv4", "ipv6"} {
		writeSwitch(t, procNet, family, "0")
	}
	oldRun, oldRunWithInput := runCommand, runCommandWithInput
	t.Cleanup(func() { runCommand, runCommandWithInput = oldRun, oldRunWithInput })
	runCommand = node.run
	runCommandWithInput = func(_ context.Context, _ time.Duration, input io.Reader, binary string, args ...string) (*Result, error) {
		command := binary + " " + strings.Join(args, " ")
		node.calls = append(node.calls, command)
		script, _ := io.ReadAll(input)
		node.nftScripts = append(node.nftScripts, string(script))
		if node.nftInstallErr != nil {
			return &Result{Stderr: []byte("Error: could not process rule")}, node.nftInstallErr
		}
		node.table, node.tableHandle = true, node.tableHandle+1
		return &Result{}, nil
	}
	return node
}

func (n *reloadNode) writeBridge(t *testing.T, sys string) {
	t.Helper()
	dir := filepath.Join(sys, guardIface)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ifindex"), []byte("12\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeSwitch(t *testing.T, procNet, family, value string) {
	t.Helper()
	dir := filepath.Join(procNet, family, "conf", guardIface)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "forwarding"), []byte(value+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func (n *reloadNode) run(_ context.Context, _ time.Duration, binary string, args ...string) (*Result, error) {
	command := binary + " " + strings.Join(args, " ")
	n.calls = append(n.calls, command)
	switch {
	case strings.HasPrefix(command, "ip -o address show dev "):
		if !n.bridge {
			return &Result{Stderr: []byte(`Device "csVnet3" does not exist.`)}, errors.New("exit status 1")
		}
		if n.address {
			return &Result{Stdout: []byte("12: csVnet3    inet 192.0.2.1/24 scope global csVnet3\n")}, nil
		}
		return &Result{}, nil
	case command == "ip -4 -o address show":
		return &Result{Stdout: []byte(n.otherAddresses)}, nil
	case command == "ip -4 route show":
		return &Result{Stdout: []byte(n.routes)}, nil
	case strings.HasPrefix(command, "ip address add "):
		if !n.bridge {
			return &Result{Stderr: []byte(`Cannot find device "csVnet3"`)}, errors.New("exit status 1")
		}
		if n.addErr != nil {
			return &Result{Stderr: []byte("RTNETLINK answers: Operation not permitted")}, n.addErr
		}
		n.address = true
		return &Result{}, nil
	case strings.HasPrefix(command, "nft -a list table inet "):
		if n.nftListErr != nil {
			return &Result{Stderr: []byte("Operation not permitted")}, n.nftListErr
		}
		if !n.table {
			return &Result{Stderr: []byte("Error: No such file or directory")}, errors.New("exit status 1")
		}
		return &Result{Stdout: []byte(fmt.Sprintf("table inet %s { # handle %d\n\tchain input {\n\t}\n}\n", args[len(args)-1], n.tableHandle))}, nil
	}
	return &Result{}, nil
}

func (n *reloadNode) ran(prefix string) bool {
	for _, call := range n.calls {
		if strings.HasPrefix(call, prefix) {
			return true
		}
	}
	return false
}

// The state is read without changing anything: the address, the table and its
// handle, the interface's index and the two forwarding switches.
func TestInspectHostAddressReadsTheThreeFacts(t *testing.T) {
	node := newReloadNode(t)
	state, err := InspectHostAddress(context.Background(), guardIface, guardCIDR)
	if err != nil {
		t.Fatal(err)
	}
	if !state.BridgePresent || state.Ifindex != 12 || !state.AddressPresent || !state.TablePresent || state.TableHandle != 7 || len(state.ForwardingOn) != 0 {
		t.Fatalf("healthy state = %+v", state)
	}
	for _, call := range node.calls {
		if strings.HasPrefix(call, "ip address add") || strings.HasPrefix(call, "nft delete") || strings.Contains(call, "-f -") {
			t.Errorf("an inspection ran %q", call)
		}
	}

	// What `ifreload -a` does: the address goes, forwarding comes on.
	node.address = false
	_, _, procNet := nodeRoots()
	writeSwitch(t, procNet, "ipv4", "1")
	state, err = InspectHostAddress(context.Background(), guardIface, guardCIDR)
	if err != nil {
		t.Fatal(err)
	}
	if state.AddressPresent || !state.TablePresent || len(state.ForwardingOn) != 1 || state.ForwardingOn[0] != "IPv4" {
		t.Fatalf("state after a reload = %+v", state)
	}

	// IPv6 forwarding on as well, and the table gone.
	writeSwitch(t, procNet, "ipv6", "1")
	node.table = false
	state, err = InspectHostAddress(context.Background(), guardIface, guardCIDR)
	if err != nil {
		t.Fatal(err)
	}
	if state.TablePresent || strings.Join(state.ForwardingOn, ",") != "IPv4,IPv6" {
		t.Fatalf("state with the table gone = %+v", state)
	}

	// A node without IPv6 has only the IPv4 switch.
	if err := os.RemoveAll(filepath.Join(procNet, "ipv6")); err != nil {
		t.Fatal(err)
	}
	if state, err = InspectHostAddress(context.Background(), guardIface, guardCIDR); err != nil || strings.Join(state.ForwardingOn, ",") != "IPv4" {
		t.Fatalf("state without IPv6 = %+v, %v", state, err)
	}
}

// nodeRoots returns the fake node's directories set by fakeNodeRoots.
func nodeRoots() (sys, proc, procNet string) { return sysClassNet, procDir, procSysNet }

func TestInspectHostAddressSaysABridgeThatIsGone(t *testing.T) {
	node := newReloadNode(t)
	if err := os.RemoveAll(filepath.Join(sysClassNet, guardIface)); err != nil {
		t.Fatal(err)
	}
	state, err := InspectHostAddress(context.Background(), guardIface, guardCIDR)
	if err != nil {
		t.Fatalf("a missing bridge is a state, not an error: %v", err)
	}
	if state.BridgePresent || state.AddressPresent || state.TablePresent {
		t.Fatalf("state of a missing bridge = %+v", state)
	}
	if len(node.calls) != 0 {
		t.Errorf("a missing bridge was inspected further: %v", node.calls)
	}
}

func TestInspectHostAddressReportsWhatItCannotRead(t *testing.T) {
	node := newReloadNode(t)
	node.nftListErr = errors.New("exit status 1")
	if _, err := InspectHostAddress(context.Background(), guardIface, guardCIDR); err == nil || !strings.Contains(err.Error(), "list containment table") {
		t.Fatalf("an nft that cannot list the table was read as: %v", err)
	}
	node.nftListErr = nil
	if err := os.Remove(filepath.Join(procSysNet, "ipv4", "conf", guardIface, "forwarding")); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectHostAddress(context.Background(), guardIface, guardCIDR); err == nil || !strings.Contains(err.Error(), "IPv4 forwarding") {
		t.Fatalf("an unreadable forwarding switch was read as: %v", err)
	}
	for _, bad := range []string{"../eth0", "cs vnet", ""} {
		if _, err := InspectHostAddress(context.Background(), bad, guardCIDR); err == nil {
			t.Errorf("interface name %q was accepted", bad)
		}
	}
	if _, err := InspectHostAddress(context.Background(), guardIface, "not-a-cidr"); err == nil {
		t.Error("a bad CIDR was accepted")
	}
}

// A table that exists is present even when nft's listing names no handle.
func TestInspectHostAddressTableWithoutAHandle(t *testing.T) {
	newReloadNode(t)
	runCommand = func(_ context.Context, _ time.Duration, binary string, args ...string) (*Result, error) {
		command := binary + " " + strings.Join(args, " ")
		if strings.HasPrefix(command, "nft ") {
			return &Result{Stdout: []byte("table inet csiso_x {\n}\n")}, nil
		}
		return &Result{Stdout: []byte("12: csVnet3    inet 192.0.2.1/24 scope global csVnet3\n")}, nil
	}
	state, err := InspectHostAddress(context.Background(), guardIface, guardCIDR)
	if err != nil || !state.TablePresent || state.TableHandle != 0 {
		t.Fatalf("state = %+v, %v", state, err)
	}
}

// The repair adds the address and nothing else: no containment table, no
// forwarding change.
func TestRestoreInterfaceAddressAddsOnlyTheAddress(t *testing.T) {
	node := newReloadNode(t)
	node.address = false
	if err := RestoreInterfaceAddress(context.Background(), guardIface, guardCIDR); err != nil {
		t.Fatal(err)
	}
	if !node.address || !node.ran("ip address add 192.0.2.1/24 dev csVnet3") {
		t.Fatalf("the address was not added: %v", node.calls)
	}
	if len(node.nftScripts) != 0 || node.ran("nft") || node.ran("sysctl") {
		t.Errorf("restoring the address touched nft or sysctl: %v", node.calls)
	}

	// Already back: nothing is added a second time.
	node.calls = nil
	if err := RestoreInterfaceAddress(context.Background(), guardIface, guardCIDR); err != nil {
		t.Fatal(err)
	}
	if node.ran("ip address add") {
		t.Errorf("an address that is there was added again: %v", node.calls)
	}
}

// The node may have gained a use of the network since the run added the
// address: it is not added then.
func TestRestoreInterfaceAddressRefusesANetworkTheNodeUsesNow(t *testing.T) {
	node := newReloadNode(t)
	node.address = false
	node.otherAddresses = "2: eth0    inet 192.0.2.77/24 brd 192.0.2.255 scope global eth0\n"
	err := RestoreInterfaceAddress(context.Background(), guardIface, guardCIDR)
	if err == nil || !strings.Contains(err.Error(), "the node itself uses") {
		t.Fatalf("err = %v", err)
	}
	if node.ran("ip address add") {
		t.Errorf("an address was added into a network the node uses: %v", node.calls)
	}
}

func TestRestoreInterfaceAddressFailures(t *testing.T) {
	node := newReloadNode(t)
	node.address = false
	node.addErr = errors.New("exit status 2")
	if err := RestoreInterfaceAddress(context.Background(), guardIface, guardCIDR); err == nil || errors.Is(err, ErrInterfaceGone) {
		t.Fatalf("a refused add was read as %v", err)
	}
	// The zone was removed between the look and the add.
	node.addErr = nil
	node.bridge = false
	if err := RestoreInterfaceAddress(context.Background(), guardIface, guardCIDR); !errors.Is(err, ErrInterfaceGone) {
		t.Fatalf("an add to a missing interface = %v, want ErrInterfaceGone", err)
	}
	if err := RestoreInterfaceAddress(context.Background(), "csVnet3", "bad"); err == nil {
		t.Fatal("a bad CIDR was accepted")
	}
}

// The containment is installed again by the script AddInterfaceAddress uses,
// and no address or forwarding command runs with it.
func TestRestoreInterfaceContainmentInstallsTheSameTable(t *testing.T) {
	node := newReloadNode(t)
	node.table = false
	if err := RestoreInterfaceContainment(context.Background(), guardIface, guardCIDR); err != nil {
		t.Fatal(err)
	}
	if len(node.nftScripts) != 1 || node.nftScripts[0] != isolationNFTScript(isolationTableName(guardIface, guardCIDR), guardIface) {
		t.Fatalf("scripts = %q", node.nftScripts)
	}
	if node.ran("ip address") {
		t.Errorf("restoring the table touched an address: %v", node.calls)
	}
	node.nftInstallErr = errors.New("exit status 1")
	if err := RestoreInterfaceContainment(context.Background(), guardIface, guardCIDR); err == nil || !strings.Contains(err.Error(), isolationTableName(guardIface, guardCIDR)) {
		t.Fatalf("a refused install = %v", err)
	}
}

// A run asks what is already on the host before it journals the allocation as
// pending: an address or table that was there first must be named, so the run
// stops instead of recovery later removing it as the run's.
func TestHostAddressTakenNamesWhatWasThereFirst(t *testing.T) {
	node := newReloadNode(t)

	taken, err := HostAddressTaken(context.Background(), guardIface, guardCIDR)
	if err != nil || !strings.Contains(taken, "address "+guardCIDR+" is already on interface "+guardIface) || !strings.Contains(taken, "containment table") {
		t.Fatalf("address and table present: %q, %v", taken, err)
	}
	node.address = false
	if taken, err = HostAddressTaken(context.Background(), guardIface, guardCIDR); err != nil || strings.Contains(taken, "address") || !strings.Contains(taken, "containment table "+isolationTableName(guardIface, guardCIDR)+" already exists") {
		t.Fatalf("table only: %q, %v", taken, err)
	}
	node.address, node.table = true, false
	if taken, err = HostAddressTaken(context.Background(), guardIface, guardCIDR); err != nil || !strings.Contains(taken, "address") || strings.Contains(taken, "containment table") {
		t.Fatalf("address only: %q, %v", taken, err)
	}
	node.address = false
	if taken, err = HostAddressTaken(context.Background(), guardIface, guardCIDR); err != nil || taken != "" {
		t.Fatalf("clean host: %q, %v", taken, err)
	}
	for _, call := range node.calls {
		if strings.HasPrefix(call, "ip address add") || strings.HasPrefix(call, "nft delete") || strings.Contains(call, "-f -") {
			t.Errorf("the look at the host ran %q", call)
		}
	}
	// A fact that cannot be read is an error: the run does not guess.
	node.nftListErr = errors.New("exit status 1")
	if _, err = HostAddressTaken(context.Background(), guardIface, guardCIDR); err == nil {
		t.Fatal("an unreadable nft listing was taken for a clean host")
	}
}
