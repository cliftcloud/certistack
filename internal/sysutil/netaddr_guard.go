// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package sysutil

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// The probe address AddInterfaceAddress assigns is not in ifupdown2's
// configuration, so the node's next network reload removes it, and turns IPv4
// forwarding back on for the bridge. PVE reloads every node's network at each
// cluster-wide SDN apply (this run's, another run's, an administrator's or
// Terraform's). The nftables containment table is keyed on the interface name
// and survives a reload; the address and the forwarding switch do not. The
// functions below let a run look at the three, read-only, and put back what a
// reload took away, without touching the journal or the table that is there.

// ErrInterfaceGone marks a restore that failed because the interface no longer
// exists: its zone was removed, and its addresses went with it. Nothing can be
// put back on it.
var ErrInterfaceGone = errors.New("the interface does not exist")

// HostAddressState is what a read-only look at a run's probe address finds.
type HostAddressState struct {
	// BridgePresent is false when the interface does not exist. The other
	// fields are then not read.
	BridgePresent bool
	// Ifindex is the interface's kernel index; 0 when it could not be read.
	Ifindex int
	// AddressPresent is whether the interface carries exactly the probe CIDR.
	AddressPresent bool
	// TablePresent is whether the containment table exists, and TableHandle
	// its kernel handle (0 when nft's listing did not name one).
	TablePresent bool
	TableHandle  uint64
	// ForwardingOn names the forwarding switches found on for the bridge:
	// "IPv4" and "IPv6" (the two DisableBridgeForwarding turns off).
	ForwardingOn []string
}

// InspectHostAddress reads the state of the probe address cidr on iface, the
// containment table AddInterfaceAddress installed for it, and the bridge's
// forwarding switches. It changes nothing. A missing interface is a state
// (BridgePresent false), not an error; an error means a fact could not be read.
func InspectHostAddress(ctx context.Context, iface, cidr string) (HostAddressState, error) {
	var state HostAddressState
	if err := validateInterfaceAddress(iface, cidr); err != nil {
		return state, err
	}
	if err := validateBridgeName(iface); err != nil {
		return state, err
	}
	index, err := sysfsInterfaceIndex(iface)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return state, nil
	case err != nil:
		return state, err
	}
	state.BridgePresent, state.Ifindex = true, index
	if state.AddressPresent, err = interfaceHasAddress(ctx, iface, cidr); err != nil {
		return state, fmt.Errorf("inspect addresses on interface %s: %w", iface, err)
	}
	if state.TablePresent, state.TableHandle, err = isolationTableState(ctx, iface, cidr); err != nil {
		return state, err
	}
	if state.ForwardingOn, err = forwardingSwitchesOn(iface); err != nil {
		return state, err
	}
	return state, nil
}

// HostAddressTaken says what is already on the host where a run is about to
// install probe address cidr on iface: the address itself, the containment
// table AddInterfaceAddress would install for it, or both. "" means neither,
// so everything found there afterwards was added by the run. It changes
// nothing; an error means a fact could not be read.
//
// A run asks before it journals the allocation as pending, because recovery
// settles a pending allocation by what the host shows: with a table or address
// that was there first, a crash right after the journal write would otherwise
// leave recovery to remove what was never the run's.
func HostAddressTaken(ctx context.Context, iface, cidr string) (string, error) {
	state, err := InspectHostAddress(ctx, iface, cidr)
	if err != nil {
		return "", err
	}
	var found []string
	if state.AddressPresent {
		found = append(found, fmt.Sprintf("address %s is already on interface %s", cidr, iface))
	}
	if state.TablePresent {
		found = append(found, fmt.Sprintf("containment table %s already exists", isolationTableName(iface, cidr)))
	}
	return strings.Join(found, " and "), nil
}

// sysfsInterfaceIndex is the kernel index of iface from /sys/class/net, which
// does not exist (os.ErrNotExist) for an interface that is gone.
func sysfsInterfaceIndex(iface string) (int, error) {
	data, err := os.ReadFile(filepath.Join(sysClassNet, iface, "ifindex"))
	if err != nil {
		return 0, err
	}
	index, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || index <= 0 {
		// The interface is there; its index is only unknown.
		return 0, nil
	}
	return index, nil
}

// isolationTableState says whether the containment table for cidr on iface
// exists. Its handle is read when nft names one; a listing that does not is
// still a table that exists.
func isolationTableState(ctx context.Context, iface, cidr string) (present bool, handle uint64, err error) {
	table := isolationTableName(iface, cidr)
	result, err := runCommand(ctx, 15*time.Second, "nft", "-a", "list", "table", "inet", table)
	if err != nil {
		if nftObjectAlreadyAbsent(result) {
			return false, 0, nil
		}
		return false, 0, fmt.Errorf("list containment table %s: %w", table, err)
	}
	first, _, _ := strings.Cut(string(result.Stdout), "\n")
	if match := tableHandlePattern.FindStringSubmatch(first); match != nil {
		handle, _ = strconv.ParseUint(match[1], 10, 64)
	}
	return true, handle, nil
}

// forwardingSwitchesOn reads the bridge's IPv4 and IPv6 forwarding switches
// (the ones DisableBridgeForwarding writes) and names those that are on. A
// node without IPv6 has no IPv6 switch.
func forwardingSwitchesOn(iface string) ([]string, error) {
	var on []string
	for _, family := range []struct{ name, dir string }{{"IPv4", "ipv4"}, {"IPv6", "ipv6"}} {
		data, err := os.ReadFile(filepath.Join(procSysNet, family.dir, "conf", iface, "forwarding"))
		if err != nil {
			if family.dir == "ipv6" && errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, fmt.Errorf("read %s forwarding on bridge %s: %w", family.name, iface, err)
		}
		if strings.TrimSpace(string(data)) != "0" {
			on = append(on, family.name)
		}
	}
	return on, nil
}

// RestoreInterfaceAddress puts back the probe address that a network reload
// removed from iface: `ip address add` alone, after the checks
// AddInterfaceAddress makes that the node itself does not use the network.
// It installs no containment and records nothing; the caller already owns the
// address (its journal entry and its removal at teardown stand). An address that
// is on the interface again is left as it is. A missing interface wraps
// ErrInterfaceGone.
func RestoreInterfaceAddress(ctx context.Context, iface, cidr string) error {
	if err := validateInterfaceAddress(iface, cidr); err != nil {
		return err
	}
	// The node may have gained an address, route or gateway in the network
	// since the run added the address; adding it again would capture them.
	if err := verifyNodeNetworksClear(ctx, iface, cidr); err != nil {
		return err
	}
	present, err := interfaceHasAddress(ctx, iface, cidr)
	if err != nil {
		return fmt.Errorf("inspect addresses on interface %s: %w", iface, err)
	}
	if present {
		return nil
	}
	result, err := runCommand(ctx, 15*time.Second, "ip", "address", "add", cidr, "dev", iface)
	if err != nil {
		if result != nil && interfaceAlreadyAbsent(string(result.Stderr)) {
			return fmt.Errorf("add address %s to interface %s: %w", cidr, iface, ErrInterfaceGone)
		}
		return fmt.Errorf("add address %s to interface %s: %w", cidr, iface, err)
	}
	return nil
}

// RestoreInterfaceContainment installs the containment table for cidr on iface
// again, exactly as AddInterfaceAddress does. The caller has found the table
// missing.
func RestoreInterfaceContainment(ctx context.Context, iface, cidr string) error {
	if err := validateInterfaceAddress(iface, cidr); err != nil {
		return err
	}
	if err := addInterfaceIsolation(ctx, iface, cidr); err != nil {
		return fmt.Errorf("install containment table %s for interface %s: %w", isolationTableName(iface, cidr), iface, err)
	}
	return nil
}
