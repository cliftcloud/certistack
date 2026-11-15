// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package sysutil

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// A probe address and its containment table are named by the interface and
// CIDR alone, and those are reused: a later run, or an administrator, can
// create the same interface, address and table. What a journal recorded is
// therefore not proof that what is there now is the same thing. The kernel's
// identities are: an interface's index, which no other interface takes while
// this one exists, and an nftables table's handle, which is never issued twice.
// The run records both when it installs the address, and a removal that has
// them touches only what still carries them.

var (
	errInterfaceAbsent = errors.New("the interface does not exist")
	errTableAbsent     = errors.New("the containment table does not exist")
)

var (
	linkIndexPattern   = regexp.MustCompile(`^\s*(\d+):`)
	tableHandlePattern = regexp.MustCompile(`#\s*handle\s+(\d+)\s*$`)
)

// HostAddressIdentity reads the kernel's identity of the interface iface and
// of the containment table AddInterfaceAddress installed for cidr on it: the
// interface index (0 when it cannot be read) and the table's handle (0 when it
// cannot be read), with the first error met. A zero is "not recorded", and a
// removal then falls back to the names alone.
func HostAddressIdentity(ctx context.Context, iface, cidr string) (ifindex int, tableHandle uint64, err error) {
	if err := validateInterfaceAddress(iface, cidr); err != nil {
		return 0, 0, err
	}
	var errs []error
	if ifindex, err = interfaceIndex(ctx, iface); err != nil {
		errs = append(errs, err)
		ifindex = 0
	}
	if tableHandle, err = isolationTableHandle(ctx, iface, cidr); err != nil {
		errs = append(errs, err)
		tableHandle = 0
	}
	return ifindex, tableHandle, errors.Join(errs...)
}

// interfaceIndex is the kernel index of iface; errInterfaceAbsent when there is
// none.
func interfaceIndex(ctx context.Context, iface string) (int, error) {
	result, err := runCommand(ctx, 15*time.Second, "ip", "-o", "link", "show", "dev", iface)
	if err != nil {
		if result != nil && !errors.Is(err, context.DeadlineExceeded) && interfaceAlreadyAbsent(string(result.Stderr)) {
			return 0, errInterfaceAbsent
		}
		return 0, fmt.Errorf("read the index of interface %s: %w", iface, err)
	}
	match := linkIndexPattern.FindStringSubmatch(string(result.Stdout))
	if match == nil {
		return 0, fmt.Errorf("read the index of interface %s: ip answered nothing that names it", iface)
	}
	index, err := strconv.Atoi(match[1])
	if err != nil || index <= 0 {
		return 0, fmt.Errorf("read the index of interface %s: %q is not an index", iface, match[1])
	}
	return index, nil
}

// isolationTableHandle is the nftables handle of the containment table for
// cidr on iface; errTableAbsent when there is none.
func isolationTableHandle(ctx context.Context, iface, cidr string) (uint64, error) {
	table := isolationTableName(iface, cidr)
	result, err := runCommand(ctx, 15*time.Second, "nft", "-a", "list", "table", "inet", table)
	if err != nil {
		if nftObjectAlreadyAbsent(result) {
			return 0, errTableAbsent
		}
		return 0, fmt.Errorf("read the handle of containment table %s: %w", table, err)
	}
	first, _, _ := strings.Cut(string(result.Stdout), "\n")
	match := tableHandlePattern.FindStringSubmatch(first)
	if match == nil {
		return 0, fmt.Errorf("read the handle of containment table %s: nft answered nothing that names it", table)
	}
	handle, err := strconv.ParseUint(match[1], 10, 64)
	if err != nil || handle == 0 {
		return 0, fmt.Errorf("read the handle of containment table %s: %q is not a handle", table, match[1])
	}
	return handle, nil
}

// RemoveRecordedHostAddress is RemoveInterfaceAddress for an address a journal
// recorded with the identity HostAddressIdentity read when it was installed.
// ifindex (when not 0) is the index of the interface the run added it to: the
// address is removed only while the interface still has that index. An
// interface that is gone took its addresses with it; one with another index is
// a replacement, and what is on it is not this run's. handle (when not 0) is
// the handle of the table the run installed: only that table is deleted, by its
// handle, so a table of the same name that a later run or an administrator
// installed is never touched. What is left alone as not the run's is returned in
// notes, for the operator; it is not a failure, since nothing of this run's is
// left in its place. The errors are RemoveInterfaceAddress's.
func RemoveRecordedHostAddress(ctx context.Context, iface, cidr string, ifindex int, handle uint64) (notes []string, err error) {
	if err := validateInterfaceAddress(iface, cidr); err != nil {
		return nil, err
	}
	table := isolationTableName(iface, cidr)
	addressGone := false
	if ifindex != 0 {
		current, indexErr := interfaceIndex(ctx, iface)
		switch {
		case errors.Is(indexErr, errInterfaceAbsent):
			addressGone = true
		case indexErr != nil:
			return nil, fmt.Errorf("%w: cannot tell whether interface %s is the one the run added the address to: %v; its containment table %s stays installed until the address is gone", ErrAddressLeft, iface, indexErr, table)
		case current != ifindex:
			addressGone = true
			notes = append(notes, fmt.Sprintf("left interface %s, and any address on it, alone: it has index %d, not the index %d of the interface the run added %s to", iface, current, ifindex, cidr))
		}
	}
	if !addressGone {
		if err := removeExactAddress(ctx, iface, cidr); err != nil {
			return notes, fmt.Errorf("%w: %v; its containment table %s stays installed until the address is gone", ErrAddressLeft, err, table)
		}
	}
	tableNotes, err := removeRecordedIsolation(ctx, iface, cidr, handle)
	notes = append(notes, tableNotes...)
	if err != nil {
		return notes, fmt.Errorf("%w: address %s is removed from interface %s, but its containment table %s is not: %v", ErrContainmentLeft, cidr, iface, table, err)
	}
	return notes, nil
}

// RemoveRecordedContainment is RemoveInterfaceContainment for a table a journal
// recorded with its handle (0: by name alone).
func RemoveRecordedContainment(ctx context.Context, iface, cidr string, handle uint64) (notes []string, err error) {
	if err := validateInterfaceAddress(iface, cidr); err != nil {
		return nil, err
	}
	notes, err = removeRecordedIsolation(ctx, iface, cidr, handle)
	if err != nil {
		return notes, fmt.Errorf("remove VNet containment from interface %s: %w", iface, err)
	}
	return notes, nil
}

// removeRecordedIsolation deletes the containment table with the recorded
// handle. Without one it deletes the table of that name, as before.
func removeRecordedIsolation(ctx context.Context, iface, cidr string, handle uint64) ([]string, error) {
	if handle == 0 {
		return nil, removeInterfaceIsolation(ctx, iface, cidr)
	}
	table := isolationTableName(iface, cidr)
	current, err := isolationTableHandle(ctx, iface, cidr)
	switch {
	case errors.Is(err, errTableAbsent):
		return nil, nil
	case err != nil:
		return nil, err
	case current != handle:
		return []string{fmt.Sprintf("left table %s alone: its handle is %d, not the handle %d of the table the run installed", table, current, handle)}, nil
	}
	// Deleted by handle: were the table replaced since it was read, this deletes
	// nothing rather than the replacement.
	result, err := runCommand(ctx, 15*time.Second, "nft", "delete", "table", "inet", "handle", strconv.FormatUint(handle, 10))
	if err == nil || nftObjectAlreadyAbsent(result) {
		return nil, nil
	}
	return nil, err
}

// SettleUnconfirmedHostAddress is for a run that was stopped while it added its
// probe address, before the journal recorded the address and its identities
// (allocation_pending): it reads the host for what the run's add
// could have made and removes it when it is shown to be the run's, so that the
// journal can be settled instead of stopping every later run for an operator.
//
// The run asks HostAddressTaken before it journals the allocation, and stops
// when either the address or its table is already there, so what the host shows
// afterwards was put there by the run (up to a change on the host in the
// instant between the look and the add). AddInterfaceAddress refuses an
// address already on the interface and then installs the containment table
// before it adds the address, so the table is what shows the run got that far:
//
//   - the table and the address are both there: the address was added after the
//     table, by the run, and both are removed (by name: no identity was ever
//     recorded);
//   - the table is there and the address is not: only the table is the run's,
//     and it is removed;
//   - the table is not there and the address is: the run never installed the
//     table, so it never added the address, which is someone else's. It is left
//     alone and said in notes;
//   - neither is there: nothing was made.
//
// An error, from reading the host or from a removal, leaves the allocation
// unsettled; ErrAddressLeft and ErrContainmentLeft are RemoveInterfaceAddress's.
func SettleUnconfirmedHostAddress(ctx context.Context, iface, cidr string) (notes []string, err error) {
	if err := validateInterfaceAddress(iface, cidr); err != nil {
		return nil, err
	}
	table := isolationTableName(iface, cidr)
	_, tableErr := isolationTableHandle(ctx, iface, cidr)
	tablePresent := tableErr == nil
	if tableErr != nil && !errors.Is(tableErr, errTableAbsent) {
		return nil, fmt.Errorf("cannot tell whether the run installed containment table %s: %w", table, tableErr)
	}
	addressPresent, err := interfaceHasAddress(ctx, iface, cidr)
	if err != nil {
		return nil, fmt.Errorf("cannot tell whether address %s is on interface %s: %w", cidr, iface, err)
	}
	switch {
	case !tablePresent && !addressPresent:
		return nil, nil
	case !tablePresent:
		return []string{fmt.Sprintf("left address %s on interface %s alone: the run installs containment table %s before it adds the address, and that table is not there, so the address was there before the run and is not the run's", cidr, iface, table)}, nil
	case !addressPresent:
		if err := removeInterfaceIsolation(ctx, iface, cidr); err != nil {
			return nil, fmt.Errorf("%w: containment table %s of the interrupted run is not removed: %v", ErrContainmentLeft, table, err)
		}
		return []string{fmt.Sprintf("removed containment table %s, which the interrupted run installed for %s on %s before it added the address", table, cidr, iface)}, nil
	}
	if err := RemoveInterfaceAddress(ctx, iface, cidr); err != nil {
		return nil, err
	}
	return []string{fmt.Sprintf("removed address %s from interface %s and containment table %s, which the interrupted run was adding when it stopped", cidr, iface, table)}, nil
}
