// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package sysutil

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// Commands are run through these variables so tests can simulate failures
// of the individual steps.
var (
	runCommand          = Run
	runCommandWithInput = RunWithInput
)

// ErrContainmentLeft marks an AddInterfaceAddress or RemoveInterfaceAddress
// failure after which this run's nftables containment table is still
// installed while the address is gone: the caller owns the table and must
// remove it (RemoveInterfaceContainment, or RemoveInterfaceAddress again)
// and record it until then.
var ErrContainmentLeft = errors.New("VNet containment table left in place")

// ErrAddressLeft marks an AddInterfaceAddress or RemoveInterfaceAddress
// failure after which the address may still be assigned by this run (for
// example a timed-out `ip address add` that took effect, or a failed
// delete): the caller owns the address and its containment, which stays
// installed, and must remove both (RemoveInterfaceAddress) and record them
// until then.
var ErrAddressLeft = errors.New("probe address may be left assigned")

// AddInterfaceAddress assigns an exact CIDR to a local Linux interface. It is
// intended for the temporary host-side endpoint on a CertiStack VNet. It
// refuses an address already on the interface, which belongs to someone
// else. A failure returns with nothing of this run's left behind, unless the
// error wraps ErrContainmentLeft or ErrAddressLeft.
func AddInterfaceAddress(ctx context.Context, iface, cidr string) error {
	if err := validateInterfaceAddress(iface, cidr); err != nil {
		return err
	}
	if err := verifyInterfaceForwardingDisabled(ctx, iface); err != nil {
		return err
	}
	if err := verifyNodeNetworksClear(ctx, iface, cidr); err != nil {
		return err
	}
	present, err := interfaceHasAddress(ctx, iface, cidr)
	if err != nil {
		return fmt.Errorf("inspect addresses on interface %s: %w", iface, err)
	}
	if present {
		return fmt.Errorf("address %s is already assigned to interface %s and is not owned by this run", cidr, iface)
	}
	if err := addInterfaceIsolation(ctx, iface, cidr); err != nil {
		return fmt.Errorf("contain VNet interface %s before assigning probe address: %w", iface, err)
	}
	if _, err := runCommand(ctx, 15*time.Second, "ip", "address", "add", cidr, "dev", iface); err != nil {
		return rollBackInterfaceAddress(iface, cidr, fmt.Errorf("add address %s to interface %s: %w", cidr, iface, err))
	}
	return nil
}

// rollBackInterfaceAddress undoes a failed AddInterfaceAddress. The address
// was absent before the add, so if it is present now it is this run's.
func rollBackInterfaceAddress(iface, cidr string, addErr error) error {
	ctx := context.Background()
	present, inspectErr := interfaceHasAddress(ctx, iface, cidr)
	switch {
	case inspectErr != nil:
		return errors.Join(addErr, fmt.Errorf("%w: cannot inspect interface %s after the failed add: %v", ErrAddressLeft, iface, inspectErr))
	case present:
		if err := RemoveInterfaceAddress(ctx, iface, cidr); err != nil {
			// The error says whether the address or only its containment
			// is left; anything else leaves the address unaccounted for.
			if errors.Is(err, ErrAddressLeft) || errors.Is(err, ErrContainmentLeft) {
				return errors.Join(addErr, fmt.Errorf("roll back %s on %s: %w", cidr, iface, err))
			}
			return errors.Join(addErr, fmt.Errorf("%w: roll back %s on %s: %v", ErrAddressLeft, cidr, iface, err))
		}
		return addErr
	}
	if err := removeInterfaceIsolation(ctx, iface, cidr); err != nil {
		return errors.Join(addErr, fmt.Errorf("%w: roll back containment on %s: %v", ErrContainmentLeft, iface, err))
	}
	return addErr
}

// RemoveInterfaceContainment removes only the nftables containment table
// AddInterfaceAddress installs, leaving the interface's addresses alone. It
// is for a failed add, where an address on the interface is not this run's.
func RemoveInterfaceContainment(ctx context.Context, iface, cidr string) error {
	if err := validateInterfaceAddress(iface, cidr); err != nil {
		return err
	}
	if err := removeInterfaceIsolation(ctx, iface, cidr); err != nil {
		return fmt.Errorf("remove VNet containment from interface %s: %w", iface, err)
	}
	return nil
}

// interfaceHasAddress reports whether iface carries exactly cidr (address and
// prefix length). An interface that does not exist carries nothing: the
// answer is "no", not an error, so a VNet whose bridge is already gone (a
// removed SDN VNet takes its bridge and the addresses on it) does not turn a
// finished removal into a failed one.
func interfaceHasAddress(ctx context.Context, iface, cidr string) (bool, error) {
	wantIP, wantNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false, err
	}
	wantOnes, _ := wantNet.Mask.Size()
	result, err := runCommand(ctx, 15*time.Second, "ip", "-o", "address", "show", "dev", iface)
	if err != nil {
		if result != nil && !errors.Is(err, context.DeadlineExceeded) && interfaceAlreadyAbsent(string(result.Stderr)) {
			return false, nil
		}
		return false, err
	}
	for _, line := range strings.Split(string(result.Stdout), "\n") {
		fields := strings.Fields(line)
		for i := 0; i+1 < len(fields); i++ {
			if fields[i] != "inet" && fields[i] != "inet6" {
				continue
			}
			ip, network, err := net.ParseCIDR(fields[i+1])
			if err != nil {
				continue
			}
			if ones, _ := network.Mask.Size(); ip.Equal(wantIP) && ones == wantOnes {
				return true, nil
			}
		}
	}
	return false, nil
}

// verifyNodeNetworksClear refuses a probe address whose network the node itself
// already uses: an address on another interface inside it, a route for it, or
// a default gateway inside it. Adding the probe address would give the node a
// second connected route for that network and, if the gateway is the probe
// address, a local address in place of its gateway, so the node's own traffic
// (and the controller's SSH session) would be captured for the length of the
// run. Only the VNet's own interface and loopback may carry the range.
func verifyNodeNetworksClear(ctx context.Context, iface, cidr string) error {
	_, sandbox, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	overlaps := func(other *net.IPNet) bool { return sandbox.Contains(other.IP) || other.Contains(sandbox.IP) }
	deviceName := func(token string) string { return strings.SplitN(strings.TrimSuffix(token, ":"), "@", 2)[0] }

	addresses, err := runCommand(ctx, 15*time.Second, "ip", "-4", "-o", "address", "show")
	if err != nil {
		return fmt.Errorf("list the node's IPv4 addresses before assigning the probe address: %w", err)
	}
	for _, line := range strings.Split(string(addresses.Stdout), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[2] != "inet" {
			continue
		}
		name := deviceName(fields[1])
		if name == iface || name == "lo" {
			continue
		}
		if _, network, err := net.ParseCIDR(fields[3]); err == nil && overlaps(network) {
			return fmt.Errorf("refusing probe address %s: the node itself uses %s on %s (address %s), inside or around the sandbox network %s. Assigning the probe address would capture the node's own traffic for that network and could cut it off from its controller. Choose a network.ip_range that no address, route or gateway of the node uses", cidr, network, name, fields[3], sandbox)
		}
	}

	routes, err := runCommand(ctx, 15*time.Second, "ip", "-4", "route", "show")
	if err != nil {
		return fmt.Errorf("list the node's IPv4 routes before assigning the probe address: %w", err)
	}
	for _, line := range strings.Split(string(routes.Stdout), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		device, via := "", ""
		for i := 1; i+1 < len(fields); i++ {
			switch fields[i] {
			case "dev":
				device = deviceName(fields[i+1])
			case "via":
				via = fields[i+1]
			}
		}
		if device == iface || device == "lo" {
			continue
		}
		if gateway := net.ParseIP(via); gateway != nil && sandbox.Contains(gateway) {
			return fmt.Errorf("refusing probe address %s: the node reaches other networks through the gateway %s (%q), which is inside the sandbox network %s. Assigning the probe address would capture the node's traffic to its gateway and could cut it off from its controller. Choose a network.ip_range that does not contain the node's gateway", cidr, via, strings.TrimSpace(line), sandbox)
		}
		if fields[0] == "default" || strings.HasPrefix(fields[0], "unreachable") || strings.HasPrefix(fields[0], "blackhole") {
			continue
		}
		prefix := fields[0]
		if !strings.Contains(prefix, "/") {
			prefix += "/32"
		}
		if _, network, err := net.ParseCIDR(prefix); err == nil && overlaps(network) {
			return fmt.Errorf("refusing probe address %s: the node has a route for %s (%q), inside or around the sandbox network %s. Assigning the probe address would capture the node's traffic for that network. Choose a network.ip_range that no address or route of the node uses", cidr, network, strings.TrimSpace(line), sandbox)
		}
	}
	return nil
}

func verifyInterfaceForwardingDisabled(ctx context.Context, iface string) error {
	key := "net.ipv4.conf." + iface + ".forwarding"
	result, err := runCommand(ctx, 15*time.Second, "sysctl", "-n", key)
	if err != nil {
		return fmt.Errorf("verify IPv4 forwarding is disabled for interface %s: %w", iface, err)
	}
	if strings.TrimSpace(string(result.Stdout)) != "0" {
		return fmt.Errorf("refusing VNet interface %s because IPv4 forwarding is enabled on it. PVE's ifupdown2 turns it on for every SDN bridge at each network reload; a pre-provisioned sandbox VNet must keep it off (for example with an if-up.d hook), see https://certistack.dev/docs/plan-reference/#use-a-pre-provisioned-sandbox", iface)
	}
	return nil
}

// RemoveInterfaceAddress removes only the exact CIDR assigned by
// AddInterfaceAddress, and then its containment table. The table keeps a
// guest on the VNet off the host's services on that address, so it is
// removed only once the address is confirmed gone; a missing interface or
// address is already-cleaned. A failure wraps ErrAddressLeft (the address
// may still be assigned, and its containment stays installed) or
// ErrContainmentLeft (the address is gone, the table is not).
func RemoveInterfaceAddress(ctx context.Context, iface, cidr string) error {
	if err := validateInterfaceAddress(iface, cidr); err != nil {
		return err
	}
	table := isolationTableName(iface, cidr)
	if err := removeExactAddress(ctx, iface, cidr); err != nil {
		return fmt.Errorf("%w: %v; its containment table %s stays installed until the address is gone", ErrAddressLeft, err, table)
	}
	if err := removeInterfaceIsolation(ctx, iface, cidr); err != nil {
		return fmt.Errorf("%w: address %s is removed from interface %s, but its containment table %s is not: %v", ErrContainmentLeft, cidr, iface, table, err)
	}
	return nil
}

// removeExactAddress deletes cidr from iface. It returns nil only when the
// address is gone: the delete succeeded, ip answered that the address or the
// interface does not exist, or, after any other failure (a timed-out delete
// can still have taken effect), the interface is seen without it.
func removeExactAddress(ctx context.Context, iface, cidr string) error {
	result, err := runCommand(ctx, 15*time.Second, "ip", "address", "delete", cidr, "dev", iface)
	if err == nil || (result != nil && interfaceAddressAlreadyAbsent(string(result.Stderr))) {
		return nil
	}
	deleteErr := fmt.Errorf("remove address %s from interface %s: %w", cidr, iface, err)
	// Look again even when ctx has ended: the delete's outcome decides
	// whether the containment can go.
	present, inspectErr := interfaceHasAddress(context.WithoutCancel(ctx), iface, cidr)
	switch {
	case inspectErr != nil:
		return fmt.Errorf("%w, and whether it is still assigned is unknown: %v", deleteErr, inspectErr)
	case present:
		return fmt.Errorf("%w; it is still assigned", deleteErr)
	}
	return nil
}

func addInterfaceIsolation(ctx context.Context, iface, cidr string) error {
	table := isolationTableName(iface, cidr)
	_, err := runCommandWithInput(ctx, 15*time.Second, bytes.NewBufferString(isolationNFTScript(table, iface)), "nft", "-f", "-")
	return err
}

func removeInterfaceIsolation(ctx context.Context, iface, cidr string) error {
	table := isolationTableName(iface, cidr)
	result, err := runCommand(ctx, 15*time.Second, "nft", "delete", "table", "inet", table)
	if err == nil || nftObjectAlreadyAbsent(result) {
		return nil
	}
	return err
}

func isolationTableName(iface, cidr string) string {
	sum := sha256.Sum256([]byte(iface + "\x00" + cidr))
	return "csiso_" + hex.EncodeToString(sum[:])[:12]
}

func isolationNFTScript(table, iface string) string {
	quotedInterface := strconv.Quote(iface)
	return fmt.Sprintf(`add table inet %s
add chain inet %s input { type filter hook input priority -100; policy accept; }
add chain inet %s forward { type filter hook forward priority -100; policy accept; }
add rule inet %s input iifname %s ct state established,related accept
add rule inet %s input iifname %s drop
add rule inet %s forward iifname %s drop
add rule inet %s forward oifname %s drop
`, table, table, table, table, quotedInterface, table, quotedInterface, table, quotedInterface, table, quotedInterface)
}

func nftObjectAlreadyAbsent(result *Result) bool {
	if result == nil {
		return false
	}
	output := strings.ToLower(string(result.Stderr))
	return strings.Contains(output, "no such file") || strings.Contains(output, "does not exist")
}

func interfaceAddressAlreadyAbsent(output string) bool {
	output = strings.ToLower(output)
	return interfaceAlreadyAbsent(output) ||
		strings.Contains(output, "cannot assign requested address") ||
		strings.Contains(output, "address not found")
}

// interfaceAlreadyAbsent recognizes what ip says of an interface that does
// not exist: `Cannot find device "x"` from a modification, and `Device "x"
// does not exist.` from a query.
func interfaceAlreadyAbsent(output string) bool {
	output = strings.ToLower(output)
	return strings.Contains(output, "cannot find device") ||
		(strings.Contains(output, "device") && strings.Contains(output, "does not exist"))
}

func validateInterfaceAddress(iface, cidr string) error {
	if strings.TrimSpace(iface) == "" || len(iface) > 15 || strings.ContainsAny(iface, " \t\r\n\\\"'{};") {
		return fmt.Errorf("interface name must be a short nft-safe identifier")
	}
	if _, _, err := net.ParseCIDR(cidr); err != nil {
		return fmt.Errorf("address must be a valid CIDR: %w", err)
	}
	return nil
}

// IsolationTableName is the nftables table that contains a probe address
// on an interface, as AddInterfaceAddress names it.
func IsolationTableName(iface, cidr string) string { return isolationTableName(iface, cidr) }
