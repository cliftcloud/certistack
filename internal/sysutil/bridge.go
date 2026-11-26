// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package sysutil

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// sysClassNet, procDir and procSysNet are replaced by tests.
var (
	sysClassNet   = "/sys/class/net"
	procDir       = "/proc"
	procSysNet    = "/proc/sys/net"
	settleEvery   = 500 * time.Millisecond
	settleStable  = 2
	ifupdownTools = map[string]bool{"ifreload": true, "ifup": true, "ifdown": true}
)

// SettleTimeout bounds SettleBridge on a cluster of the given number of nodes:
// PVE reloads them one after another, about 6.5 s each, in an order that
// varies, so this node may be last. It is at least 3 minutes, and 10 s a node;
// 3 minutes when the count is unknown (0).
func SettleTimeout(nodes int) time.Duration {
	return max(3*time.Minute, time.Duration(nodes)*10*time.Second)
}

// SettleBridge waits for the network reload an SDN apply started on this
// node: until the bridge iface is there (present) or gone (!present), and
// ifupdown2 is not at work, for two checks in a row. PVE's apply forks
// each node's network reload one after another and does not wait for them,
// so neither its request nor its task's end says when this node's bridge
// is ready. ifupdown2 writes a new bridge's forwarding after
// creating it, so the bridge alone is not enough.
func SettleBridge(ctx context.Context, iface string, present bool, timeout time.Duration) error {
	if err := validateBridgeName(iface); err != nil {
		return err
	}
	deadline := time.Now().Add(timeout)
	stable := 0
	for {
		// Only a path that is there, or that the kernel says is not, is an
		// observation: a lookup that fails for another reason (permission, I/O)
		// proves neither, so it never counts toward the settled checks.
		_, statErr := os.Stat(filepath.Join(sysClassNet, iface))
		exists := statErr == nil
		unknown := ""
		if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
			unknown = "the bridge's state cannot be read: " + statErr.Error()
		}
		busy, busyUnknown := ifupdownState()
		if unknown == "" {
			unknown = busyUnknown
		}
		if exists == present && !busy && unknown == "" {
			if stable++; stable >= settleStable {
				return nil
			}
		} else {
			stable = 0
		}
		if time.Now().After(deadline) {
			state := "absent"
			if exists {
				state = "present"
			}
			if busy {
				state += ", and ifupdown2 is still running"
			}
			if unknown != "" {
				state += ", and it could not be established (" + unknown + ")"
			}
			return fmt.Errorf("the node's network reload after the SDN apply did not settle within %s: bridge %s is %s", timeout, iface, state)
		}
		timer := time.NewTimer(settleEvery)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// BridgePorts lists the interfaces the kernel has attached to bridge iface on
// this node (/sys/class/net/<iface>/brif), sorted: tap devices of VMs, veth
// devices of containers, firewall ports, a VXLAN tunnel, whatever is there,
// whether or not any configuration names it. A bridge that is not on this node,
// an interface that is not a bridge, or a list that cannot be read is an
// error, never an empty bridge.
func BridgePorts(iface string) ([]string, error) {
	if err := validateBridgeName(iface); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(filepath.Join(sysClassNet, iface, "brif"))
	if errors.Is(err, os.ErrNotExist) {
		if _, statErr := os.Stat(filepath.Join(sysClassNet, iface)); errors.Is(statErr, os.ErrNotExist) {
			return nil, fmt.Errorf("bridge %s is not on this node", iface)
		} else if statErr == nil {
			return nil, fmt.Errorf("interface %s on this node is not a bridge", iface)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("read the ports of bridge %s: %w", iface, err)
	}
	ports := make([]string, 0, len(entries))
	for _, entry := range entries {
		ports = append(ports, entry.Name())
	}
	sort.Strings(ports)
	return ports, nil
}

// DisableBridgeForwarding turns IPv4 and IPv6 forwarding off on a bridge
// the run owns. ifupdown2 turns IPv4 forwarding on for every PVE SDN
// bridge at each network reload (it writes 0 only for a bridge with no
// address, no uppers and a static method, and PVE writes VNets without
// one), so an ephemeral sandbox VNet comes up forwarding. The run's
// nftables table drops what is forwarded through it all the same.
func DisableBridgeForwarding(iface string) error {
	if err := validateBridgeName(iface); err != nil {
		return err
	}
	v4 := filepath.Join(procSysNet, "ipv4", "conf", iface, "forwarding")
	if err := os.WriteFile(v4, []byte("0\n"), 0o644); err != nil {
		return fmt.Errorf("turn IPv4 forwarding off on bridge %s: %w", iface, err)
	}
	v6 := filepath.Join(procSysNet, "ipv6", "conf", iface, "forwarding")
	if err := os.WriteFile(v6, []byte("0\n"), 0o644); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("turn IPv6 forwarding off on bridge %s: %w", iface, err)
	}
	return nil
}

// DisableBridgeForwardingOf turns forwarding off for the named families only
// ("IPv4", "IPv6"), leaving the other as it is. The address guard uses it to put
// back the switches a network reload turned on, without touching a switch the
// run found on when it started (a bridge the platform owns).
func DisableBridgeForwardingOf(iface string, families ...string) error {
	if err := validateBridgeName(iface); err != nil {
		return err
	}
	for _, family := range families {
		switch family {
		case "IPv4":
			path := filepath.Join(procSysNet, "ipv4", "conf", iface, "forwarding")
			if err := os.WriteFile(path, []byte("0\n"), 0o644); err != nil {
				return fmt.Errorf("turn IPv4 forwarding off on bridge %s: %w", iface, err)
			}
		case "IPv6":
			path := filepath.Join(procSysNet, "ipv6", "conf", iface, "forwarding")
			if err := os.WriteFile(path, []byte("0\n"), 0o644); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("turn IPv6 forwarding off on bridge %s: %w", iface, err)
			}
		default:
			return fmt.Errorf("unknown forwarding family %q", family)
		}
	}
	return nil
}

func validateBridgeName(iface string) error {
	if iface == "" || len(iface) > 15 || strings.ContainsAny(iface, "/. \t\n") {
		return fmt.Errorf("invalid bridge name %q", iface)
	}
	return nil
}
