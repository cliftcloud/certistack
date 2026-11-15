// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package sysutil

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fakeNodeRoots(t *testing.T) (sys, proc, procNet string) {
	t.Helper()
	dir := t.TempDir()
	sys, proc, procNet = filepath.Join(dir, "sys"), filepath.Join(dir, "proc"), filepath.Join(dir, "procnet")
	for _, d := range []string{sys, proc, procNet} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	origSys, origProc, origNet, origEvery := sysClassNet, procDir, procSysNet, settleEvery
	sysClassNet, procDir, procSysNet, settleEvery = sys, proc, procNet, time.Millisecond
	t.Cleanup(func() { sysClassNet, procDir, procSysNet, settleEvery = origSys, origProc, origNet, origEvery })
	return sys, proc, procNet
}

// The bridge appearing (setup) or going (teardown) settles it, on any
// platform; ifupdown2's part is Linux's (bridge_linux_test.go).
func TestSettleBridgeWaitsForTheBridge(t *testing.T) {
	sys, _, _ := fakeNodeRoots(t)
	go func() {
		time.Sleep(20 * time.Millisecond)
		_ = os.MkdirAll(filepath.Join(sys, "csVnet1"), 0o755)
	}()
	if err := SettleBridge(context.Background(), "csVnet1", true, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	_ = os.RemoveAll(filepath.Join(sys, "csVnet1"))
	if err := SettleBridge(context.Background(), "csVnet1", false, time.Second); err != nil {
		t.Fatal(err)
	}
	err := SettleBridge(context.Background(), "csVnet1", true, 20*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "bridge csVnet1 is absent") {
		t.Fatalf("SettleBridge = %v", err)
	}
}

func TestDisableBridgeForwardingWritesZero(t *testing.T) {
	_, _, procNet := fakeNodeRoots(t)
	for _, family := range []string{"ipv4", "ipv6"} {
		dir := filepath.Join(procNet, family, "conf", "csVnet1")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "forwarding"), []byte("1\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := DisableBridgeForwarding("csVnet1"); err != nil {
		t.Fatal(err)
	}
	for _, family := range []string{"ipv4", "ipv6"} {
		got, _ := os.ReadFile(filepath.Join(procNet, family, "conf", "csVnet1", "forwarding"))
		if strings.TrimSpace(string(got)) != "0" {
			t.Fatalf("%s forwarding = %q", family, got)
		}
	}
	// No IPv6 on the node: IPv4 alone.
	_ = os.RemoveAll(filepath.Join(procNet, "ipv6"))
	if err := DisableBridgeForwarding("csVnet1"); err != nil {
		t.Fatalf("without IPv6: %v", err)
	}
	if err := DisableBridgeForwarding("../eth0"); err == nil {
		t.Fatal("a path in the bridge name was accepted")
	}
}

// The guard puts back only the switch a reload turned on: the other family is
// left as it was (a bridge the platform owns keeps its own IPv6 setting).
func TestDisableBridgeForwardingOfWritesOnlyTheNamedFamilies(t *testing.T) {
	_, _, procNet := fakeNodeRoots(t)
	for _, family := range []string{"ipv4", "ipv6"} {
		dir := filepath.Join(procNet, family, "conf", "csVnet1")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "forwarding"), []byte("1\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	read := func(family string) string {
		got, _ := os.ReadFile(filepath.Join(procNet, family, "conf", "csVnet1", "forwarding"))
		return strings.TrimSpace(string(got))
	}
	if err := DisableBridgeForwardingOf("csVnet1", "IPv4"); err != nil {
		t.Fatal(err)
	}
	if read("ipv4") != "0" || read("ipv6") != "1" {
		t.Fatalf("after IPv4 only: v4=%s v6=%s", read("ipv4"), read("ipv6"))
	}
	if err := DisableBridgeForwardingOf("csVnet1", "IPv6"); err != nil || read("ipv6") != "0" {
		t.Fatalf("IPv6: %v, v6=%s", err, read("ipv6"))
	}
	_ = os.RemoveAll(filepath.Join(procNet, "ipv6"))
	if err := DisableBridgeForwardingOf("csVnet1", "IPv6"); err != nil {
		t.Fatalf("without IPv6 on the node: %v", err)
	}
	if err := DisableBridgeForwardingOf("csVnet1", "IPv5"); err == nil {
		t.Fatal("an unknown family was accepted")
	}
	if err := DisableBridgeForwardingOf("../eth0", "IPv4"); err == nil {
		t.Fatal("a path in the bridge name was accepted")
	}
}

// PVE reloads the nodes in turn, about 6.5 s each, and this node may be
// last: 78 s on 12 nodes.
func TestSettleTimeoutScalesWithTheCluster(t *testing.T) {
	for nodes, want := range map[int]time.Duration{0: 3 * time.Minute, 12: 3 * time.Minute, 18: 3 * time.Minute, 30: 5 * time.Minute, 64: 640 * time.Second} {
		if got := SettleTimeout(nodes); got != want {
			t.Errorf("SettleTimeout(%d) = %s, want %s", nodes, got, want)
		}
	}
}
