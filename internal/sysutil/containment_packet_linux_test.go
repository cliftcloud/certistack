//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package sysutil

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The packet-level containment test. It builds a bridge with a probe address
// and a "guest" in a network namespace of its own, and sends real packets
// through the nftables containment and the real ip and nft commands. It is
// opt-in because it needs privilege over a network namespace and touches
// devices and firewall tables, so it runs only inside a private one:
//
//	unshare -Urn bash -c 'CERTISTACK_PACKET_TEST_NETNS=$(readlink /proc/self/ns/net) \
//	    go test ./internal/sysutil -run ContainmentPacket -count=1 -v'
//
// (a user and network namespace of its own, as an unprivileged user can
// create; ip, nft, nsenter, unshare and python3 must be installed). Without
// that variable naming the very namespace the test runs in, it skips: it
// never creates anything in the host's namespace.
const (
	packetBridge = "csptbr"
	packetCIDR   = "10.203.77.1/24"
)

type packetLab struct {
	t       *testing.T
	peerPID string
	port    int
}

// privateNetns skips the test unless it runs in the network namespace the
// caller named as private, and returns the tools' absence as a skip.
func privateNetns(t *testing.T) {
	t.Helper()
	ns, err := os.Readlink("/proc/self/ns/net")
	if err != nil || os.Getenv("CERTISTACK_PACKET_TEST_NETNS") != ns {
		t.Skip("opt-in: run it in a private network namespace, see the comment above")
	}
	for _, tool := range []string{"ip", "nft", "nsenter", "unshare", "python3"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("opt-in packet test needs %s: %v", tool, err)
		}
	}
}

func packetCommand(t *testing.T, binary string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, binary, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v: %s", binary, args, err, out)
	}
	return string(out)
}

// newPacketLab makes the bridge with the probe address assigned and a listener
// on it, and a guest namespace attached to the bridge by a veth pair.
func newPacketLab(t *testing.T) *packetLab {
	t.Helper()
	lab := &packetLab{t: t}
	// The tests share the namespace: each leaves it as it found it.
	t.Cleanup(func() {
		_ = exec.Command("ip", "link", "del", "csptside").Run()
		_ = exec.Command("ip", "link", "del", packetBridge).Run()
		_ = exec.Command("nft", "delete", "table", "inet", isolationTableName(packetBridge, packetCIDR)).Run()
	})
	packetCommand(t, "ip", "link", "set", "lo", "up")
	packetCommand(t, "ip", "link", "add", packetBridge, "type", "bridge")
	packetCommand(t, "ip", "link", "set", packetBridge, "up")
	packetCommand(t, "ip", "address", "add", packetCIDR, "dev", packetBridge)
	packetCommand(t, "ip", "link", "add", "csptside", "type", "veth", "peer", "name", "csptguest")
	packetCommand(t, "ip", "link", "set", "csptside", "master", packetBridge)
	packetCommand(t, "ip", "link", "set", "csptside", "up")

	peer := exec.Command("unshare", "--net", "sleep", "60")
	if err := peer.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Process.Kill(); _ = peer.Wait() })
	lab.peerPID = strconv.Itoa(peer.Process.Pid)
	ns, _ := os.Readlink("/proc/self/ns/net")
	ready := false
	for i := 0; i < 200 && !ready; i++ {
		peerNS, err := os.Readlink("/proc/" + lab.peerPID + "/ns/net")
		ready = err == nil && peerNS != ns
		if !ready {
			time.Sleep(5 * time.Millisecond)
		}
	}
	if !ready {
		t.Fatal("the guest network namespace did not become ready")
	}
	packetCommand(t, "ip", "link", "set", "csptguest", "netns", lab.peerPID)
	guest := func(args ...string) {
		packetCommand(t, "nsenter", append([]string{"-t", lab.peerPID, "-n"}, args...)...)
	}
	guest("ip", "link", "set", "lo", "up")
	guest("ip", "address", "add", "10.203.77.2/24", "dev", "csptguest")
	guest("ip", "link", "set", "csptguest", "up")

	listener, err := net.Listen("tcp4", "10.203.77.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte("host-service"))
			_ = conn.Close()
		}
	}()
	lab.port = listener.Addr().(*net.TCPAddr).Port
	return lab
}

// reaches reports whether the guest gets the host service's answer.
func (l *packetLab) reaches() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	script := fmt.Sprintf("import socket; s=socket.create_connection(('10.203.77.1',%d),0.5); print(s.recv(32).decode()); s.close()", l.port)
	out, err := exec.CommandContext(ctx, "nsenter", "-t", l.peerPID, "-n", "python3", "-c", script).CombinedOutput()
	return err == nil && strings.Contains(string(out), "host-service")
}

func tableInstalled(t *testing.T) bool {
	t.Helper()
	return exec.Command("nft", "list", "table", "inet", isolationTableName(packetBridge, packetCIDR)).Run() == nil
}

// failAddressDelete makes every `ip address delete` fail as a timeout or a
// permission failure would, for the rest of the test.
func failAddressDelete(t *testing.T) (restore func()) {
	t.Helper()
	real := runCommand
	runCommand = func(ctx context.Context, timeout time.Duration, binary string, args ...string) (*Result, error) {
		if binary == "ip" && len(args) >= 2 && args[0] == "address" && args[1] == "delete" {
			return &Result{Stderr: []byte("injected: operation not permitted")}, errors.New("injected exit status 2")
		}
		return real(ctx, timeout, binary, args...)
	}
	restore = func() { runCommand = real }
	t.Cleanup(restore)
	return restore
}

// With real packets: a failed address removal must not take the
// containment with it. The reporter's version of this test showed the guest
// reaching the host's service after such a failure; now the guest stays cut
// off until the address is really gone, and only then is the table removed.
func TestContainmentPacketStaysUntilTheAddressIsGone(t *testing.T) {
	privateNetns(t)
	lab := newPacketLab(t)
	if !lab.reaches() {
		t.Fatal("control: the guest cannot reach the host service before containment")
	}
	if err := addInterfaceIsolation(context.Background(), packetBridge, packetCIDR); err != nil {
		t.Fatal(err)
	}
	if lab.reaches() {
		t.Fatal("containment did not block the guest's connection")
	}

	restore := failAddressDelete(t)
	err := RemoveInterfaceAddress(context.Background(), packetBridge, packetCIDR)
	if !errors.Is(err, ErrAddressLeft) {
		t.Fatalf("a removal whose address delete failed = %v, want ErrAddressLeft", err)
	}
	if !tableInstalled(t) || lab.reaches() {
		t.Fatalf("after the failed removal: table installed %v, guest reaches the host %v; want the containment kept and the guest cut off", tableInstalled(t), lab.reaches())
	}

	restore()
	if err := RemoveInterfaceAddress(context.Background(), packetBridge, packetCIDR); err != nil {
		t.Fatalf("removal once nothing fails = %v", err)
	}
	if tableInstalled(t) {
		t.Fatal("the containment table stayed after the address was removed")
	}
	if strings.Contains(packetCommand(t, "ip", "-o", "address", "show", "dev", packetBridge), "10.203.77.1/24") {
		t.Fatal("the address is still assigned")
	}
}

// Against the real ip: a bridge that is already gone (a removed VNet takes
// its bridge and the address on it) is an absent address, not an error, even
// when the delete itself failed and the follow-up query has to say so. The
// messages matched are iproute2's own.
func TestContainmentPacketRemovalOfAnAddressWhoseBridgeIsGone(t *testing.T) {
	privateNetns(t)
	newPacketLab(t)
	if err := addInterfaceIsolation(context.Background(), packetBridge, packetCIDR); err != nil {
		t.Fatal(err)
	}
	packetCommand(t, "ip", "link", "del", packetBridge)

	// The delete fails with something that is not "absent" (a timeout, say),
	// so only the query of the missing interface can show the address gone.
	failAddressDelete(t)
	if err := RemoveInterfaceAddress(context.Background(), packetBridge, packetCIDR); err != nil {
		t.Fatalf("removal of an address whose bridge is gone = %v, want success", err)
	}
	if tableInstalled(t) {
		t.Fatal("the containment table stayed after its address and bridge were gone")
	}
}

// Against the real ip and nft: an interface and containment table of
// the same names that a later owner created are a replacement, and a removal
// with the identities the first owner recorded leaves both alone, then removes
// exactly what still carries them.
func TestContainmentPacketRecordedIdentityLeavesAReplacement(t *testing.T) {
	privateNetns(t)
	newPacketLab(t)
	if err := addInterfaceIsolation(context.Background(), packetBridge, packetCIDR); err != nil {
		t.Fatal(err)
	}
	ifindex, handle, err := HostAddressIdentity(context.Background(), packetBridge, packetCIDR)
	if err != nil || ifindex == 0 || handle == 0 {
		t.Fatalf("identity = %d, %d, %v", ifindex, handle, err)
	}

	// The first owner's interface and table go, and a replacement takes their names.
	packetCommand(t, "ip", "link", "del", "csptside")
	packetCommand(t, "ip", "link", "del", packetBridge)
	packetCommand(t, "nft", "delete", "table", "inet", isolationTableName(packetBridge, packetCIDR))
	packetCommand(t, "ip", "link", "add", packetBridge, "type", "bridge")
	packetCommand(t, "ip", "link", "set", packetBridge, "up")
	packetCommand(t, "ip", "address", "add", packetCIDR, "dev", packetBridge)
	if err := addInterfaceIsolation(context.Background(), packetBridge, packetCIDR); err != nil {
		t.Fatal(err)
	}
	newIndex, newHandle, err := HostAddressIdentity(context.Background(), packetBridge, packetCIDR)
	if err != nil || newIndex == ifindex || newHandle == handle {
		t.Fatalf("the replacement has identity %d, %d, the same as the first owner's %d, %d (%v)", newIndex, newHandle, ifindex, handle, err)
	}

	notes, err := RemoveRecordedHostAddress(context.Background(), packetBridge, packetCIDR, ifindex, handle)
	if err != nil || len(notes) != 2 {
		t.Fatalf("removal with the first owner's identity = %v, %v; want the replacements reported and left", notes, err)
	}
	if !tableInstalled(t) || !strings.Contains(packetCommand(t, "ip", "-o", "address", "show", "dev", packetBridge), "10.203.77.1/24") {
		t.Fatal("the replacement's table or address was removed")
	}

	// With the replacement's own identity, the removal takes exactly them.
	if notes, err := RemoveRecordedHostAddress(context.Background(), packetBridge, packetCIDR, newIndex, newHandle); err != nil || len(notes) != 0 {
		t.Fatalf("removal with the replacement's own identity = %v, %v", notes, err)
	}
	if tableInstalled(t) || strings.Contains(packetCommand(t, "ip", "-o", "address", "show", "dev", packetBridge), "10.203.77.1/24") {
		t.Fatal("the table or address the identity names was not removed")
	}
}
