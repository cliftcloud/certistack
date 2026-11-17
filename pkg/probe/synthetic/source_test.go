// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package synthetic

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/probe"
)

func TestSourceRejectsPartialBinding(t *testing.T) {
	for _, source := range []Source{{Interface: "csVn01"}, {Address: "10.100.0.1"}, {Interface: "csVn01", Address: "not-an-ip"}} {
		if _, err := source.dialer("tcp", time.Second); err == nil {
			t.Errorf("source %+v produced a dialer", source)
		}
	}
}

func boundProbers(port int, source Source) map[string]interface {
	Probe(context.Context) probe.Result
} {
	tcp := NewTCPProber("127.0.0.1", port, time.Second, "bound tcp")
	tcp.Source = source
	httpProber := NewHTTPProber("127.0.0.1", port, "/", false, false, 200, time.Second, "bound http", "")
	httpProber.Source = source
	dns := NewDNSProber("127.0.0.1", port, "", "tcp", time.Second, "bound dns")
	dns.Source = source
	ldap := NewLDAPProber("127.0.0.1", port, "", time.Second, "bound ldap")
	ldap.Source = source
	return map[string]interface {
		Probe(context.Context) probe.Result
	}{"tcp": tcp, "http": httpProber, "dns": dns, "ldap": ldap}
}

// allowLocalTargets disables the worker-address check so a test can exercise
// interface binding on its own against a local listener.
func allowLocalTargets(t *testing.T) {
	t.Helper()
	original := checkTargetNotLocal
	checkTargetNotLocal = func(string) error { return nil }
	t.Cleanup(func() { checkTargetNotLocal = original })
}

// A bound wire probe never reaches a listener on the worker host itself.
func TestBoundProbesRefuseWorkerHostTargets(t *testing.T) {
	port := startLocalTCPListener(t)
	unbound := NewTCPProber("127.0.0.1", port, time.Second, "unbound").Probe(context.Background())
	if !unbound.Passed {
		t.Fatalf("unbound probe did not reach the local listener: %s", unbound.Error)
	}
	for name, prober := range boundProbers(port, Source{Interface: "csVnAbsent", Address: "127.0.0.1"}) {
		res := prober.Probe(context.Background())
		if res.Passed || !strings.Contains(res.Error, "address of the worker host") {
			t.Errorf("%s probe to a worker address: passed=%v error=%q", name, res.Passed, res.Error)
		}
	}
}

// Nor does it fall back to the host routing table: bound to an interface
// that does not carry the listener, it fails.
func TestBoundProbesDoNotLeaveThroughOtherInterfaces(t *testing.T) {
	allowLocalTargets(t)
	port := startLocalTCPListener(t)
	source := Source{Interface: "csVnAbsent", Address: "127.0.0.1"}
	for name, prober := range boundProbers(port, source) {
		res := prober.Probe(context.Background())
		if res.Passed {
			t.Errorf("%s probe bound to %s reached a host listener", name, source.Interface)
		}
		if !strings.Contains(res.Error, source.Interface) {
			t.Errorf("%s probe error = %q, want it to name the sandbox interface", name, res.Error)
		}
	}
}

// The reproduced gap: a preprovisioned VNet carried a second host address,
// a host listener on it answered a bound probe, and the probe passed with no
// guest present. Any address on any worker interface is refused.
func TestCheckTargetNotLocalRefusesEveryWorkerAddress(t *testing.T) {
	original := localAddresses
	localAddresses = func() ([]net.Addr, error) {
		return []net.Addr{
			&net.IPNet{IP: net.ParseIP("10.70.0.1"), Mask: net.CIDRMask(24, 32)},
			&net.IPNet{IP: net.ParseIP("10.70.0.5"), Mask: net.CIDRMask(24, 32)},
		}, nil
	}
	t.Cleanup(func() { localAddresses = original })

	for _, target := range []string{"10.70.0.5", "10.70.0.1", "127.0.0.1", "::1", "0.0.0.0"} {
		if err := CheckTargetNotLocal(target); err == nil {
			t.Errorf("worker address %s accepted as a probe target", target)
		}
	}
	if err := CheckTargetNotLocal("10.70.0.11"); err != nil {
		t.Errorf("guest address rejected: %v", err)
	}
}

func startLocalTCPListener(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
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
			_ = conn.Close()
		}
	}()
	return listener.Addr().(*net.TCPAddr).Port
}
