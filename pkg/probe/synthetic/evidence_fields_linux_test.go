//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package synthetic

import (
	"context"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/probe"
)

// This file is Linux-only on purpose. A wire probe binds its socket to the
// sandbox VNet interface (SO_BINDTODEVICE), which is a Linux facility, and the
// product refuses to probe from another system with "binding a probe to sandbox
// interface lo requires Linux": the node worker that runs the probes is
// Linux-only. The test below proves that two sources are told apart by the peer
// address the listener sees, which needs the real bind; on Windows it failed on
// the base for exactly that reason, which is the product's refusal and not a
// defect. What does not need the bind, that every prober records its source, is
// TestEveryWireProberRecordsItsSource and runs everywhere.

// The reported case. Wire probes bound to two different source
// addresses reached the same listener from two peers, and both left the same
// result. A result now records the sandbox interface and host address its
// probe was bound to.
func TestWireResultRecordsTheSourceItWasBoundTo(t *testing.T) {
	allowLocalTargets(t)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var mu sync.Mutex
	var peers []string
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			peers = append(peers, conn.RemoteAddr().(*net.TCPAddr).IP.String())
			mu.Unlock()
			_ = conn.Close()
		}
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	probeFrom := func(address string) probe.Result {
		p := NewTCPProber("127.0.0.1", port, 2*time.Second, "bound TCP identity")
		p.Source = Source{Interface: "lo", Address: address}
		return p.Probe(context.Background())
	}
	two, three := probeFrom("127.0.0.2"), probeFrom("127.0.0.3")
	if !two.Passed || !three.Passed {
		if strings.Contains(two.Error+three.Error, "bind probe socket") {
			t.Skipf("this environment does not let the test bind a socket to lo: %s %s", two.Error, three.Error)
		}
		t.Fatalf("results = %+v and %+v, want both passed", two, three)
	}
	// The listener records a peer after the probe has returned, so wait for it.
	var seen []string
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		mu.Lock()
		seen = append([]string(nil), peers...)
		mu.Unlock()
		if len(seen) >= 2 {
			break
		}
	}
	if !reflect.DeepEqual(seen, []string{"127.0.0.2", "127.0.0.3"}) {
		t.Fatalf("peers the listener saw = %v", seen)
	}
	if two.SourceInterface != "lo" || two.SourceAddress != "127.0.0.2" || three.SourceAddress != "127.0.0.3" {
		t.Fatalf("recorded sources = %s/%s and %s/%s", two.SourceInterface, two.SourceAddress, three.SourceInterface, three.SourceAddress)
	}
}
