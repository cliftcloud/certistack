// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package synthetic

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// listenIPv6 returns a listener on the IPv6 loopback, or nil where the host
// has no IPv6 loopback (a container with IPv6 turned off). Tests that need a
// real peer assert on it only when there is one; the address handling they
// guard is also asserted without it.
func listenIPv6() net.Listener {
	l, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		return nil
	}
	return l
}

// Plan validation accepts an IPv6 network.ip_range and target_ip for
// every wire probe, but the tcp and ldap probers glued the host and port with
// a bare colon ("::1:37933"), which no dialer reads as an address ("too many
// colons in address"). Both now bracket an IPv6 host, as the other four wire
// probers already did, and record the bracketed form as their target.
func TestTCPProberDialsAnIPv6TargetAndRecordsItBracketed(t *testing.T) {
	l := listenIPv6()
	port := 0
	if l != nil {
		defer l.Close()
		port = l.Addr().(*net.TCPAddr).Port
		go func() {
			for {
				conn, err := l.Accept()
				if err != nil {
					return
				}
				_ = conn.Close()
			}
		}()
	} else {
		port = 49152 // nothing listens; the address must still be well formed
	}
	res := NewTCPProber("::1", port, 1500*time.Millisecond, "ipv6").Probe(context.Background())
	if want := "[::1]:" + strconv.Itoa(port); res.Target != want {
		t.Errorf("target = %q, want %q", res.Target, want)
	}
	if strings.Contains(res.Error, "too many colons") || strings.Contains(res.Error, "missing port") {
		t.Fatalf("the prober built an address no dialer can read: %q", res.Error)
	}
	if l != nil && !res.Passed {
		t.Fatalf("a listener on [::1]:%d did not pass: %+v", port, res)
	}
}

func TestLDAPProberDialsAnIPv6TargetAndRecordsItBracketed(t *testing.T) {
	l := listenIPv6()
	port := 0
	if l != nil {
		defer l.Close()
		port = l.Addr().(*net.TCPAddr).Port
		go func() {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := readLDAPMessage(conn); err != nil {
				return
			}
			_, _ = conn.Write(ldapBindSuccess)
		}()
	} else {
		port = 49153
	}
	res := NewLDAPProber("::1", port, "", 1500*time.Millisecond, "ipv6").Probe(context.Background())
	if want := "[::1]:" + strconv.Itoa(port); res.Target != want {
		t.Errorf("target = %q, want %q", res.Target, want)
	}
	if strings.Contains(res.Error, "too many colons") || strings.Contains(res.Error, "missing port") {
		t.Fatalf("the prober built an address no dialer can read: %q", res.Error)
	}
	if l != nil && !res.Passed {
		t.Fatalf("a directory on [::1]:%d did not pass: %+v", port, res)
	}
}

// IPv4 targets keep the form they always had.
func TestTCPAndLDAPProbersRecordIPv4TargetsUnchanged(t *testing.T) {
	if got := NewTCPProber("192.0.2.10", 22, time.Second, "v4").Probe(canceledContext()).Target; got != "192.0.2.10:22" {
		t.Errorf("tcp target = %q", got)
	}
	if got := NewLDAPProber("192.0.2.20", 389, "", time.Second, "v4").Probe(canceledContext()).Target; got != "192.0.2.20:389" {
		t.Errorf("ldap target = %q", got)
	}
}

func canceledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}
