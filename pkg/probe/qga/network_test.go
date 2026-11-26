// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package qga

import (
	"strings"
	"testing"
	"time"
)

func TestNewHTTPNetworkProber_UsesSNIAndSandboxResolution(t *testing.T) {
	prober := NewHTTPNetworkProber(
		"/tmp/test.qga", "10.60.70.15", 443, "/healthz", true,
		"certistack.local", 200, 10*time.Second, "HTTPS SNI",
	)
	if !strings.Contains(prober.Command, "--resolve 'certistack.local:443:10.60.70.15'") {
		t.Fatalf("curl command does not pin SNI name to sandbox IP: %s", prober.Command)
	}
	if !strings.Contains(prober.Command, "'https://certistack.local:443/healthz'") {
		t.Fatalf("curl command does not use the SNI hostname: %s", prober.Command)
	}
	if !strings.Contains(prober.Command, "--noproxy '*'") {
		t.Fatalf("curl command may use an ambient proxy: %s", prober.Command)
	}
	if strings.Contains(prober.Command, " -k") {
		t.Fatalf("curl command disables TLS verification: %s", prober.Command)
	}
}

func TestShellQuoteEscapesSingleQuote(t *testing.T) {
	if got, want := shellQuote("a'b"), "'a'\\''b'"; got != want {
		t.Fatalf("shellQuote() = %q, want %q", got, want)
	}
}

// The in-guest network probers take an IPv6 target too. The target
// they record is bracketed, and so is the URL curl is given; the netcat
// command passes the host and the port as separate arguments.
func TestNetworkProbersBracketAnIPv6Target(t *testing.T) {
	tcp := NewTCPNetworkProber("/tmp/test.qga", "fd00:99::10", 22, 5*time.Second, "tcp")
	if tcp.Target != "[fd00:99::10]:22" {
		t.Errorf("tcp target = %q, want [fd00:99::10]:22", tcp.Target)
	}
	if !strings.Contains(tcp.Command, "nc -z -w 5 'fd00:99::10' 22") {
		t.Errorf("tcp command = %s", tcp.Command)
	}
	if v4 := NewTCPNetworkProber("/tmp/test.qga", "192.0.2.10", 22, 5*time.Second, "tcp"); v4.Target != "192.0.2.10:22" {
		t.Errorf("IPv4 tcp target = %q", v4.Target)
	}

	direct := NewHTTPNetworkProber("/tmp/test.qga", "fd00:99::10", 8080, "/health", false, "", 200, 5*time.Second, "http")
	if !strings.Contains(direct.Command, "'http://[fd00:99::10]:8080/health'") || direct.Target != "http://[fd00:99::10]:8080/health" {
		t.Errorf("IPv6 http probe: target %q, command %s", direct.Target, direct.Command)
	}
	named := NewHTTPNetworkProber("/tmp/test.qga", "fd00:99::10", 443, "/health", true, "certistack.local", 200, 5*time.Second, "https")
	if !strings.Contains(named.Command, "--resolve 'certistack.local:443:[fd00:99::10]'") || !strings.Contains(named.Command, "'https://certistack.local:443/health'") {
		t.Errorf("IPv6 https probe with a server name: %s", named.Command)
	}
	if v4 := NewHTTPNetworkProber("/tmp/test.qga", "192.0.2.30", 80, "/", false, "", 200, 5*time.Second, "http"); !strings.Contains(v4.Command, "'http://192.0.2.30:80/'") {
		t.Errorf("IPv4 http command changed: %s", v4.Command)
	}
}
