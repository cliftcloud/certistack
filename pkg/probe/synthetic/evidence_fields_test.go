// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package synthetic

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/probe"
)

// The reported case. HTTPS probes of a named virtual host and of the
// bare address, against one server on one address, both pass and used to
// leave the same result. The result now records the identity the probe
// asserted, which is the TLS server name and Host header the server saw.
func TestHTTPResultRecordsTheAssertedVirtualHost(t *testing.T) {
	var mu sync.Mutex
	var observed []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		observed = append(observed, fmt.Sprintf("sni=%s host=%s", r.TLS.ServerName, r.Host))
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	_, portText, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	roots := server.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	probeFor := func(serverName string) probe.Result {
		p := NewHTTPProber("127.0.0.1", port, "/", true, false, http.StatusOK, 2*time.Second, "HTTPS identity", serverName)
		p.TLSRootCAs = roots
		return p.Probe(context.Background())
	}
	bare, named := probeFor(""), probeFor("example.com")
	if !bare.Passed || !named.Passed {
		t.Fatalf("results = %+v and %+v, want both passed", bare, named)
	}
	mu.Lock()
	got := append([]string(nil), observed...)
	mu.Unlock()
	if len(got) != 2 || !strings.HasPrefix(got[0], "sni= host=127.0.0.1:") || got[1] != "sni=example.com host=example.com" {
		t.Fatalf("identities the server observed = %v", got)
	}
	if bare.ServerName != "" || named.ServerName != "example.com" {
		t.Fatalf("recorded server names = %q and %q, want none and example.com", bare.ServerName, named.ServerName)
	}
	// A refusal before any request still says which identity was asserted.
	refused := NewHTTPProber("127.0.0.1", port, "/a#fragment", true, false, 200, time.Second, "bad path", "app.example.com").Probe(context.Background())
	if refused.Passed || refused.ServerName != "app.example.com" {
		t.Fatalf("refused probe = %+v, want a failure that records its server name", refused)
	}
}

// Every wire prober records its source, whether its probe passed or
// not, and a prober with no source records none.
func TestEveryWireProberRecordsItsSource(t *testing.T) {
	source := Source{Interface: "csVn01", Address: "10.100.0.1"}
	// A closed local port: the bound dial is refused (a worker address), so
	// each probe fails at once, and what the result records is its source.
	probers := map[string]interface {
		Probe(context.Context) probe.Result
	}{}
	tcp := NewTCPProber("127.0.0.1", 9, time.Second, "tcp")
	tcp.Source = source
	httpProber := NewHTTPProber("127.0.0.1", 9, "/", false, false, 200, time.Second, "http", "")
	httpProber.Source = source
	dns := NewDNSProber("127.0.0.1", 9, "", "tcp", time.Second, "dns")
	dns.Source = source
	ldap := NewLDAPProber("127.0.0.1", 9, "", time.Second, "ldap")
	ldap.Source = source
	mssql := NewMSSQLProber("127.0.0.1", 9, time.Second, "mssql")
	mssql.Source = source
	smb := NewSMBProber("127.0.0.1", 9, time.Second, "smb")
	smb.Source = source
	probers["tcp"], probers["http"], probers["dns"], probers["ldap"], probers["mssql"], probers["smb"] = tcp, httpProber, dns, ldap, mssql, smb
	for name, prober := range probers {
		result := prober.Probe(context.Background())
		if result.Passed {
			t.Errorf("%s probe to a worker address passed", name)
		}
		if result.SourceInterface != "csVn01" || result.SourceAddress != "10.100.0.1" {
			t.Errorf("%s result records source %q/%q, want csVn01/10.100.0.1", name, result.SourceInterface, result.SourceAddress)
		}
	}

	port := startLocalTCPListener(t)
	unbound := NewTCPProber("127.0.0.1", port, time.Second, "unbound").Probe(context.Background())
	if !unbound.Passed || unbound.SourceInterface != "" || unbound.SourceAddress != "" {
		t.Errorf("unbound probe = %+v, want a pass that records no source", unbound)
	}
}
