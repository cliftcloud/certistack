// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package synthetic

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// sqlServerName is the name the test server's certificate carries.
const sqlServerName = "sql.example.test"

// testCA is a certificate authority that signs the certificates of the
// server_name tests.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "CertiStack test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{cert: cert, key: key}
}

func (ca *testCA) pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	return pool
}

// issue is a server certificate for the given DNS names, signed by the CA.
func (ca *testCA) issue(t *testing.T, names ...string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// verifiedTDSServer is a TDS 8.0 strict server whose certificate the test CA
// signed for sqlServerName. It records the SNI of every ClientHello.
func verifiedTDSServer(t *testing.T, ca *testCA, alpn []string) (*strictTDSServer, func() []string) {
	t.Helper()
	cert := ca.issue(t, sqlServerName)
	var mu sync.Mutex
	var seen []string
	server := startStrictTDSServer(t, alpn, func(c *tls.Config) {
		c.Certificates = nil
		c.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			mu.Lock()
			seen = append(seen, hello.ServerName)
			mu.Unlock()
			return &cert, nil
		}
	}, answerInsideTLS(tdsPreloginResponse(0x03), true))
	return server, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), seen...)
	}
}

func verifiedProber(port int, serverName string, roots *x509.CertPool) *MSSQLProber {
	prober := NewMSSQLProber("127.0.0.1", port, 3*time.Second, "SQL Server 2022 strict, verified")
	prober.ServerName = serverName
	prober.TLSRootCAs = roots
	return prober
}

// A probe with a server_name verifies the TDS 8.0 strict handshake: the
// certificate chains to the roots and names server_name, which is also the SNI.
func TestMSSQLProberWithAServerNameVerifiesTheCertificate(t *testing.T) {
	ca := newTestCA(t)
	server, sni := verifiedTDSServer(t, ca, []string{"tds/8.0"})
	res := verifiedProber(server.port, sqlServerName, ca.pool()).Probe(context.Background())
	server.finish()
	if !res.Passed || res.Error != "" {
		t.Fatalf("result = %+v", res)
	}
	for _, want := range []string{"TDS 8.0 strict", "ALPN tds/8.0", "certificate verified for " + sqlServerName, "version 15.0.2000.0", "encryption required"} {
		if !strings.Contains(res.Detail, want) {
			t.Errorf("detail %q lacks %q", res.Detail, want)
		}
	}
	if strings.Contains(res.Detail, "not verified") {
		t.Errorf("a verified pass says %q", res.Detail)
	}
	if res.ServerName != sqlServerName || res.Type != "mssql" || res.Target != net.JoinHostPort("127.0.0.1", strconv.Itoa(server.port)) {
		t.Errorf("result records type %q, target %q, server name %q", res.Type, res.Target, res.ServerName)
	}
	if got := sni(); len(got) != 1 || got[0] != sqlServerName {
		t.Errorf("the server saw SNI %q, want one ClientHello with %q", got, sqlServerName)
	}
	if got := server.failed.Load(); got != 0 {
		t.Errorf("%d cleartext attempts reached the server: a probe with a server_name makes only the strict one", got)
	}
	if got := server.negotiated(); len(got) != 1 || got[0] != "tds/8.0" {
		t.Errorf("negotiated ALPN protocols = %q, want one tds/8.0 connection", got)
	}
	if got := len(server.seenRequests()); got != 1 {
		t.Errorf("the server read %d PRELOGIN requests inside TLS, want 1", got)
	}
}

// Negative controls: whatever is wrong with the identity, the probe fails
// before any PRELOGIN is sent, names server_name, and records it.
func TestMSSQLProberWithAServerNameFailsWhenTheIdentityIsNotShown(t *testing.T) {
	ca, other := newTestCA(t), newTestCA(t)
	for name, tc := range map[string]struct {
		serverName string
		roots      *x509.CertPool
		want       string
	}{
		"a certificate for another name":               {"other.example.test", ca.pool(), "certificate is valid for " + sqlServerName},
		"a certificate from an untrusted root":         {sqlServerName, other.pool(), "unknown authority"},
		"the node's own trust store, no test CA":       {sqlServerName, nil, "unknown authority"},
		"an IP address the certificate does not carry": {"127.0.0.1", ca.pool(), "IP SANs"},
	} {
		t.Run(name, func(t *testing.T) {
			server, _ := verifiedTDSServer(t, ca, []string{"tds/8.0"})
			res := verifiedProber(server.port, tc.serverName, tc.roots).Probe(context.Background())
			server.finish()
			if res.Passed {
				t.Fatalf("result = %+v", res)
			}
			for _, want := range []string{`server_name "` + tc.serverName + `"`, "verified TDS 8.0 strict handshake", "did not verify", "x509", tc.want} {
				if !strings.Contains(res.Error, want) {
					t.Errorf("error %q lacks %q", res.Error, want)
				}
			}
			if res.ServerName != tc.serverName {
				t.Errorf("the failed result records server name %q, want %q", res.ServerName, tc.serverName)
			}
			if got := len(server.seenRequests()); got != 0 {
				t.Errorf("the server read %d PRELOGIN requests: nothing may be sent to a server whose identity did not verify", got)
			}
		})
	}
}

// A cleartext PRELOGIN answer shows no certificate, so it does not satisfy a
// probe with a server_name. The probe makes no cleartext attempt, and a server
// that would answer a cleartext PRELOGIN, or answers one to anything it reads,
// fails it.
func TestMSSQLProberWithAServerNameIsNotSatisfiedByCleartext(t *testing.T) {
	ca := newTestCA(t)
	for name, answersAnything := range map[string]bool{
		"answers a cleartext PRELOGIN only":         false,
		"answers a cleartext PRELOGIN to any bytes": true,
	} {
		t.Run(name, func(t *testing.T) {
			var mu sync.Mutex
			var first []byte
			port, connections := serveEvery(t, func(_ int, conn net.Conn) {
				var b [1]byte
				if _, err := conn.Read(b[:]); err != nil {
					return
				}
				mu.Lock()
				first = append(first, b[0])
				mu.Unlock()
				if answersAnything || b[0] == tdsTypePrelogin {
					_, _ = conn.Write(tdsPreloginResponse(0x02))
				}
			})
			res := verifiedProber(port, sqlServerName, ca.pool()).Probe(context.Background())
			if res.Passed {
				t.Fatalf("a cleartext answer passed a probe with a server_name: %+v", res)
			}
			for _, want := range []string{`server_name "` + sqlServerName + `"`, "verified TDS 8.0 strict handshake", "did not offer it"} {
				if !strings.Contains(res.Error, want) {
					t.Errorf("error %q lacks %q", res.Error, want)
				}
			}
			if res.ServerName != sqlServerName {
				t.Errorf("the failed result records server name %q", res.ServerName)
			}
			if got := connections.Load(); got != 1 {
				t.Errorf("%d connections, want the one strict attempt and no cleartext one", got)
			}
			mu.Lock()
			defer mu.Unlock()
			if len(first) != 1 || first[0] != 0x16 {
				t.Errorf("the server's first bytes were % x, want one TLS handshake record (0x16) and no TDS PRELOGIN (0x12)", first)
			}
		})
	}
}

// With a verified identity the rest of the strict rules still apply, and a
// failure after the handshake is not blamed on the certificate.
func TestMSSQLProberWithAServerNameKeepsTheStrictRules(t *testing.T) {
	ca := newTestCA(t)

	t.Run("a TLS server that does not select tds/8.0", func(t *testing.T) {
		server, _ := verifiedTDSServer(t, ca, nil)
		res := verifiedProber(server.port, sqlServerName, ca.pool()).Probe(context.Background())
		server.finish()
		if res.Passed || !strings.Contains(res.Error, "did not select ALPN protocol tds/8.0") || !strings.Contains(res.Error, "verified TDS 8.0 strict handshake") {
			t.Fatalf("result = %+v", res)
		}
		if got := len(server.seenRequests()); got != 0 {
			t.Errorf("the server read %d PRELOGIN requests", got)
		}
	})

	t.Run("a verified server that answers no PRELOGIN", func(t *testing.T) {
		cert := ca.issue(t, sqlServerName)
		server := startStrictTDSServer(t, []string{"tds/8.0"}, func(c *tls.Config) { c.Certificates = []tls.Certificate{cert} },
			answerInsideTLS(tdsPacket([]byte{1, 2, 3, 4, 5, 6}), true))
		res := verifiedProber(server.port, sqlServerName, ca.pool()).Probe(context.Background())
		server.finish()
		if res.Passed || !strings.Contains(res.Error, "malformed PRELOGIN response inside TLS") || strings.Contains(res.Error, "did not verify") {
			t.Fatalf("result = %+v", res)
		}
	})
}

// A probe without a server_name is the probe that has always run: the
// cleartext attempt first, the strict retry, the certificate unchecked,
// whoever signed it and whatever it names, and no server name recorded.
func TestMSSQLProberWithoutAServerNameDoesNotVerifyTheCertificate(t *testing.T) {
	ca := newTestCA(t)
	server, sni := verifiedTDSServer(t, ca, []string{"tds/8.0"})
	// The roots are the wrong ones: they are not read without a server_name.
	res := verifiedProber(server.port, "", newTestCA(t).pool()).Probe(context.Background())
	server.finish()
	if !res.Passed || res.Error != "" {
		t.Fatalf("result = %+v", res)
	}
	for _, want := range []string{"TDS 8.0 strict", "certificate not verified"} {
		if !strings.Contains(res.Detail, want) {
			t.Errorf("detail %q lacks %q", res.Detail, want)
		}
	}
	if strings.Contains(res.Detail, "certificate verified") {
		t.Errorf("detail %q claims a verified certificate", res.Detail)
	}
	if res.ServerName != "" {
		t.Errorf("result records server name %q, want none", res.ServerName)
	}
	if got := server.failed.Load(); got != 1 {
		t.Errorf("%d cleartext attempts reached the server, want exactly the one first attempt", got)
	}
	if got := sni(); len(got) != 1 || got[0] != "" {
		t.Errorf("the server saw SNI %q, want one ClientHello with none (the target is an address)", got)
	}
}
