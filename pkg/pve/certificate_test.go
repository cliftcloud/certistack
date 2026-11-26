// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pve

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// A stock Proxmox VE node's API certificate is signed by the cluster's own CA.
// Without CERTISTACK_PVE_CA_SOURCE the first request fails with "x509:
// certificate signed by unknown authority". That is not retried as a transient
// failure (about 28 seconds with the delays), and the message names the cause
// and the variable.
func TestCertificateProblemNamesTheCauseAndTheRemedy(t *testing.T) {
	refused := func(inner error) error {
		return &url.Error{Op: "Get", URL: "https://pve.lab.example:8006/api2/json/version", Err: &tls.CertificateVerificationError{Err: inner}}
	}
	for _, tc := range []struct {
		name string
		err  error
		want []string
	}{
		{"unknown authority", refused(x509.UnknownAuthorityError{}),
			[]string{"signed by a CA this host does not trust", "x509: certificate signed by unknown authority", "/etc/pve/pve-root-ca.pem", "CERTISTACK_PVE_CA_SOURCE",
				// The command that does it for the newcomer.
				"certistack setup pve-ca --env-file <your env file>"}},
		{"expired", refused(x509.CertificateInvalidError{Reason: x509.Expired}),
			[]string{"has expired or is not yet valid", "pvecm updatecerts", "CERTISTACK_PVE_CA_SOURCE"}},
		{"wrong host name", refused(x509.HostnameError{Host: "pve.lab.example", Certificate: &x509.Certificate{DNSNames: []string{"pve-01"}}}),
			[]string{"not issued for the host name in PVE_URL"}},
		{"another verification fault", refused(x509.CertificateInvalidError{Reason: x509.IncompatibleUsage}),
			[]string{"failed verification", "CERTISTACK_PVE_CA_SOURCE"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := certificateProblem(tc.err)
			if !ok {
				t.Fatalf("certificateProblem(%v) did not recognize a refused certificate", tc.err)
			}
			for _, want := range append(tc.want, "It was not retried") {
				if !strings.Contains(got, want) {
					t.Errorf("sentence lacks %q: %s", want, got)
				}
			}
			if strings.Contains(got, "pve.lab.example") || strings.Contains(got, "pve-01") {
				t.Errorf("the sentence names the endpoint or the certificate's names: %s", got)
			}
		})
	}
	for _, err := range []error{
		nil,
		errors.New("tls: handshake failure"),
		&net.OpError{Op: "dial", Err: errors.New("connection refused")},
		context.DeadlineExceeded,
	} {
		if got, ok := certificateProblem(err); ok {
			t.Errorf("certificateProblem(%v) = %q, want no match", err, got)
		}
	}
}

// requestCountingTLSServer is an HTTPS server and the number of connections
// made to it; a handshake the client abandons still counts.
func requestCountingTLSServer(t *testing.T, tlsConfig *tls.Config) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var connections atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"version":"9.0.0"}}`))
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	if tlsConfig != nil {
		server.TLS = tlsConfig
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server, &connections
}

func writeCertificatePEM(t *testing.T, cert *x509.Certificate) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pve-root-ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// expiredServerCertificate is a self-signed certificate for 127.0.0.1 that
// ended yesterday.
func expiredServerCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "pve-test"},
		NotBefore:             time.Now().Add(-72 * time.Hour),
		NotAfter:              time.Now().Add(-24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// The real TLS stack, against a server whose certificate this client does not
// trust, trusts but for another name, and trusts but has expired: each is
// refused once, with no retry, and the message names the cause.
func TestDoDoesNotRetryARefusedCertificate(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T) (baseURL, caFile string, connections *atomic.Int32)
		want  []string
	}{
		{"CA the host does not trust", func(t *testing.T) (string, string, *atomic.Int32) {
			server, connections := requestCountingTLSServer(t, nil)
			return server.URL, "", connections
		}, []string{"signed by a CA this host does not trust", "CERTISTACK_PVE_CA_SOURCE", "/etc/pve/pve-root-ca.pem"}},
		// The httptest certificate lists 127.0.0.1, ::1 and example.com, not localhost.
		{"trusted CA, another host name", func(t *testing.T) (string, string, *atomic.Int32) {
			server, connections := requestCountingTLSServer(t, nil)
			u, err := url.Parse(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			return "https://localhost:" + u.Port(), writeCertificatePEM(t, server.Certificate()), connections
		}, []string{"not issued for the host name in PVE_URL"}},
		{"expired certificate", func(t *testing.T) (string, string, *atomic.Int32) {
			expired := expiredServerCertificate(t)
			server, connections := requestCountingTLSServer(t, &tls.Config{Certificates: []tls.Certificate{expired}})
			leaf, err := x509.ParseCertificate(expired.Certificate[0])
			if err != nil {
				t.Fatal(err)
			}
			return server.URL, writeCertificatePEM(t, leaf), connections
		}, []string{"has expired or is not yet valid"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			baseURL, caFile, connections := tc.setup(t)
			client := NewClient(Config{BaseURL: baseURL, TLSCAFile: caFile, TokenID: "u@pve!t", TokenSecret: "s3cret-do-not-log"})
			// The delays are zero so that a retry would be fast; the number of
			// connections shows whether there was one.
			client.retryDelays = []time.Duration{0, 0, 0}
			err := client.Do(context.Background(), http.MethodGet, "version", nil, nil)
			if err == nil {
				t.Fatal("a refused certificate was accepted")
			}
			if n := connections.Load(); n != 1 {
				t.Errorf("%d connections were made, want exactly 1: a refused certificate must not be retried", n)
			}
			for _, want := range append(tc.want, "PVE HTTP request failed for GET version: ", "It was not retried") {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error lacks %q: %v", want, err)
				}
			}
			for _, leaked := range []string{"127.0.0.1", "localhost", "example.com", "s3cret-do-not-log"} {
				if strings.Contains(err.Error(), leaked) {
					t.Errorf("error holds %q: %v", leaked, err)
				}
			}
			if IsTransient(err) {
				t.Errorf("a refused certificate is reported transient: %v", err)
			}
		})
	}
}

// The classification is the one place the retry loop differs for a certificate;
// a plain dropped connection to the same server still retries.
func TestDoStillRetriesWhenTheConnectionDrops(t *testing.T) {
	server, hits := flakyServer(t, 2, 0)
	if err := retryingClient(server.URL).Do(context.Background(), http.MethodGet, "version", nil, nil); err != nil || hits.Load() != 3 {
		t.Fatalf("err = %v, hits = %d; want success on the third attempt", err, hits.Load())
	}
}
