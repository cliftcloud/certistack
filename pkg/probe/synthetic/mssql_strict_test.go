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
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/probe"
)

// strictTestCert is a self-signed certificate that names nothing the probe
// connects to (no IP address, a made-up host name): a probe that verified the
// certificate could never pass against it.
func strictTestCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "sql.invalid"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// strictTDSServer stands for SQL Server 2022 with Force Strict Encryption: a
// TLS listener, so that a cleartext PRELOGIN is not a TLS handshake and fails
// it. Every connection that completes the handshake is handed to handle.
type strictTDSServer struct {
	port        int
	failed      atomic.Int32 // connections whose TLS handshake failed
	established atomic.Int32 // connections whose TLS handshake succeeded

	mu       sync.Mutex
	alpn     []string
	requests [][]byte

	listener net.Listener
	wg       sync.WaitGroup
}

// finish stops accepting and waits for every connection's handler, so that
// what the server saw is complete when the test reads it.
func (s *strictTDSServer) finish() {
	s.listener.Close()
	s.wg.Wait()
}

func (s *strictTDSServer) negotiated() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.alpn...)
}

func (s *strictTDSServer) seenRequests() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([][]byte(nil), s.requests...)
}

func startStrictTDSServer(t *testing.T, alpn []string, mutate func(*tls.Config), handle func(s *strictTDSServer, conn *tls.Conn)) *strictTDSServer {
	t.Helper()
	cfg := &tls.Config{Certificates: []tls.Certificate{strictTestCert(t)}, NextProtos: alpn, MinVersion: tls.VersionTLS12}
	if mutate != nil {
		mutate(cfg)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &strictTDSServer{port: l.Addr().(*net.TCPAddr).Port, listener: l}
	t.Cleanup(s.finish)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			raw, err := l.Accept()
			if err != nil {
				return
			}
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				defer raw.Close()
				_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
				conn := tls.Server(raw, cfg)
				if err := conn.Handshake(); err != nil {
					s.failed.Add(1)
					return
				}
				s.established.Add(1)
				s.mu.Lock()
				s.alpn = append(s.alpn, conn.ConnectionState().NegotiatedProtocol)
				s.mu.Unlock()
				handle(s, conn)
			}()
		}
	}()
	return s
}

// answerInsideTLS reads the PRELOGIN request inside the tunnel, records it and
// writes response. With requireALPN the server does what a strict instance
// does and serves nothing to a client that did not negotiate tds/8.0.
func answerInsideTLS(response []byte, requireALPN bool) func(*strictTDSServer, *tls.Conn) {
	return func(s *strictTDSServer, conn *tls.Conn) {
		if requireALPN && conn.ConnectionState().NegotiatedProtocol != "tds/8.0" {
			return
		}
		request, err := readTDSRequest(conn)
		if err != nil {
			return
		}
		s.mu.Lock()
		s.requests = append(s.requests, request)
		s.mu.Unlock()
		_, _ = conn.Write(response)
	}
}

// serveEvery accepts connections without end and hands each, with its
// sequence number from 1, to handle. It returns the port and a counter.
func serveEvery(t *testing.T, handle func(n int, conn net.Conn)) (int, *atomic.Int32) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var wg sync.WaitGroup
	t.Cleanup(func() {
		l.Close()
		wg.Wait()
	})
	var count atomic.Int32
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			n := int(count.Add(1))
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				handle(n, conn)
			}()
		}
	}()
	return l.Addr().(*net.TCPAddr).Port, &count
}

// A server that forces TDS 8.0 strict encryption is tested, not reported as
// untestable. The probe keeps the
// cleartext PRELOGIN as its first attempt; the strict server drops it, and the
// probe retries on a fresh connection with TLS first, ALPN tds/8.0, and the
// PRELOGIN inside the tunnel. The certificate is self-signed and names
// nothing: the probe asserts that the SQL Server engine answers, not who it is.
func TestMSSQLProberTestsAServerThatForcesTDS8StrictEncryption(t *testing.T) {
	server := startStrictTDSServer(t, []string{"tds/8.0"}, nil, answerInsideTLS(tdsPreloginResponse(0x03), true))
	res := NewMSSQLProber("127.0.0.1", server.port, 3*time.Second, "SQL Server 2022 strict").Probe(context.Background())
	server.finish()
	if !res.Passed || res.Error != "" {
		t.Fatalf("strict server result = %+v", res)
	}
	for _, want := range []string{"TDS 8.0 strict", "TLS 1.3", "ALPN tds/8.0", "certificate not verified", "version 15.0.2000.0", "encryption required"} {
		if !strings.Contains(res.Detail, want) {
			t.Errorf("detail %q lacks %q", res.Detail, want)
		}
	}
	if got := server.failed.Load(); got != 1 {
		t.Errorf("%d cleartext attempts reached the server, want exactly the one first attempt", got)
	}
	if got := server.negotiated(); len(got) != 1 || got[0] != "tds/8.0" {
		t.Errorf("negotiated ALPN protocols = %q, want one tds/8.0 connection", got)
	}
	requests := server.seenRequests()
	if len(requests) != 1 {
		t.Fatalf("the server read %d PRELOGIN requests inside TLS, want 1", len(requests))
	}
	if requests[0][0] != tdsTypePrelogin || requests[0][1] != tdsStatusEOM {
		t.Fatalf("request header % x is not a single-packet PRELOGIN", requests[0][:tdsHeaderLen])
	}
	if _, _, err := parseTDSPrelogin(requests[0][tdsHeaderLen:]); err != nil {
		t.Fatalf("the PRELOGIN inside TLS does not parse: %v", err)
	}
}

// TLS 1.2 is the floor the probe accepts and says which version it got.
func TestMSSQLProberStrictPathNamesTheNegotiatedTLSVersion(t *testing.T) {
	server := startStrictTDSServer(t, []string{"tds/8.0"}, func(c *tls.Config) { c.MaxVersion = tls.VersionTLS12 }, answerInsideTLS(tdsPreloginResponse(0x00), true))
	res := NewMSSQLProber("127.0.0.1", server.port, 3*time.Second, "TLS 1.2 strict").Probe(context.Background())
	if !res.Passed || !strings.Contains(res.Detail, "TLS 1.2") || strings.Contains(res.Detail, "TLS 1.3") {
		t.Fatalf("TLS 1.2 strict server result = %+v", res)
	}
}

// A server that answers a cleartext PRELOGIN is tested in clear and never
// sees a TLS handshake.
func TestMSSQLProberDoesNotTryStrictWhenTheCleartextPreloginIsAnswered(t *testing.T) {
	port, connections := serveEvery(t, func(_ int, conn net.Conn) {
		if _, err := readTDSRequest(conn); err == nil {
			_, _ = conn.Write(tdsPreloginResponse(0x02))
		}
	})
	res := NewMSSQLProber("127.0.0.1", port, 2*time.Second, "cleartext").Probe(context.Background())
	if !res.Passed || strings.Contains(res.Detail, "strict") || !strings.Contains(res.Detail, "encryption not supported") {
		t.Fatalf("cleartext result = %+v", res)
	}
	if got := connections.Load(); got != 1 {
		t.Fatalf("%d connections, want 1: a cleartext answer is final", got)
	}
}

// Negative controls: whatever the strict attempt meets, the probe passes only
// on a PRELOGIN response read inside a TLS tunnel that negotiated tds/8.0, and
// says that both attempts failed.
func TestMSSQLProberStrictAttemptFailsClosed(t *testing.T) {
	inTunnel := func(response []byte) func(*strictTDSServer, *tls.Conn) { return answerInsideTLS(response, true) }
	for name, tc := range map[string]struct {
		alpn   []string
		handle func(*strictTDSServer, *tls.Conn)
		want   []string
		// answered is true when the server reads a PRELOGIN inside TLS.
		answered bool
	}{
		"TLS without the ALPN id, though it would answer": {nil, answerInsideTLS(tdsPreloginResponse(0x03), false), []string{"ALPN", "tds/8.0"}, false},
		"TLS with another ALPN protocol only":             {[]string{"h2"}, answerInsideTLS(tdsPreloginResponse(0x03), false), []string{"TDS 8.0 strict"}, false},
		"closes after the handshake":                      {[]string{"tds/8.0"}, func(*strictTDSServer, *tls.Conn) {}, []string{"did not answer TDS PRELOGIN"}, false},
		"answers a TDS packet that is not a PRELOGIN response": {[]string{"tds/8.0"},
			inTunnel(tdsPacket([]byte{1, 2, 3, 4, 5, 6})), []string{"malformed PRELOGIN response"}, true},
		"answers with a PRELOGIN request, packet type 0x12": {[]string{"tds/8.0"},
			inTunnel(tdsPreloginPacket()), []string{"unexpected TDS packet type 0x12"}, true},
		"answers with HTTP": {[]string{"tds/8.0"},
			inTunnel([]byte("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")), []string{"unexpected TDS packet type 0x48"}, true},
		"answers with bytes that look like a TLS alert": {[]string{"tds/8.0"},
			inTunnel([]byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x46, 0x00}), []string{"unexpected TDS packet type 0x15"}, true},
		"answers a response whose VERSION points into the option table": {[]string{"tds/8.0"},
			inTunnel(tdsPacket([]byte{tdsOptionVersion, 0, 0, 0, 6, tdsOptionTerminator})), []string{"outside the data area"}, true},
		"answers a response without a VERSION option": {[]string{"tds/8.0"},
			inTunnel(tdsPacket([]byte{tdsOptionEncryption, 0, 6, 0, 1, tdsOptionTerminator, 0})), []string{"no VERSION option"}, true},
	} {
		t.Run(name, func(t *testing.T) {
			server := startStrictTDSServer(t, tc.alpn, nil, tc.handle)
			res := NewMSSQLProber("127.0.0.1", server.port, 3*time.Second, "strict negative").Probe(context.Background())
			server.finish()
			if res.Passed {
				t.Fatalf("result = %+v", res)
			}
			for _, want := range tc.want {
				if !strings.Contains(res.Error, want) {
					t.Errorf("error %q lacks %q", res.Error, want)
				}
			}
			if !strings.Contains(res.Error, "cleartext") || !strings.Contains(res.Error, "TDS 8.0 strict") {
				t.Errorf("error %q does not name both the cleartext and the strict attempt", res.Error)
			}
			if got := len(server.seenRequests()); (got == 1) != tc.answered {
				t.Errorf("the server read %d PRELOGIN requests inside TLS, want one only when answered is %v", got, tc.answered)
			}
		})
	}
}

// The strict attempt is made once, on a fresh connection: a server that drops
// every connection is two connections and one failure that says so.
func TestMSSQLProberRetriesAsStrictExactlyOnce(t *testing.T) {
	port, connections := serveEvery(t, func(_ int, conn net.Conn) {})
	res := NewMSSQLProber("127.0.0.1", port, 3*time.Second, "drops everything").Probe(context.Background())
	if res.Passed || !strings.Contains(res.Error, "cleartext") || !strings.Contains(res.Error, "TDS 8.0 strict") {
		t.Fatalf("result = %+v", res)
	}
	if got := connections.Load(); got != 2 {
		t.Fatalf("%d connections, want the cleartext attempt and one strict retry", got)
	}
}

// A plain-TCP server that never answers is no strict-encryption signature: the
// probe fails at its own timeout on the one connection, without a retry, and
// under the absolute budget a caller sets with the context.
func TestMSSQLProberSilentServerIsBoundedAndNotRetriedAsStrict(t *testing.T) {
	port, connections := serveEvery(t, func(_ int, conn net.Conn) {
		buf := make([]byte, 4096)
		for {
			if _, err := conn.Read(buf); err != nil {
				return
			}
		}
	})
	started := time.Now()
	res := NewMSSQLProber("127.0.0.1", port, 400*time.Millisecond, "silent").Probe(context.Background())
	if took := time.Since(started); took > 3*time.Second {
		t.Errorf("a silent server took %v with a 400ms timeout", took)
	}
	if res.Passed || !strings.Contains(res.Error, "did not answer TDS PRELOGIN") || strings.Contains(res.Error, "strict") {
		t.Fatalf("silent server result = %+v", res)
	}
	if got := connections.Load(); got != 1 {
		t.Fatalf("%d connections to a silent server, want 1", got)
	}

	// The caller's budget wins over a longer probe timeout.
	budget, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	started = time.Now()
	res = NewMSSQLProber("127.0.0.1", port, 30*time.Second, "silent under a budget").Probe(budget)
	if took := time.Since(started); took > 3*time.Second || res.Passed {
		t.Fatalf("a silent server under a 300ms budget took %v: %+v", took, res)
	}
}

// A server that goes silent inside TLS is also bounded by the budget: the
// strict attempt is a probe attempt like any other.
func TestMSSQLProberSilentStrictServerIsBounded(t *testing.T) {
	server := startStrictTDSServer(t, []string{"tds/8.0"}, nil, func(s *strictTDSServer, conn *tls.Conn) {
		if _, err := readTDSRequest(conn); err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, conn) // read the PRELOGIN, answer nothing, stay open
	})
	started := time.Now()
	res := NewMSSQLProber("127.0.0.1", server.port, 500*time.Millisecond, "silent strict").Probe(context.Background())
	if took := time.Since(started); took > 2500*time.Millisecond {
		t.Errorf("a silent strict server took %v with a 500ms timeout", took)
	}
	if res.Passed || !strings.Contains(res.Error, "TDS 8.0 strict") {
		t.Fatalf("silent strict server result = %+v", res)
	}
}

// The strict attempt ends at once when the probe is canceled and never passes
// on an answer released afterwards, like the cleartext one.
func TestMSSQLProberStrictAttemptEndsAtOnceWhenCanceled(t *testing.T) {
	seen, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	server := startStrictTDSServer(t, []string{"tds/8.0"}, nil, func(s *strictTDSServer, conn *tls.Conn) {
		if _, err := readTDSRequest(conn); err != nil {
			return
		}
		once.Do(func() { close(seen) })
		<-release
		_, _ = conn.Write(tdsPreloginResponse(0x03))
	})
	res, took := cancelWhileWaiting(t, seen, release, func(ctx context.Context) probe.Result {
		return NewMSSQLProber("127.0.0.1", server.port, 30*time.Second, "mssql strict").Probe(ctx)
	})
	if res.Passed || !strings.Contains(res.Error, "interrupted") || took > 2*time.Second {
		t.Fatalf("result = %+v after %v", res, took)
	}
}
