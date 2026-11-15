// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package synthetic

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestTCPProber_Success(t *testing.T) {
	// Start a local TCP listener
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().(*net.TCPAddr)
	prober := NewTCPProber("127.0.0.1", addr.Port, 2*time.Second, "test local listener")

	ctx := context.Background()
	res := prober.Probe(ctx)

	if !res.Passed {
		t.Fatalf("expected TCP probe to pass, got error: %s", res.Error)
	}
	if res.Type != "tcp" {
		t.Errorf("expected type 'tcp', got %s", res.Type)
	}
	if !strings.Contains(res.Detail, "Service readiness time") {
		t.Errorf("expected Detail to contain 'Service readiness time', got %s", res.Detail)
	}
}

func TestTCPProber_Failure(t *testing.T) {
	// Probe a closed port
	prober := NewTCPProber("127.0.0.1", 59999, 200*time.Millisecond, "test closed port")

	ctx := context.Background()
	res := prober.Probe(ctx)

	if res.Passed {
		t.Fatal("expected TCP probe to fail against closed port")
	}
}

// The fault case: a stopped listener refused every attempt, but the
// report said "context deadline exceeded" because the deadline ended the
// polling and replaced the refusal.
func TestTCPProber_KeepsRefusalWhenDeadlineEndsPolling(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 4500*time.Millisecond)
	defer cancel()
	res := NewTCPProber("127.0.0.1", port, 60*time.Second, "stopped listener").Probe(ctx)
	if res.Passed || !strings.Contains(res.Error, "refused") {
		t.Fatalf("error = %q, want the refusal, not only the deadline", res.Error)
	}
}

func TestHTTPProber_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("healthy"))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Extract port from server URL
	_, portStr, _ := net.SplitHostPort(server.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	prober := NewHTTPProber("127.0.0.1", port, "/health", false, false, 200, 2*time.Second, "health check", "")

	ctx := context.Background()
	res := prober.Probe(ctx)

	if !res.Passed {
		t.Fatalf("expected HTTP probe to pass, got error: %s", res.Error)
	}
}

// The mesh case: /readyz answered 503 on every attempt, but the report
// said "context deadline exceeded" because the deadline expired between
// attempts and overwrote the answer.
func TestHTTPProber_KeepsAnswerWhenDeadlineEndsPolling(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"ready": false}`))
	}))
	defer server.Close()
	_, portStr, _ := net.SplitHostPort(server.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	res := NewHTTPProber("127.0.0.1", port, "/readyz", false, false, 200, 60*time.Second, "mesh readyz", "").Probe(ctx)
	if res.Passed || !strings.Contains(res.Error, "got 503 Service Unavailable") {
		t.Fatalf("error = %q, want the 503 answer, not only the deadline", res.Error)
	}
	// The error is signed into a retained report; the target's response body
	// (a stack trace or application data on a failing endpoint) must not be.
	if strings.Contains(res.Error, "ready") {
		t.Fatalf("error = %q, recorded the response body", res.Error)
	}
}

func TestHTTPProber_StatusMismatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal error"))
	}))
	defer server.Close()

	_, portStr, _ := net.SplitHostPort(server.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	prober := NewHTTPProber("127.0.0.1", port, "/health", false, false, 200, 2*time.Second, "health check", "")

	ctx := context.Background()
	res := prober.Probe(ctx)

	if res.Passed {
		t.Fatal("expected HTTP probe to fail on status 500")
	}
}

func TestHTTPProber_RejectsRedirectWithoutFollowingIt(t *testing.T) {
	var finalHits int
	var cancel context.CancelFunc
	redirectURL := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redirect":
			w.Header().Set("Location", redirectURL+"/final")
			w.WriteHeader(http.StatusFound)
			cancel()
		case "/final":
			finalHits++
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()
	redirectURL = server.URL

	_, portText, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancelContext := context.WithCancel(context.Background())
	cancel = cancelContext
	defer cancelContext()
	prober := NewHTTPProber("127.0.0.1", port, "/redirect", false, false, http.StatusOK, time.Second, "redirect check", "")
	result := prober.Probe(ctx)
	if result.Passed {
		t.Fatal("HTTP prober accepted a redirect as a successful response")
	}
	if finalHits != 0 {
		t.Fatalf("redirect target received %d requests, want none", finalHits)
	}
}

func TestHTTPProber_AcceptsExpectedRedirectStatusWithoutFollowingIt(t *testing.T) {
	var finalHits int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redirect":
			w.Header().Set("Location", "/final")
			w.WriteHeader(http.StatusFound)
		case "/final":
			finalHits++
			w.WriteHeader(http.StatusOK)
		}
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
	// A plan may deliberately expect a redirect-serving endpoint (e.g. an
	// http-to-https or path-canonicalization redirect) to keep returning
	// exactly that status; the prober must accept it without ever following
	// the redirect itself.
	prober := NewHTTPProber("127.0.0.1", port, "/redirect", false, false, http.StatusFound, time.Second, "expected redirect", "")
	result := prober.Probe(context.Background())
	if !result.Passed {
		t.Fatalf("HTTP prober rejected an explicitly expected redirect status: %#v", result)
	}
	if finalHits != 0 {
		t.Fatalf("redirect target received %d requests, want none", finalHits)
	}
}

func TestHTTPProber_TLSUsesConfiguredServerNameAndHost(t *testing.T) {
	const serverName = "example.com"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || r.TLS.ServerName != serverName {
			t.Errorf("TLS SNI = %q, want %q", r.TLS.ServerName, serverName)
			w.WriteHeader(http.StatusMisdirectedRequest)
			return
		}
		if r.Host != serverName {
			t.Errorf("Host = %q, want %q", r.Host, serverName)
			w.WriteHeader(http.StatusMisdirectedRequest)
			return
		}
		if r.URL.Path != "/healthz" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	_, portStr, _ := net.SplitHostPort(server.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)
	prober := NewHTTPProber("127.0.0.1", port, "/healthz", true, true, http.StatusOK, 2*time.Second, "SNI health check", serverName)
	prober.TLSRootCAs = server.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs

	res := prober.Probe(context.Background())
	if !res.Passed {
		t.Fatalf("expected HTTPS SNI probe to pass, got error: %s", res.Error)
	}
}

func TestHTTPProber_LegacyInsecureFlagDoesNotBypassTLS(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	// The exported constructor retains this legacy argument only so existing
	// callers compile. With no trusted root configured, it must not turn an
	// httptest self-signed certificate into a passing recovery assertion.
	prober := NewHTTPProber("127.0.0.1", port, "/healthz", true, true, http.StatusOK, 250*time.Millisecond, "legacy TLS flag", "example.com")
	res := prober.Probe(context.Background())
	if res.Passed {
		t.Fatal("legacy insecure flag bypassed TLS certificate verification")
	}
}

func TestLDAPProber_Success(t *testing.T) {
	// Start mock LDAP server returning a valid ASN.1 BindResponse with resultCode 0
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer l.Close()

	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		req := make([]byte, 128)
		_, _ = conn.Read(req)

		// Send RFC 4511 BindResponse: 30 0c 02 01 01 61 07 0a 01 00 04 00 04 00
		resp := []byte{
			0x30, 0x0c, // SEQUENCE, len 12
			0x02, 0x01, 0x01, // INTEGER 1 (MessageID)
			0x61, 0x07, // BindResponse [APPLICATION 1], len 7
			0x0a, 0x01, 0x00, // ENUMERATED 0 (resultCode: success)
			0x04, 0x00, // matchedDN ""
			0x04, 0x00, // diagnosticMessage ""
		}
		_, _ = conn.Write(resp)
	}()

	addr := l.Addr().(*net.TCPAddr)
	prober := NewLDAPProber("127.0.0.1", addr.Port, "", 2*time.Second, "test ldap")
	res := prober.Probe(context.Background())

	if !res.Passed {
		t.Fatalf("expected LDAP probe to pass, got error: %s", res.Error)
	}
	if res.Type != "ldap" {
		t.Errorf("expected type 'ldap', got %s", res.Type)
	}
}

func TestLDAPProber_ClosedPort(t *testing.T) {
	prober := NewLDAPProber("127.0.0.1", 59998, "", 200*time.Millisecond, "closed ldap port")
	res := prober.Probe(context.Background())
	if res.Passed {
		t.Fatal("expected LDAP probe to fail on closed port")
	}
}

func TestLDAPResultDescription_ExplainsMissingBaseObject(t *testing.T) {
	got := ldapResultDescription(32)
	if !strings.Contains(got, "noSuchObject") || !strings.Contains(got, "absent from this recovered snapshot") || !strings.Contains(got, "resultCode 32") {
		t.Fatalf("missing-object LDAP message = %q", got)
	}
}

func TestLDAPBindResultCodeRejectsWrongOperationAndMessageID(t *testing.T) {
	// A response body can contain the same byte values as a BindResponse. The
	// parser must require the actual protocol-operation tag and message ID.
	wrongOperation := ldapTLV(0x30, append(ldapTLV(0x02, []byte{1}), ldapTLV(0x78, []byte{0x61, 0x0a, 0x01, 0x00})...))
	if _, err := ldapBindResultCode(wrongOperation, 1); err == nil || !strings.Contains(err.Error(), "BindResponse tag") {
		t.Fatalf("wrong operation error = %v, want BindResponse-tag rejection", err)
	}
	if _, err := ldapBindResultCode(ldapTLV(0x30, append(ldapTLV(0x02, []byte{2}), ldapTLV(0x61, append(ldapTLV(0x0a, []byte{0}), ldapTLV(0x04, nil)...))...)), 1); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("wrong message ID error = %v, want message-ID rejection", err)
	}
}

func TestLDAPProber_AutoDiscoveryUsesOneProbeDeadline(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()

	serverDone := make(chan error, 1)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		if _, err := readLDAPMessage(conn); err != nil {
			serverDone <- fmt.Errorf("read bind: %w", err)
			return
		}
		_, _ = conn.Write([]byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00})
		if _, err := readLDAPMessage(conn); err != nil {
			serverDone <- fmt.Errorf("read Root DSE search: %w", err)
			return
		}
		_, _ = conn.Write(ldapRootDSEEntryPacket(3,
			"dc=one,dc=test", "dc=two,dc=test", "dc=three,dc=test", "dc=four,dc=test"))
		_, _ = conn.Write(ldapSearchResultDonePacket(3, 0))
		// Receive the first search but deliberately never respond. The client
		// must use its one absolute probe deadline, rather than a full timeout
		// for every advertised naming context.
		if _, err := readLDAPMessage(conn); err != nil {
			serverDone <- fmt.Errorf("read discovered base-object search: %w", err)
			return
		}
		serverDone <- nil
	}()

	addr := l.Addr().(*net.TCPAddr)
	started := time.Now()
	res := NewLDAPProber("127.0.0.1", addr.Port, "auto", 250*time.Millisecond, "LDAP deadline check").Probe(context.Background())
	if res.Passed {
		t.Fatalf("nonresponsive discovered base search unexpectedly passed: %+v", res)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("automatic LDAP discovery ignored the single probe deadline: %v", elapsed)
	}
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatalf("LDAP test server: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("LDAP test server did not receive the first discovered search")
	}
}

func TestLDAPProber_BaseObjectSearch(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()

	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		if _, err := readLDAPMessage(conn); err != nil {
			t.Errorf("read bind: %v", err)
			return
		}
		// LDAP BindResponse success, message ID 1.
		_, _ = conn.Write([]byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00})

		search, err := readLDAPMessage(conn)
		if err != nil {
			t.Errorf("read search: %v", err)
			return
		}
		if !strings.Contains(string(search), "dc=certistack,dc=test") {
			t.Errorf("base DN missing from search request: %x", search)
			return
		}
		// The entry, as OpenLDAP returns it to an anonymous reader, then
		// SearchResultDone success, message ID 2.
		_, _ = conn.Write(ldapObjectEntryPacket(2, "dc=certistack,dc=test", openLDAPBaseAttributes...))
		_, _ = conn.Write([]byte{0x30, 0x0c, 0x02, 0x01, 0x02, 0x65, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00})
	}()

	addr := l.Addr().(*net.TCPAddr)
	prober := NewLDAPProber("127.0.0.1", addr.Port, "dc=certistack,dc=test", 2*time.Second, "LDAP base search")
	res := prober.Probe(context.Background())
	if !res.Passed {
		t.Fatalf("expected LDAP base search to pass, got error: %s", res.Error)
	}
	if !strings.Contains(res.Detail, "base-object search") {
		t.Fatalf("expected base-search detail, got %q", res.Detail)
	}
}

func TestLDAPProber_MissingBaseDNReportsRootDSENamingContexts(t *testing.T) {
	rootDSEEntry := ldapRootDSEEntryPacket(3, "dc=example,dc=test", "dc=secondary,dc=test")
	_, operation, err := ldapMessageEnvelope(rootDSEEntry)
	if err != nil {
		t.Fatalf("Root DSE entry envelope: %v", err)
	}
	if entry, err := parseLDAPSearchEntry(operation); err != nil || entry.dn != "" || !reflect.DeepEqual(entry.attributes["namingcontexts"], []string{"dc=example,dc=test", "dc=secondary,dc=test"}) {
		t.Fatalf("Root DSE entry parsed as %+v, %v", entry, err)
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()

	serverDone := make(chan error, 1)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()

		if _, err := readLDAPMessage(conn); err != nil {
			serverDone <- fmt.Errorf("read bind: %w", err)
			return
		}
		_, _ = conn.Write([]byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00})

		if _, err := readLDAPMessage(conn); err != nil {
			serverDone <- fmt.Errorf("read base-object search: %w", err)
			return
		}
		_, _ = conn.Write(ldapSearchResultDonePacket(2, 32))

		rootDSE, err := readLDAPMessage(conn)
		if err != nil {
			serverDone <- fmt.Errorf("read Root DSE search: %w", err)
			return
		}
		if !strings.Contains(string(rootDSE), "namingContexts") {
			serverDone <- fmt.Errorf("Root DSE request did not ask for namingContexts: %x", rootDSE)
			return
		}
		_, _ = conn.Write(rootDSEEntry)
		_, _ = conn.Write(ldapSearchResultDonePacket(3, 0))
		serverDone <- nil
	}()

	addr := l.Addr().(*net.TCPAddr)
	res := NewLDAPProber("127.0.0.1", addr.Port, "dc=missing,dc=test", 2*time.Second, "LDAP base search").Probe(context.Background())
	if res.Passed {
		t.Fatalf("missing configured base DN unexpectedly passed: %+v", res)
	}
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatalf("LDAP test server: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("LDAP test server did not complete Root DSE exchange")
	}
	for _, expected := range []string{"noSuchObject", "dc=example,dc=test", "dc=secondary,dc=test"} {
		if !strings.Contains(res.Error, expected) {
			t.Fatalf("missing diagnostic %q in %q", expected, res.Error)
		}
	}
}

func TestLDAPProber_AutoBaseDNVerifiesAdvertisedNamingContext(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()

	serverDone := make(chan error, 1)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()

		if _, err := readLDAPMessage(conn); err != nil {
			serverDone <- fmt.Errorf("read bind: %w", err)
			return
		}
		_, _ = conn.Write([]byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00})

		rootDSE, err := readLDAPMessage(conn)
		if err != nil {
			serverDone <- fmt.Errorf("read Root DSE search: %w", err)
			return
		}
		if !strings.Contains(string(rootDSE), "namingContexts") {
			serverDone <- fmt.Errorf("Root DSE request did not ask for namingContexts: %x", rootDSE)
			return
		}
		_, _ = conn.Write(ldapRootDSEEntryPacket(3, "dc=example,dc=test", "dc=secondary,dc=test"))
		_, _ = conn.Write(ldapSearchResultDonePacket(3, 0))

		search, err := readLDAPMessage(conn)
		if err != nil {
			serverDone <- fmt.Errorf("read discovered base-object search: %w", err)
			return
		}
		if !strings.Contains(string(search), "dc=example,dc=test") {
			serverDone <- fmt.Errorf("discovered naming context missing from search request: %x", search)
			return
		}
		_, _ = conn.Write(ldapObjectEntryPacket(4, "dc=example,dc=test", openLDAPBaseAttributes...))
		_, _ = conn.Write(ldapSearchResultDonePacket(4, 0))
		serverDone <- nil
	}()

	addr := l.Addr().(*net.TCPAddr)
	res := NewLDAPProber("127.0.0.1", addr.Port, "auto", 2*time.Second, "LDAP portable directory check").Probe(context.Background())
	if !res.Passed {
		t.Fatalf("expected automatic LDAP base discovery to pass, got: %s", res.Error)
	}
	if !strings.Contains(res.Detail, "discovered base-object search dc=example,dc=test") {
		t.Fatalf("automatic LDAP detail = %q", res.Detail)
	}
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatalf("LDAP test server: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("LDAP test server did not complete automatic discovery exchange")
	}
}

func TestLDAPProber_AutoBaseDNTriesLaterNamingContext(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()

	serverDone := make(chan error, 1)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		if _, err := readLDAPMessage(conn); err != nil {
			serverDone <- fmt.Errorf("read bind: %w", err)
			return
		}
		_, _ = conn.Write([]byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00})
		if _, err := readLDAPMessage(conn); err != nil {
			serverDone <- fmt.Errorf("read Root DSE search: %w", err)
			return
		}
		_, _ = conn.Write(ldapRootDSEEntryPacket(3, "dc=unreadable,dc=test", "dc=readable,dc=test"))
		_, _ = conn.Write(ldapSearchResultDonePacket(3, 0))

		firstSearch, err := readLDAPMessage(conn)
		if err != nil {
			serverDone <- fmt.Errorf("read first discovered search: %w", err)
			return
		}
		if !strings.Contains(string(firstSearch), "dc=unreadable,dc=test") {
			serverDone <- fmt.Errorf("first naming context was not tried: %x", firstSearch)
			return
		}
		_, _ = conn.Write(ldapSearchResultDonePacket(4, 32))

		secondSearch, err := readLDAPMessage(conn)
		if err != nil {
			serverDone <- fmt.Errorf("read second discovered search: %w", err)
			return
		}
		if !strings.Contains(string(secondSearch), "dc=readable,dc=test") {
			serverDone <- fmt.Errorf("second naming context was not tried: %x", secondSearch)
			return
		}
		_, _ = conn.Write(ldapObjectEntryPacket(5, "dc=readable,dc=test", openLDAPBaseAttributes...))
		_, _ = conn.Write(ldapSearchResultDonePacket(5, 0))
		serverDone <- nil
	}()

	addr := l.Addr().(*net.TCPAddr)
	res := NewLDAPProber("127.0.0.1", addr.Port, "auto", 2*time.Second, "LDAP portable directory check").Probe(context.Background())
	if !res.Passed || !strings.Contains(res.Detail, "dc=readable,dc=test") {
		t.Fatalf("automatic LDAP fallback result = %+v", res)
	}
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatalf("LDAP test server: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("LDAP test server did not complete multi-context discovery exchange")
	}
}

type ldapAttribute struct {
	name   string
	values []string
}

// ldapEntryPacket is a SearchResultEntry for the empty DN (the Root DSE).
func ldapEntryPacket(messageID int, attributes ...ldapAttribute) []byte {
	return ldapObjectEntryPacket(messageID, "", attributes...)
}

// ldapObjectEntryPacket is a SearchResultEntry for dn.
func ldapObjectEntryPacket(messageID int, dn string, attributes ...ldapAttribute) []byte {
	var encoded []byte
	for _, attribute := range attributes {
		var values []byte
		for _, value := range attribute.values {
			values = append(values, ldapTLV(0x04, []byte(value))...)
		}
		encoded = append(encoded, ldapTLV(0x30, append(ldapTLV(0x04, []byte(attribute.name)), ldapTLV(0x31, values)...))...)
	}
	entry := append(ldapTLV(0x04, []byte(dn)), ldapTLV(0x30, encoded)...)
	return ldapTLV(0x30, append(ldapIntegerTLV(0x02, messageID), ldapTLV(0x64, entry)...))
}

// openLDAPBaseAttributes are what OpenLDAP returns for a dcObject suffix
// entry to an anonymous base-object search asking for all user attributes.
var openLDAPBaseAttributes = []ldapAttribute{
	{"objectClass", []string{"top", "dcObject", "organization"}},
	{"o", []string{"CertiStack Test"}},
}

// serveRootDSE answers one anonymous bind with bindResult and, when the
// client asks, the Root DSE with rootDSE. It returns every request after
// the bind, so a test can prove which operations the probe sent.
func serveRootDSE(t *testing.T, bindResult byte, rootDSE ...ldapAttribute) (int, <-chan [][]byte) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { l.Close() })
	requests := make(chan [][]byte, 1)
	go func() {
		var seen [][]byte
		defer func() { requests <- seen }()
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := readLDAPMessage(conn); err != nil {
			return
		}
		_, _ = conn.Write([]byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, bindResult, 0x04, 0x00, 0x04, 0x00})
		for {
			request, err := readLDAPMessage(conn)
			if err != nil {
				return // the probe closed the connection
			}
			seen = append(seen, request)
			messageID, _, _ := ldapMessageEnvelope(request)
			if len(rootDSE) > 0 {
				_, _ = conn.Write(ldapEntryPacket(messageID, rootDSE...))
			}
			_, _ = conn.Write(ldapSearchResultDonePacket(messageID, 0))
		}
	}()
	return l.Addr().(*net.TCPAddr).Port, requests
}

// activeDirectoryRootDSE is what a Windows DC returns to an anonymous client.
var activeDirectoryRootDSE = []ldapAttribute{
	{"namingContexts", []string{"DC=certistack,DC=test", "CN=Configuration,DC=certistack,DC=test", "CN=Schema,CN=Configuration,DC=certistack,DC=test", "DC=DomainDnsZones,DC=certistack,DC=test"}},
	{"defaultNamingContext", []string{"DC=certistack,DC=test"}},
	{"dnsHostName", []string{"CS-W16-DC.certistack.test"}},
	{"isSynchronized", []string{"TRUE"}},
}

func TestLDAPProber_NamingContextReadsOnlyTheRootDSE(t *testing.T) {
	port, requests := serveRootDSE(t, 0, activeDirectoryRootDSE...)
	prober := NewLDAPProber("127.0.0.1", port, "", 2*time.Second, "AD naming context")
	prober.NamingContext = "dc=certistack, dc=test"
	res := prober.Probe(context.Background())
	if !res.Passed {
		t.Fatalf("AD Root DSE assertion failed: %s", res.Error)
	}
	for _, want := range []string{"DC=certistack,DC=test", "dnsHostName CS-W16-DC.certistack.test", "isSynchronized TRUE"} {
		if !strings.Contains(res.Detail, want) {
			t.Errorf("detail %q lacks %q", res.Detail, want)
		}
	}
	seen := <-requests
	if len(seen) != 1 {
		t.Fatalf("probe sent %d requests after the bind, want only the Root DSE read", len(seen))
	}
	if request := string(seen[0]); !strings.Contains(request, "defaultNamingContext") || strings.Contains(request, "certistack") {
		t.Fatalf("request was not a Root DSE read (empty base, asking for defaultNamingContext): %x", seen[0])
	}
}

func TestLDAPProber_NamingContextFailsForAnotherDirectory(t *testing.T) {
	port, requests := serveRootDSE(t, 0, activeDirectoryRootDSE...)
	prober := NewLDAPProber("127.0.0.1", port, "", 2*time.Second, "legacy forest")
	prober.NamingContext = "DC=legacy,DC=certistack,DC=test"
	res := prober.Probe(context.Background())
	<-requests
	if res.Passed {
		t.Fatal("a directory advertising another domain passed")
	}
	for _, want := range []string{"does not advertise naming context DC=legacy,DC=certistack,DC=test", "DC=certistack,DC=test"} {
		if !strings.Contains(res.Error, want) {
			t.Errorf("error %q lacks %q", res.Error, want)
		}
	}
}

// An OpenLDAP Root DSE has namingContexts but no defaultNamingContext.
func TestLDAPProber_NamingContextAcceptsAnAdvertisedContext(t *testing.T) {
	port, requests := serveRootDSE(t, 0, ldapAttribute{"namingContexts", []string{"dc=certistack,dc=test"}})
	prober := NewLDAPProber("127.0.0.1", port, "", 2*time.Second, "OpenLDAP naming context")
	prober.NamingContext = "DC=certistack,DC=test"
	if res := prober.Probe(context.Background()); !res.Passed {
		t.Fatalf("OpenLDAP naming context: %s", res.Error)
	}
	<-requests
}

func TestLDAPProber_NamingContextReadsTheRootDSEAfterARefusedBind(t *testing.T) {
	// A DC that requires signed binds refuses the clear-text anonymous bind
	// but still serves its Root DSE.
	for _, refusal := range []byte{8, 48} {
		port, requests := serveRootDSE(t, refusal, activeDirectoryRootDSE...)
		prober := NewLDAPProber("127.0.0.1", port, "", 2*time.Second, "signing required")
		prober.NamingContext = "DC=certistack,DC=test"
		if res := prober.Probe(context.Background()); !res.Passed {
			t.Fatalf("bind refused with %d: %+v", refusal, res)
		}
		if seen := <-requests; len(seen) != 1 {
			t.Fatalf("bind refused with %d: %d requests, want the Root DSE read", refusal, len(seen))
		}
	}
	// Any other bind failure still fails, without a search.
	port, requests := serveRootDSE(t, 49, activeDirectoryRootDSE...)
	prober := NewLDAPProber("127.0.0.1", port, "", 2*time.Second, "bad credentials")
	prober.NamingContext = "DC=certistack,DC=test"
	if res := prober.Probe(context.Background()); res.Passed || !strings.Contains(res.Error, "invalidCredentials") {
		t.Fatalf("bind failed with 49: %+v", res)
	}
	if seen := <-requests; len(seen) != 0 {
		t.Fatalf("probe searched after bind error 49")
	}
}

func TestLDAPProber_NamingContextFailsWithoutAnyContext(t *testing.T) {
	port, requests := serveRootDSE(t, 0)
	prober := NewLDAPProber("127.0.0.1", port, "", 2*time.Second, "empty Root DSE")
	prober.NamingContext = "DC=certistack,DC=test"
	res := prober.Probe(context.Background())
	<-requests
	if res.Passed || !strings.Contains(res.Error, "advertises no naming contexts") {
		t.Fatalf("empty Root DSE result = %+v", res)
	}
}

func ldapSearchResultDonePacket(messageID, resultCode int) []byte {
	done := append(ldapIntegerTLV(0x0a, resultCode), ldapTLV(0x04, nil)...)
	done = append(done, ldapTLV(0x04, nil)...)
	message := append(ldapIntegerTLV(0x02, messageID), ldapTLV(0x65, done)...)
	return ldapTLV(0x30, message)
}

func ldapRootDSEEntryPacket(messageID int, contexts ...string) []byte {
	values := make([]byte, 0, len(contexts)*24)
	for _, context := range contexts {
		values = append(values, ldapTLV(0x04, []byte(context))...)
	}
	attribute := append(ldapTLV(0x04, []byte("namingContexts")), ldapTLV(0x31, values)...)
	// SearchResultEntry.attributes is a SEQUENCE OF PartialAttribute.  The
	// PartialAttribute itself must be encoded as its own SEQUENCE.
	attributes := ldapTLV(0x30, ldapTLV(0x30, attribute))
	entry := append(ldapTLV(0x04, nil), attributes...)
	message := append(ldapIntegerTLV(0x02, messageID), ldapTLV(0x64, entry)...)
	return ldapTLV(0x30, message)
}

func TestDNSProber_ClosedServer(t *testing.T) {
	// Pointing to a dummy non-responsive port should fail, NOT pass
	prober := NewDNSProber("127.0.0.1", 59997, "example.com", "udp", 200*time.Millisecond, "closed dns port")
	res := prober.Probe(context.Background())
	if res.Passed {
		t.Fatal("expected DNS probe to fail against non-responsive server")
	}
}

func TestDNSProber_TCP(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				var lengthBuf [2]byte
				if _, err := io.ReadFull(conn, lengthBuf[:]); err != nil {
					return
				}
				request := make([]byte, binary.BigEndian.Uint16(lengthBuf[:]))
				if _, err := io.ReadFull(conn, request); err != nil || len(request) < 12 {
					return
				}

				// Preserve the query ID and question; answer with 127.0.0.1.
				response := make([]byte, 0, len(request)+16)
				response = append(response, request[0], request[1], 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00)
				response = append(response, request[12:]...)
				response = append(response,
					0xc0, 0x0c, // name pointer
					0x00, 0x01, // A
					0x00, 0x01, // IN
					0x00, 0x00, 0x00, 0x3c, // TTL
					0x00, 0x04, 127, 0, 0, 1,
				)
				binary.BigEndian.PutUint16(lengthBuf[:], uint16(len(response)))
				_, _ = conn.Write(append(lengthBuf[:], response...))
			}(conn)
		}
	}()

	port := listener.Addr().(*net.TCPAddr).Port
	prober := NewDNSProber("127.0.0.1", port, "healthy.certistack.test", "tcp", 2*time.Second, "TCP DNS")
	res := prober.Probe(context.Background())
	if !res.Passed {
		t.Fatalf("expected TCP DNS probe to pass, got error: %s", res.Error)
	}
	if !strings.Contains(res.Target, "tcp://") {
		t.Fatalf("expected TCP target, got %q", res.Target)
	}
}
