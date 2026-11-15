// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package synthetic

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// startRawHTTP answers every request with statusLine as the status line,
// exactly as given, over TLS when config is set. net/http's own server cannot
// send a status below 100.
func startRawHTTP(t *testing.T, statusLine string, config *tls.Config) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if config != nil {
		listener = tls.NewListener(listener, config)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				reader := bufio.NewReader(conn)
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						return
					}
					if line == "\r\n" {
						break
					}
				}
				_, _ = conn.Write([]byte("HTTP/1.1 " + statusLine + "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
			}()
		}
	}()
	return listener.Addr().(*net.TCPAddr).Port
}

// A status line's three digits are not always an HTTP status code.
// net/http accepts 099, 600 and 999, and the probe used to report each as
// "HTTP <n> OK" when the plan expected it. The reporter's three responses fail,
// over cleartext and TLS alike; 599, the highest status, and 200 still pass.
func TestHTTPProberRejectsStatusesThatAreNotHTTP(t *testing.T) {
	tlsServer := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(tlsServer.Close)
	roots := tlsServer.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	for _, tc := range []struct {
		line     string
		expected int
		pass     bool
	}{
		{"099 Below The Range", 99, false},
		{"600 Above The Range", 600, false},
		{"999 Way Above", 999, false},
		{"000 Zero", 1, false},
		{"599 The Highest", 599, true},
		{"200 OK", 200, true},
		{"204 No Content", 204, true},
		{"503 Service Unavailable", 200, false},
	} {
		for _, secure := range []bool{false, true} {
			name := tc.line
			if secure {
				name += " over TLS"
			}
			t.Run(name, func(t *testing.T) {
				var config *tls.Config
				if secure {
					config = &tls.Config{Certificates: tlsServer.TLS.Certificates}
				}
				port := startRawHTTP(t, tc.line, config)
				prober := NewHTTPProber("127.0.0.1", port, "/health", secure, false, tc.expected, 400*time.Millisecond, name, "example.com")
				prober.TLSRootCAs = roots
				res := prober.Probe(context.Background())
				switch {
				case tc.pass && (!res.Passed || !strings.Contains(res.Detail, "HTTP "+strings.Fields(tc.line)[0]+" OK")):
					t.Fatalf("result = %+v, want a pass", res)
				case !tc.pass && res.Passed:
					t.Fatalf("result = %+v, want a failure", res)
				case !tc.pass && !strings.Contains(res.Error, "not an HTTP status code") && !strings.Contains(res.Error, "expected HTTP status"):
					t.Fatalf("error = %q", res.Error)
				}
				if !tc.pass && strings.Contains(res.Detail, " OK") {
					t.Fatalf("a failed probe reports %q as OK", res.Detail)
				}
			})
		}
	}
}

// A programmatic caller can still ask for a status no plan may, and gets no
// pass for the server that answers it.
func TestHTTPProberDoesNotMatchAnInvalidExpectedStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(999) // net/http's server allows 100 to 999
	}))
	t.Cleanup(server.Close)
	port := server.Listener.Addr().(*net.TCPAddr).Port
	res := NewHTTPProber("127.0.0.1", port, "/", false, false, 999, 400*time.Millisecond, "status 999", "").Probe(context.Background())
	if res.Passed || !strings.Contains(res.Error, "status 999, which is not an HTTP status code") {
		t.Fatalf("result = %+v", res)
	}
}
