// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package synthetic

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// requestRecorder is a local HTTP server that records every request target
// it receives and answers the one in fail with 503, anything else with 200.
type requestRecorder struct {
	mu      sync.Mutex
	targets []string
	port    int
}

func startRequestRecorder(t *testing.T, fail string) *requestRecorder {
	t.Helper()
	recorder := &requestRecorder{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recorder.mu.Lock()
		recorder.targets = append(recorder.targets, r.RequestURI)
		recorder.mu.Unlock()
		if r.RequestURI == fail {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	recorder.port = server.Listener.Addr().(*net.TCPAddr).Port
	return recorder
}

func (r *requestRecorder) seen() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.targets...)
}

// The request line carries the path exactly as written: the query,
// escaped slashes, question marks, hashes and percent signs all reach the
// server unchanged. The server fails exactly that target, so a probe that
// sent anything else would pass.
func TestHTTPProberSendsThePathExactlyAsWritten(t *testing.T) {
	for _, target := range []string{
		"/health?check=database&mode=deep",
		"/tenant/a%2Fb/health",
		"/health%3Fcheck=database",
		"/health%23database",
		"/health%252Fdatabase",
		"/a%7eb/%5Bx%5D?q=%20y&empty=",
		"/health?",
	} {
		t.Run(target, func(t *testing.T) {
			recorder := startRequestRecorder(t, target)
			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()
			res := NewHTTPProber("127.0.0.1", recorder.port, target, false, false, http.StatusOK, time.Second, "exact target", "").Probe(ctx)
			if res.Passed || !strings.Contains(res.Error, "got 503") {
				t.Fatalf("result = %+v, want the 503 the intended target answers", res)
			}
			for _, seen := range recorder.seen() {
				if seen != target {
					t.Fatalf("server saw %q, want %q", seen, target)
				}
			}
			if !strings.HasSuffix(res.Target, target) {
				t.Fatalf("result target %q does not name the request sent", res.Target)
			}
		})
	}
}

// A path that would reach the server as something else, or not at all,
// fails without sending anything: a #fragment is never sent, a space in the
// query would end the request line early, and a path that has percent-escapes
// and also a character needing encoding is re-encoded whole, decoding its
// %2F (a%2Fb c would be sent as a/b%20c).
func TestHTTPProberRefusesAPathItCannotSendAsWritten(t *testing.T) {
	for path, want := range map[string]string{
		"/health#database":  "must not contain '#'",
		"/health?check=a b": "space in its query",
		"/a%2Fb c":          `would be sent as "/a/b%20c"`,
		"/café%2Fx":         "percent-escapes and other characters",
		"/health%zz":        "is not a valid request target",
		"/health?x=1\tdeep": "control character",
	} {
		recorder := startRequestRecorder(t, "")
		res := NewHTTPProber("127.0.0.1", recorder.port, path, false, false, http.StatusOK, time.Second, "unsendable", "").Probe(context.Background())
		if res.Passed || !strings.Contains(res.Error, want) {
			t.Errorf("path %q: result = %+v, want an error mentioning %q", path, res, want)
		}
		if seen := recorder.seen(); len(seen) != 0 {
			t.Errorf("path %q: server saw %q", path, seen)
		}
	}
}

// A path with no percent-escapes in it is sent in the standard percent-encoding,
// which is what its author meant (a space as %20, an accented letter as its
// UTF-8 octets), and a query is sent as written. Target names what the server
// received.
func TestHTTPProberSendsAnUnescapedPathPercentEncoded(t *testing.T) {
	for path, wire := range map[string]string{
		"/a b":                "/a%20b",
		"/café":               "/caf%C3%A9",
		`/a"b`:                "/a%22b",
		"/health?q=café&x=1":  "/health?q=café&x=1",
		"/tenant/a%2Fb/x?d=1": "/tenant/a%2Fb/x?d=1",
	} {
		t.Run(path, func(t *testing.T) {
			recorder := startRequestRecorder(t, "")
			res := NewHTTPProber("127.0.0.1", recorder.port, path, false, false, http.StatusOK, time.Second, "encoded", "").Probe(context.Background())
			if !res.Passed || !strings.HasSuffix(res.Target, wire) {
				t.Fatalf("result = %+v, want a pass with target ending %q", res, wire)
			}
			if seen := recorder.seen(); len(seen) != 1 || seen[0] != wire {
				t.Fatalf("server saw %q, want %q", seen, wire)
			}
		})
	}
}

// A failing endpoint's answer (a stack trace, application data) is never read
// into the result, which is signed into a retained report: the body's marker
// appears in neither the error nor any other field of the result.
func TestHTTPProberNeverPutsAFailingEndpointsBodyInTheResult(t *testing.T) {
	const secret = "BODY-MARKER-db-password=hunter2 at com.example.Handler.run(Handler.java:42)"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Debug", "header-marker")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(secret))
	}))
	t.Cleanup(server.Close)
	port := server.Listener.Addr().(*net.TCPAddr).Port
	ctx, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
	defer cancel()
	res := NewHTTPProber("127.0.0.1", port, "/health", false, false, http.StatusOK, time.Second, "failing endpoint", "").Probe(ctx)
	if res.Passed || !strings.Contains(res.Error, "500") {
		t.Fatalf("result = %+v, want a failure that names the status", res)
	}
	signed, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	for _, leaked := range []string{"BODY-MARKER", "hunter2", "Handler.java", "header-marker"} {
		if strings.Contains(string(signed), leaked) {
			t.Fatalf("the failing endpoint's answer reached the result (%q): %s", leaked, signed)
		}
	}
}
