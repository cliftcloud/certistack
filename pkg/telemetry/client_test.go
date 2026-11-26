// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package telemetry

import (
	"context"
	"net"
	"net/http"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestConstantsAreTheDocumentedOnes(t *testing.T) {
	if DefaultURL != "https://certistack.dev/api/telemetry" || ContentType != "application/json" {
		t.Errorf("endpoint %q content type %q", DefaultURL, ContentType)
	}
	if SendTimeout != 3*time.Second || ExitBudget != 2*time.Second || Interval != 24*time.Hour {
		t.Errorf("timeout %v exit budget %v interval %v", SendTimeout, ExitBudget, Interval)
	}
	if u, err := ParseEndpoint(DefaultURL); err != nil || u.Scheme != "https" {
		t.Errorf("the default endpoint does not pass its own check: %v", err)
	}
}

func TestEndpointMustBeHTTPSOrLoopbackHTTP(t *testing.T) {
	for raw, ok := range map[string]bool{
		"https://certistack.dev/api/telemetry":    true,
		"https://example.org:8443/t":              true,
		"http://127.0.0.1:9999/api/telemetry":     true,
		"http://localhost:9999/x":                 true,
		"http://[::1]:9999/x":                     true,
		"http://127.1.2.3/x":                      true,
		"http://certistack.dev/api/telemetry":     false,
		"http://10.0.0.5/x":                       false,
		"http://localhost.evil.example/x":         false,
		"http://127.0.0.1.evil.example/x":         false,
		"ftp://example.org/x":                     false,
		"https://user:pw@example.org/x":           false,
		"https://example.org/x#frag":              false,
		"https:///nohost":                         false,
		"certistack.dev/api/telemetry":            false,
		"":                                        false,
		"https://":                                false,
		"//example.org/x":                         false,
		"file:///etc/passwd":                      false,
		"https://example.org/\x00":                false,
		"https://exa mple.org/x":                  false,
		"HTTPS://Certistack.dev/api/telemetry":    true,
		" https://certistack.dev/api/telemetry\t": true,
	} {
		_, err := ParseEndpoint(raw)
		if (err == nil) != ok {
			t.Errorf("ParseEndpoint(%q) error = %v, want accepted = %v", raw, err, ok)
		}
	}
}

func TestAnUnacceptableEndpointSendsNothingAndDoesNotFallBackToTheDefault(t *testing.T) {
	srv := newFakeServer(t, 200)
	h := newHarness(t, "")
	h.env[VarURL] = "http://example.org/not-loopback"
	mustEnable(t, h, false)
	out := h.AfterRun(context.Background(), completed("c", h.now))
	if out.Sent || out.Err == nil || srv.count() != 0 {
		t.Fatalf("outcome %+v", out)
	}
	if _, err := ResolveEndpoint(envOf()); err != nil {
		t.Fatalf("the default endpoint was refused: %v", err)
	}
	if got, _ := ResolveEndpoint(envOf()); got != DefaultURL {
		t.Fatalf("default endpoint = %q", got)
	}
}

func TestTransportHonoursTheStandardProxyEnvironment(t *testing.T) {
	tr := newTransport(time.Second)
	if reflect.ValueOf(tr.Proxy).Pointer() != reflect.ValueOf(http.ProxyFromEnvironment).Pointer() {
		t.Error("the transport does not use http.ProxyFromEnvironment")
	}
	if !tr.DisableKeepAlives {
		t.Error("the transport keeps its connection open after the report")
	}
}

func TestFailuresAreSilentAndNeverRetried(t *testing.T) {
	for name, status := range map[string]int{"server error": 500, "unavailable": 503, "not found": 404, "forbidden": 403, "too many": 429, "bad request": 400} {
		t.Run(name, func(t *testing.T) {
			srv := newFakeServer(t, status)
			h := newHarness(t, srv.URL)
			mustEnable(t, h, false)
			out := h.AfterRun(context.Background(), completed("c", h.now))
			if out.Sent || out.Err == nil {
				t.Fatalf("outcome = %+v", out)
			}
			if srv.count() != 1 {
				t.Fatalf("%d requests for a %d answer, want exactly 1 (no retry)", srv.count(), status)
			}
			// The failed attempt counts: the next run an hour later stays quiet.
			h.advance(time.Hour)
			h.AfterRun(context.Background(), completed("c", h.now))
			if srv.count() != 1 {
				t.Fatalf("a run an hour after a failed send sent again (%d requests)", srv.count())
			}
		})
	}
}

func TestADroppedConnectionIsOneAttempt(t *testing.T) {
	var hits atomic.Int32
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			hits.Add(1)
			c.Close()
		}
	}()
	h := newHarness(t, "http://"+ln.Addr().String())
	mustEnable(t, h, false)
	out := h.AfterRun(context.Background(), completed("c", h.now))
	if out.Sent || out.Err == nil {
		t.Fatalf("outcome = %+v", out)
	}
	if hits.Load() != 1 {
		t.Fatalf("%d connections, want 1: the client retried", hits.Load())
	}
}

func TestRefusedConnectionIsSilent(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close() // nothing listens here now
	h := newHarness(t, "http://"+addr)
	mustEnable(t, h, false)
	start := time.Now()
	out := h.AfterRun(context.Background(), completed("c", h.now))
	if out.Sent || out.Err == nil {
		t.Fatalf("outcome = %+v", out)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("a refused connection took %v", time.Since(start))
	}
}

func TestTLSHandshakeAgainstAPlainServerIsSilent(t *testing.T) {
	srv := newFakeServer(t, 200)
	h := newHarness(t, "")
	h.env[VarURL] = "https://" + strings.TrimPrefix(srv.URL, "http://") + "/api/telemetry"
	mustEnable(t, h, false)
	if out := h.AfterRun(context.Background(), completed("c", h.now)); out.Sent || out.Err == nil {
		t.Fatalf("outcome = %+v", out)
	}
}

func TestRedirectIsNotFollowed(t *testing.T) {
	target := newFakeServer(t, 200)
	for _, code := range []int{301, 302, 303, 307, 308} {
		redirector := newServerWith(t, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target.URL+"/elsewhere", code)
		})
		h := newHarness(t, redirector.URL)
		mustEnable(t, h, false)
		out := h.AfterRun(context.Background(), completed("c", h.now))
		if out.Sent || out.Err == nil {
			t.Errorf("%d: outcome = %+v", code, out)
		}
		if redirector.count() != 1 || target.count() != 0 {
			t.Errorf("%d: redirector saw %d requests, the target %d: the redirect was followed", code, redirector.count(), target.count())
		}
	}
}

// A server that never answers costs the 3 s the client allows, not the run.
func TestAHangingServerIsGivenUpOnAtTheTimeout(t *testing.T) {
	release := make(chan struct{})
	srv := newServerWith(t, func(w http.ResponseWriter, r *http.Request) { <-release })
	t.Cleanup(func() { close(release) })
	h := newHarness(t, srv.URL)
	h.Timeout = 250 * time.Millisecond
	mustEnable(t, h, false)
	start := time.Now()
	out := h.AfterRun(context.Background(), completed("c", h.now))
	took := time.Since(start)
	if out.Sent || out.Err == nil {
		t.Fatalf("outcome = %+v", out)
	}
	if took < 200*time.Millisecond || took > 5*time.Second {
		t.Fatalf("gave up after %v, want about the 250ms timeout", took)
	}
}

// The command's own deadline (telemetry.ExitBudget) wins when it is shorter.
func TestTheCallersDeadlineBoundsTheWait(t *testing.T) {
	release := make(chan struct{})
	srv := newServerWith(t, func(w http.ResponseWriter, r *http.Request) { <-release })
	t.Cleanup(func() { close(release) })
	h := newHarness(t, srv.URL)
	h.Timeout = 30 * time.Second
	mustEnable(t, h, false)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	out := h.AfterRun(ctx, completed("c", h.now))
	if out.Sent || time.Since(start) > 5*time.Second {
		t.Fatalf("sent=%v after %v", out.Sent, time.Since(start))
	}
}

func TestACanceledContextSendsNothing(t *testing.T) {
	srv := newFakeServer(t, 200)
	h := newHarness(t, srv.URL)
	mustEnable(t, h, false)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if out := h.AfterRun(ctx, completed("c", h.now)); out.Sent || srv.count() != 0 {
		t.Fatalf("outcome %+v, %d requests", out, srv.count())
	}
}

// The answer is ignored and read only up to a small cap, so a hostile or broken
// server cannot make the exit slow or the process big.
func TestTheResponseBodyIsCapped(t *testing.T) {
	const total = 256 << 20
	var written atomic.Int64
	srv := newServerWith(t, func(w http.ResponseWriter, r *http.Request) {
		chunk := make([]byte, 64<<10)
		for written.Load() < total {
			n, err := w.Write(chunk)
			written.Add(int64(n))
			if err != nil {
				return
			}
			w.(http.Flusher).Flush()
		}
	})
	h := newHarness(t, srv.URL)
	mustEnable(t, h, false)
	start := time.Now()
	out := h.AfterRun(context.Background(), completed("c", h.now))
	if !out.Sent {
		t.Fatalf("outcome = %+v", out)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("took %v", time.Since(start))
	}
	if written.Load() >= total {
		t.Fatalf("the client read the whole %d byte answer", total)
	}
}
