// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package telemetry

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"
)

// request is one request a fake server received: the whole thing as the wire
// carried it (request line, every header, the body), plus the parts.
type request struct {
	Method, Path, Query string
	Header              http.Header
	Body                []byte
	Dump                string
}

// fakeServer records every request and answers with a fixed status.
type fakeServer struct {
	*httptest.Server
	mu       sync.Mutex
	requests []request
}

func newFakeServer(t *testing.T, status int) *fakeServer {
	t.Helper()
	return newServerWith(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) })
}

// newServerWith records each request before answer handles it.
func newServerWith(t *testing.T, answer http.HandlerFunc) *fakeServer {
	t.Helper()
	f := &fakeServer{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dump, _ := httputil.DumpRequest(r, false)
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		f.mu.Lock()
		f.requests = append(f.requests, request{r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Clone(), body, string(dump) + string(body)})
		f.mu.Unlock()
		answer(w, r)
	}))
	t.Cleanup(f.Server.Close)
	return f
}

func (f *fakeServer) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests)
}

func (f *fakeServer) last(t *testing.T) request {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.requests) == 0 {
		t.Fatal("the server received no request")
	}
	return f.requests[len(f.requests)-1]
}

func headerNames(h http.Header) []string {
	var names []string
	for name := range h {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// harness is a Manager over a temporary state directory, a controllable clock
// and a map for an environment.
type harness struct {
	*Manager
	env map[string]string
	now time.Time
}

func newHarness(t *testing.T, endpoint string, env ...string) *harness {
	t.Helper()
	h := &harness{env: map[string]string{}, now: time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)}
	if endpoint != "" {
		h.env[VarURL] = endpoint + "/api/telemetry"
	}
	for i := 0; i+1 < len(env); i += 2 {
		h.env[env[i]] = env[i+1]
	}
	h.Manager = &Manager{
		Version:   "0.1.0-rc3",
		StatePath: filepath.Join(t.TempDir(), "home", "certistack", StateFileName),
		Getenv:    func(k string) string { return h.env[k] },
		Now:       func() time.Time { return h.now },
		Timeout:   2 * time.Second,
	}
	return h
}

func (h *harness) advance(d time.Duration) { h.now = h.now.Add(d) }

func (h *harness) state(t *testing.T) State {
	t.Helper()
	st, status := ReadState(h.StatePath)
	if status != StateOK {
		t.Fatalf("state status = %v", status)
	}
	return st
}
