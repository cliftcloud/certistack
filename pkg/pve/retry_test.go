// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pve

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// flakyServer answers the first failures requests with status (0 drops the
// connection instead) and then succeeds.
func flakyServer(t *testing.T, failures int, status int) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if int(hits.Add(1)) <= failures {
			if status == 0 {
				conn, _, err := w.(http.Hijacker).Hijack()
				if err == nil {
					conn.Close()
				}
				return
			}
			w.WriteHeader(status)
			return
		}
		w.Write([]byte(`{"data":{"status":"available"}}`))
	}))
	t.Cleanup(server.Close)
	return server, &hits
}

func retryingClient(url string) *Client {
	client := NewClient(Config{BaseURL: url})
	client.retryDelays = []time.Duration{0, 0, 0}
	return client
}

// Pveproxy can answer HTTP 596 for a storage status read while the target
// node is busy; the same GET succeeds a second later.
func TestDoRetriesTransientReadFailures(t *testing.T) {
	for _, status := range []int{595, 596, 597, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout, 0} {
		server, hits := flakyServer(t, 2, status)
		var result struct {
			Status string `json:"status"`
		}
		if err := retryingClient(server.URL).Do(context.Background(), http.MethodGet, "nodes/n1/storage/s/status", nil, &result); err != nil {
			t.Fatalf("status %d: %v", status, err)
		}
		if hits.Load() != 3 || result.Status != "available" {
			t.Fatalf("status %d: hits = %d, result = %+v; want the third attempt's answer", status, hits.Load(), result)
		}
	}
}

func TestDoGivesUpAfterFourAttempts(t *testing.T) {
	server, hits := flakyServer(t, 100, 596)
	err := retryingClient(server.URL).Do(context.Background(), http.MethodGet, "version", nil, nil)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != 596 || hits.Load() != 4 {
		t.Fatalf("err = %v, hits = %d; want the last 596 after 4 attempts", err, hits.Load())
	}
	// pveproxy sends 596 with an empty message; the operator still gets a cause.
	if !strings.Contains(err.Error(), "target node") {
		t.Fatalf("message = %q; want the proxy failure explained", err.Error())
	}
}

// A 500 is a definite answer (IsNotFound relies on one), and a lost reply to
// a mutation is ambiguous: neither is repeated.
func TestDoDoesNotRetryDefiniteOrAmbiguousFailures(t *testing.T) {
	cases := []struct {
		method string
		status int
	}{
		{http.MethodGet, http.StatusInternalServerError},
		{http.MethodGet, http.StatusForbidden},
		{http.MethodPost, 596},
		{http.MethodPost, 597},
		{http.MethodPost, http.StatusBadGateway},
		{http.MethodDelete, 596},
		{http.MethodPut, 0},
	}
	for _, tc := range cases {
		server, hits := flakyServer(t, 1, tc.status)
		if err := retryingClient(server.URL).Do(context.Background(), tc.method, "nodes/n1/qemu", nil, nil); err == nil || hits.Load() != 1 {
			t.Fatalf("%s %d: err = %v, hits = %d; want one attempt", tc.method, tc.status, err, hits.Load())
		}
	}
}

// 595 means pveproxy could not connect to the target node, and a refused
// connection means the request never left: both are safe to repeat for any
// method.
func TestDoRetriesMutationsThatNeverArrived(t *testing.T) {
	server, hits := flakyServer(t, 2, 595)
	if err := retryingClient(server.URL).Do(context.Background(), http.MethodPost, "nodes/n1/qemu", map[string]int{"vmid": 1}, nil); err != nil || hits.Load() != 3 {
		t.Fatalf("err = %v, hits = %d; want success on the third attempt", err, hits.Load())
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedURL := "http://" + listener.Addr().String()
	listener.Close()
	transient, err := retryingClient(closedURL).do(context.Background(), http.MethodPost, "nodes/n1/qemu", []byte("{}"), nil)
	if err == nil || !transient {
		t.Fatalf("refused POST: transient = %v, err = %v; want a retryable failure", transient, err)
	}
	if err.Error() != "PVE HTTP request failed for POST nodes/n1/qemu" {
		t.Fatalf("message = %q; the endpoint must stay out of it", err.Error())
	}
	var opErr *net.OpError
	if !errors.As(err, &opErr) {
		t.Fatalf("cause is not reachable through errors.As: %v", err)
	}
}

func TestDoDoesNotRetryTimeouts(t *testing.T) {
	release := make(chan struct{})
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		<-release
	}))
	defer server.Close()
	defer close(release)
	client := NewClient(Config{BaseURL: server.URL, Timeout: 50 * time.Millisecond})
	client.retryDelays = []time.Duration{0, 0, 0}
	if err := client.Do(context.Background(), http.MethodGet, "version", nil, nil); err == nil || hits.Load() != 1 {
		t.Fatalf("err = %v, hits = %d; want one timed-out attempt", err, hits.Load())
	}
}

func TestDoStopsWaitingWhenCanceled(t *testing.T) {
	server, hits := flakyServer(t, 100, 596)
	client := NewClient(Config{BaseURL: server.URL})
	client.retryDelays = []time.Duration{time.Hour}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := client.Do(ctx, http.MethodGet, "version", nil, nil)
	if err == nil || hits.Load() != 1 || time.Since(start) > 10*time.Second {
		t.Fatalf("err = %v, hits = %d after %s; want the first failure as soon as the context ends", err, hits.Load(), time.Since(start))
	}
	// And the context's end, which the failure must not replace.
	var apiErr *APIError
	if !errors.Is(err, context.DeadlineExceeded) || !errors.As(err, &apiErr) || apiErr.StatusCode != 596 {
		t.Fatalf("err = %v; want both the caller's deadline and the HTTP 596 that was being retried", err)
	}
}

// A retryable HTTP 596, then the caller is cancelled during the retry delay.
// The error is not the 596 alone, so everything that classifies an
// interruption by errors.Is(err, context.Canceled) (the signal classifier, the
// signed failure reason, the CLI's exit status 130) sees one.
func TestDoCancelledDuringRetryBackoffStaysACancellation(t *testing.T) {
	var hits atomic.Int32
	firstReply := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if hits.Add(1) == 1 {
			defer close(firstReply)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(596)
		_, _ = w.Write([]byte(`{"data":null,"message":"synthetic retryable proxy failure"}`))
	}))
	defer server.Close()
	client := NewClient(Config{BaseURL: server.URL}) // the default two-second first delay

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-firstReply
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	err := client.Do(ctx, http.MethodGet, "version", nil, nil)
	if elapsed := time.Since(start); hits.Load() != 1 || elapsed >= 2*time.Second {
		t.Fatalf("hits = %d after %s; want the cancellation to end the first retry delay", hits.Load(), elapsed)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v; it does not match context.Canceled, so the interruption is lost", err)
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != 596 || !strings.Contains(apiErr.Message, "synthetic retryable proxy failure") {
		t.Fatalf("err = %v; the failure that was being retried is not reachable", err)
	}
	// The text ends with the context's, as a wrapped cancellation does: the
	// orchestrator names the interruption by trimming it.
	if !strings.HasSuffix(err.Error(), context.Canceled.Error()) || strings.Contains(err.Error(), server.URL) {
		t.Fatalf("message = %q; want it to end with %q and keep the endpoint out", err.Error(), context.Canceled.Error())
	}
}

// A cancellation that the failed request itself reports is not wrapped twice.
func TestDoCancelledDuringARequestIsNotWrappedAgain(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
	defer server.Close()
	defer close(release)
	client := NewClient(Config{BaseURL: server.URL})
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	err := client.Do(ctx, http.MethodGet, "version", nil, nil)
	if !errors.Is(err, context.Canceled) || strings.Contains(err.Error(), "stopped retrying") {
		t.Fatalf("err = %q; want the request's own cancellation, unchanged", err)
	}
}
