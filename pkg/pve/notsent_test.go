// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pve

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// NotSent tells a request that provably never reached PVE from one
// whose reply was lost, which a mutation may have made.
func TestNotSentDistinguishesNeverSentFromLostReply(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond) // the reply comes after the client's timeout
	}))
	defer server.Close()

	slow := NewClient(Config{BaseURL: server.URL, Timeout: 50 * time.Millisecond})
	if err := slow.Do(context.Background(), "POST", "cluster/sdn/lock", nil, nil); err == nil || NotSent(err) {
		t.Fatalf("a timed-out request = %v, NotSent %v; want it possibly sent", err, NotSent(err))
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := NewClient(Config{BaseURL: server.URL}).Do(canceled, "POST", "cluster/sdn/lock", nil, nil); !NotSent(err) {
		t.Fatalf("a request canceled before it was sent = %v; want NotSent", err)
	}

	bad := NewClient(Config{BaseURL: "ftp://not-pve.example"})
	if err := bad.Do(context.Background(), "GET", "version", nil, nil); !NotSent(err) || !errors.Is(err, ErrRequestNotSent) {
		t.Fatalf("an unconfigured client = %v; want NotSent", err)
	}

	closed := httptest.NewServer(nil)
	url := closed.URL
	closed.Close()
	ctx, stop := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer stop()
	if err := NewClient(Config{BaseURL: url}).Do(ctx, "POST", "cluster/sdn/lock", nil, nil); err == nil || !NotSent(err) {
		t.Fatalf("a refused connection = %v; want NotSent", err)
	}

	if NotSent(&APIError{StatusCode: 503, Message: "Service Unavailable"}) || NotSent(errors.New("boom")) || NotSent(nil) {
		t.Fatal("NotSent accepted an error that says nothing of the request")
	}
}

// A lock token in a request path must not reach error text, which flows into
// logs, cleanup errors and the signed report.
func TestErrorTextDoesNotCarryTheLockToken(t *testing.T) {
	closed := httptest.NewServer(nil)
	url := closed.URL
	closed.Close()
	ctx, stop := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer stop()
	err := NewClient(Config{BaseURL: url}).Do(ctx, "DELETE", "cluster/sdn/lock?lock-token=SECRET-TOKEN-123&x=1", nil, nil)
	if err == nil || strings.Contains(err.Error(), "SECRET-TOKEN-123") || !strings.Contains(err.Error(), "lock-token=<redacted>") {
		t.Fatalf("error = %v; want the token redacted", err)
	}
	if got := redactPath("cluster/sdn/lock?lock-token=abc"); got != "cluster/sdn/lock?lock-token=<redacted>" {
		t.Fatalf("redactPath = %q", got)
	}
}
