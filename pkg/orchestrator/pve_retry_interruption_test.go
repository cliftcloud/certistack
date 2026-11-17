// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/pve"
)

// A signal that arrives while the PVE client waits to retry a transient
// failure is named by the run's error, not reported as that failure: the
// classifier that names a signal looks for a cancellation in the error, so
// without one the signed failure_reason would name a proxy error and lose the
// signal and the node shutdown.
func TestSignalDuringAPVERetryDelayIsNamedByTheRunsError(t *testing.T) {
	var hits atomic.Int32
	firstReply := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(596)
		_, _ = w.Write([]byte(`{"data":null,"message":"synthetic retryable proxy failure"}`))
		select {
		case firstReply <- struct{}{}:
		default:
		}
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-firstReply
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	err := pve.NewClient(pve.Config{BaseURL: server.URL}).Do(ctx, http.MethodGet, "version", nil, nil)
	if hits.Load() != 1 {
		t.Fatalf("hits = %d, want the cancellation during the first retry delay", hits.Load())
	}

	interruption := &InterruptedError{Signal: "SIGTERM", NodeStopping: true}
	classified := withInterruption(err, interruption)
	var named *InterruptedError
	if classified == err || !errors.As(classified, &named) || !errors.Is(classified, context.Canceled) {
		t.Fatalf("classified = %T %v; want the run's error to be the interruption", classified, classified)
	}
	// The PVE failure stays, as where the run was.
	if text := classified.Error(); !strings.Contains(text, "the node began shutting down (SIGTERM from systemd)") || !strings.Contains(text, "HTTP 596") || !strings.Contains(text, "synthetic retryable proxy failure") {
		t.Fatalf("classified = %q; want the interruption named, with the PVE failure as where the run was", text)
	}
}
