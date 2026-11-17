// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/pve"
)

// The exit status is chosen from the error alone: an interrupted
// command is 130 and any other uncoded error is an infrastructure failure
// (2). A cancellation during a PVE retry delay was the latter.
func TestInterruptionDuringAPVERetryDelayExitsAsInterrupted(t *testing.T) {
	first := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(596)
		select {
		case first <- struct{}{}:
		default:
		}
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-first
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	err := pve.NewClient(pve.Config{BaseURL: server.URL}).Do(ctx, http.MethodGet, "version", nil, nil)
	if got := exitCodeForError(err); got != exitCodeInterrupted {
		t.Fatalf("exit status %d for %v, want %d", got, err, exitCodeInterrupted)
	}
}
