// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package sdn

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/cliftcloud/certistack/pkg/pve"
)

// PVE's apply task forks each node's reload in turn, about 6.5 s a
// node, 78 s on 12 nodes. The apply returns at once; a failed task is
// reported when asked; a second apply waits for the first task first.
func TestReloadReturnsAtOnceAndSerializesItsApplies(t *testing.T) {
	var mu sync.Mutex
	var calls []string
	status := `{"status":"running"}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls = append(calls, r.Method+" "+r.URL.Path)
		answer := status
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPut:
			_ = json.NewEncoder(w).Encode(pve.APIResponse{Data: json.RawMessage(`"UPID:pve1:1:1:1:1:reloadnetworkall::root@pam:"`)})
		default:
			_ = json.NewEncoder(w).Encode(pve.APIResponse{Data: json.RawMessage(answer)})
		}
	}))
	defer server.Close()
	m := NewManager(pve.NewClient(pve.Config{BaseURL: server.URL}))
	ctx := context.Background()

	if err := holding(m, "tok").Reload(ctx); err != nil {
		t.Fatal(err)
	}
	if err := m.ReloadFailed(ctx); err != nil {
		t.Fatalf("a task still reloading other nodes = %v, want no failure", err)
	}
	mu.Lock()
	status = `{"status":"stopped","exitstatus":"command 'pvesh set /nodes/pve3/network' failed"}`
	mu.Unlock()
	if err := m.ReloadFailed(ctx); err == nil || !strings.Contains(err.Error(), "pve3") {
		t.Fatalf("a failed task = %v, want its exit status", err)
	}
	mu.Lock()
	status = `{"status":"stopped","exitstatus":"OK"}`
	calls = nil
	mu.Unlock()
	if err := holding(m, "tok").Reload(ctx); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(calls) != 2 || !strings.HasPrefix(calls[0], "GET ") || calls[1] != "PUT /api2/json/cluster/sdn" {
		t.Fatalf("second apply = %v, want the first task waited for, then the PUT", calls)
	}
}
