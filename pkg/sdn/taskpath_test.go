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
	"time"

	"github.com/cliftcloud/certistack/pkg/pve"
)

// The apply task's UPID is PVE's own answer, and TaskNode accepts any text in
// its process and start fields. The two direct reads of the task's status (the
// failure check, and the read after a wait that did not finish) put it in the
// path as one segment, as WaitForTask does, so a "/", "?", "#" or ".." in it
// cannot start a query, a fragment or another path.
func TestSDNReadsTheApplyTaskStatusAsOnePathSegment(t *testing.T) {
	for _, tc := range []struct{ name, upid string }{
		{"a real UPID", "UPID:pve1:00001234:0001A2B3:6512ABCD:reloadnetworkall::root@pam:"},
		{"a real UPID of an API token", "UPID:pve1:00001234:0001A2B3:6512ABCD:reloadnetworkall::root@pam!certistack:"},
		{"a slash", "UPID:pve1:a/b:0001A2B3:6512ABCD:reloadnetworkall::root@pam:"},
		{"a question mark", "UPID:pve1:00001234:x?y=1:6512ABCD:reloadnetworkall::root@pam:"},
		{"a fragment", "UPID:pve1:00001234:0001A2B3:x#y:reloadnetworkall::root@pam:"},
		{"dot segments", "UPID:pve1:../..:..:6512ABCD:reloadnetworkall::root@pam:"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			type request struct{ decoded, escaped, query string }
			var mu sync.Mutex
			var seen []request
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				seen = append(seen, request{r.URL.Path, r.URL.EscapedPath(), r.URL.RawQuery})
				mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(pve.APIResponse{Data: json.RawMessage(`{"status":"stopped","exitstatus":"OK"}`)})
			}))
			defer server.Close()
			m := NewManager(pve.NewClient(pve.Config{BaseURL: server.URL}))
			// The wait is shorter than the poll interval, so WaitForTask gives
			// up before it asks and the status is read directly.
			m.SetApplyWait(20 * time.Millisecond)
			if err := m.AdoptApplyTask(tc.upid); err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			if err := m.ReloadFailed(ctx); err != nil {
				t.Fatalf("ReloadFailed = %v", err)
			}
			if err := m.WaitForApply(ctx); err != nil {
				t.Fatalf("WaitForApply = %v", err)
			}
			mu.Lock()
			defer mu.Unlock()
			if len(seen) != 2 {
				t.Fatalf("%d status reads, want the failure check and the read after the wait: %v", len(seen), seen)
			}
			for _, got := range seen {
				if want := "/api2/json/nodes/pve1/tasks/" + tc.upid + "/status"; got.decoded != want {
					t.Errorf("PVE reads the path %q, want %q", got.decoded, want)
				}
				if got.query != "" {
					t.Errorf("the request carries the query %q", got.query)
				}
				if segments := strings.Split(got.escaped, "/"); len(segments) != 8 || segments[5] != "tasks" || segments[7] != "status" {
					t.Errorf("the request path %q is not nodes/pve1/tasks/<one segment>/status", got.escaped)
				}
			}
		})
	}
}
